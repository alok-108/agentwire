"""Cross-process / networked length-prefixed TCP (+ TLS/mTLS) RPC transport for AgentWire (`AW01`).

Wire Framing on TCP / TLS:
    [4-byte big-endian unsigned length N][N bytes of AW01 binary frame]

v0.4.0 Production Security & Reliability Guarantees:
- **Transport Confidentiality (TLS / mTLS):** Optional `ssl.SSLContext` wraps both server and
  client sockets so wire payloads are encrypted in transit (HMAC/Ed25519 authenticate; TLS encrypts).
- **Per-Agent Asymmetric Identity (Ed25519):** Pass `public_keys={agent_id: pub_32b}` +
  `server_private_key` (or legacy shared `signing_key` HMAC-SHA256). Under Ed25519, each agent
  holds its own private key and CANNOT impersonate any other `source_agent`.
- **Cross-Restart & Multi-Instance Replay Persistence:** Plug in `SqliteStateStore(db_path)` (or
  a custom Redis/Postgres `StateStore`) so replayed nonces are blocked across restarts and across
  multiple server instances.
- **Idempotent Retry Semantics:** Requests carrying `idempotency_key` are deduplicated atomically
  in `StateStore` so client timeout retries NEVER cause duplicate execution of `MUTATE` handlers.
- **Independent Server-Side Usage Metering:** `IndependentTokenMeter` (or a custom LLM-gateway
  `UsageMeter`) measures actual inbound + outbound token volume independently and enforces a
  non-bypassable floor (`max(measured, handler_reported)`) during two-phase budget settlement.
"""

from __future__ import annotations

import json
import secrets
import socket
import socketserver
import ssl
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol, runtime_checkable

from agentwire._agentwire import (
    PolicyEngine,
    decompile_frame,
    decode_frame,
    encode_ast,
    sign_ast,
    sign_ast_ed25519,
    verify_frame,
    verify_frame_ed25519,
)
from agentwire.client import TokenEstimator
from agentwire.state import StateStore
from agentwire.telemetry.stream import now_ms

MAX_RPC_FRAME_BYTES = 4 * 1024 * 1024  # 4 MiB hard cap against OOM framing attacks
DEFAULT_STATE_TTL_MS = 24 * 60 * 60 * 1000  # 24 hours


class RpcTransportError(RuntimeError):
    """Raised on network framing, TLS, timeout, correlation, or authentication transport failure."""


@dataclass(slots=True)
class UsageMeasurement:
    """Independently metered token and micro-USD consumption for one RPC execution."""

    tokens: int
    micro_usd: int
    source: str


@runtime_checkable
class UsageMeter(Protocol):
    """Pluggable server-side usage meter reconciled against handler-reported usage."""

    def measure(
        self,
        decoded_request: dict[str, Any],
        request_summary: dict[str, Any],
        response_payload: dict[str, Any],
    ) -> UsageMeasurement:
        ...


class IndependentTokenMeter:
    """Default independent server-side meter counting canonical AST + response payload tokens.

    Enforces a verifiable lower bound during two-phase budget settlement so a buggy or
    compromised handler cannot report `(0, 0)` to bypass session budget enforcement.
    """

    def __init__(
        self,
        *,
        estimator: TokenEstimator | None = None,
        micro_usd_per_1k_tokens: int = 3_000,  # $3.00 / 1M tokens = 3,000 micro-USD / 1k tokens
    ) -> None:
        self.estimator = estimator if estimator is not None else TokenEstimator()
        self.micro_usd_per_1k_tokens = micro_usd_per_1k_tokens

    def measure(
        self,
        decoded_request: dict[str, Any],
        request_summary: dict[str, Any],
        response_payload: dict[str, Any],
    ) -> UsageMeasurement:
        in_tokens = self.estimator.count_text(str(request_summary.get("canonical_ast", "")))
        out_text = json.dumps(response_payload, ensure_ascii=False, separators=(",", ":"))
        out_tokens = self.estimator.count_text(out_text)
        total_tokens = max(1, in_tokens + out_tokens)
        micro_usd = max(1, (total_tokens * self.micro_usd_per_1k_tokens + 999) // 1000)
        return UsageMeasurement(
            tokens=total_tokens,
            micro_usd=micro_usd,
            source=f"independent:{self.estimator.backend_label}",
        )


@dataclass(slots=True)
class RpcResponse:
    """Decoded response returned by `AgentWireRpcClient.call`."""

    ok: bool
    trace_id: int
    span_id: int
    payload: dict[str, Any]
    reason_code: str | None
    detail: str | None
    raw_bytes: bytes
    trace_summary: dict[str, Any]
    rtt_ms: float
    attempts: int
    deduplicated: bool = False


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("peer closed TCP connection mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_framed_bytes(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_RPC_FRAME_BYTES:
        raise RpcTransportError(
            f"frame size {len(payload)} exceeds MAX_RPC_FRAME_BYTES ({MAX_RPC_FRAME_BYTES})"
        )
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_framed_bytes(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length == 0 or length > MAX_RPC_FRAME_BYTES:
        raise RpcTransportError(
            f"invalid framed length {length} (max {MAX_RPC_FRAME_BYTES})"
        )
    return _recv_exact(sock, length)


# Handler signature: (decoded_frame, trace_summary) -> (response_payload_dict, reported_tokens, reported_micro_usd)
RpcHandler = Callable[
    [dict[str, Any], dict[str, Any]],
    tuple[dict[str, Any], int, int],
]


class _ThreadedTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class AgentWireRpcServer:
    """Networked TCP/TLS RPC server with Ed25519/HMAC verification, persistent replay &
    idempotency deduplication, independent usage metering, and receiver-side PolicyEngine.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        policy: PolicyEngine | None = None,
        signing_key: bytes | None = None,
        public_keys: dict[str, bytes] | None = None,
        server_private_key: bytes | None = None,
        ssl_context: ssl.SSLContext | None = None,
        state_store: StateStore | None = None,
        usage_meter: UsageMeter | None = None,
        server_agent_id: str = "rpc_server",
        socket_timeout_s: float = 5.0,
        state_ttl_ms: int = DEFAULT_STATE_TTL_MS,
    ) -> None:
        self.host = host
        self.requested_port = port
        self.signing_key = signing_key
        self.public_keys = dict(public_keys) if public_keys is not None else None
        self.server_private_key = server_private_key
        self.ssl_context = ssl_context
        self.state_store = state_store
        self.usage_meter: UsageMeter = (
            usage_meter if usage_meter is not None else IndependentTokenMeter()
        )
        self.state_ttl_ms = state_ttl_ms

        require_auth = (signing_key is not None) or (self.public_keys is not None)
        if policy is not None:
            self.policy = policy
        elif require_auth:
            self.policy = PolicyEngine.strict_authenticated()
        else:
            self.policy = PolicyEngine.default_multi_agent()

        self.server_agent_id = server_agent_id
        self.socket_timeout_s = socket_timeout_s
        self._handlers: dict[str, RpcHandler] = {}
        self._default_handler: RpcHandler | None = None
        self._inmem_idempotency_lock = threading.Lock()
        self._inmem_idempotency: dict[tuple[str, str], bytes] = {}
        self._server: _ThreadedTcpServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            return (self.host, self.requested_port)
        host, port = self._server.server_address[:2]
        return (str(host), int(port))

    def register_handler(self, target_agent: str, handler: RpcHandler) -> None:
        self._handlers[target_agent] = handler

    def set_default_handler(self, handler: RpcHandler) -> None:
        self._default_handler = handler

    def _encode_reply(
        self,
        *,
        source_agent: str,
        target_agent: str,
        target: str,
        intent: str,
        payload: dict[str, Any],
        trace_id: int,
        span_id: int,
        hop_depth: int,
    ) -> bytes:
        if self.server_private_key is not None:
            return sign_ast_ed25519(
                source_agent=source_agent,
                target_agent=target_agent,
                action="YIELD",
                target=target,
                intent=intent,
                private_key=self.server_private_key,
                nonce=secrets.randbits(63) or 1,
                timestamp_ms=now_ms(),
                payload=payload,
                trace_id=trace_id,
                span_id=span_id,
                hop_depth=hop_depth,
                guard_verified=True,
            )
        if self.signing_key is not None:
            return sign_ast(
                source_agent=source_agent,
                target_agent=target_agent,
                action="YIELD",
                target=target,
                intent=intent,
                signing_key=self.signing_key,
                nonce=secrets.randbits(63) or 1,
                timestamp_ms=now_ms(),
                payload=payload,
                trace_id=trace_id,
                span_id=span_id,
                hop_depth=hop_depth,
                guard_verified=True,
            )
        return encode_ast(
            source_agent=source_agent,
            target_agent=target_agent,
            action="YIELD",
            target=target,
            intent=intent,
            payload=payload,
            trace_id=trace_id,
            span_id=span_id,
            hop_depth=hop_depth,
            guard_verified=True,
        )

    def _get_cached_idempotent(self, source_agent: str, idem_key: str) -> bytes | None:
        if self.state_store is not None:
            return self.state_store.get_idempotent_response(source_agent, idem_key)
        with self._inmem_idempotency_lock:
            return self._inmem_idempotency.get((source_agent, idem_key))

    def _save_cached_idempotent(
        self, source_agent: str, idem_key: str, raw_reply: bytes, ts_now: int
    ) -> None:
        if self.state_store is not None:
            self.state_store.save_idempotent_response(
                source_agent, idem_key, raw_reply, ts_now + self.state_ttl_ms
            )
        else:
            with self._inmem_idempotency_lock:
                self._inmem_idempotency[(source_agent, idem_key)] = raw_reply

    def _handle_raw_request(self, raw_request: bytes) -> bytes:
        ts_now = now_ms()
        # 1. Decode + mandatory per-agent Ed25519 or HMAC-SHA256 cryptographic verification
        try:
            if self.public_keys is not None:
                decoded = verify_frame_ed25519(raw_request, self.public_keys)
            elif self.signing_key is not None:
                decoded = verify_frame(raw_request, self.signing_key)
            else:
                decoded = decode_frame(raw_request)
        except ValueError as err:
            return self._encode_reply(
                source_agent=self.server_agent_id,
                target_agent="unknown",
                target="rpc:error",
                intent="yield_result",
                payload={
                    "ok": False,
                    "reason_code": "AUTHENTICATION_OR_DECODE_FAILED",
                    "detail": str(err),
                },
                trace_id=0,
                span_id=0,
                hop_depth=0,
            )

        hdr = decoded["header"]
        trace_id = int(hdr["trace_id"])
        span_id = int(hdr["span_id"])
        nonce = int(hdr["nonce"])
        source_agent = str(hdr["source_agent"])
        target_agent = str(hdr["target_agent"])
        hop_depth = int(hdr["hop_depth"])
        body_payload = decoded["body"]["payload"]
        idem_key = body_payload.get("idempotency_key")
        if not isinstance(idem_key, str) or not idem_key.strip():
            idem_key = None

        # 2. Persistent cross-restart / multi-instance replay check (before policy & handler!)
        if self.state_store is not None and nonce > 0:
            is_fresh = self.state_store.record_nonce_if_new(
                source_agent, nonce, ts_now + self.state_ttl_ms
            )
            if not is_fresh:
                return self._encode_reply(
                    source_agent=target_agent,
                    target_agent=source_agent,
                    target="rpc:policy_rejected",
                    intent="yield_result",
                    payload={
                        "ok": False,
                        "reason_code": "REPLAY_DETECTED",
                        "detail": (
                            f"replayed nonce {nonce} for source agent '{source_agent}' "
                            f"blocked by persistent StateStore"
                        ),
                    },
                    trace_id=trace_id,
                    span_id=span_id,
                    hop_depth=hop_depth,
                )

        # 3. Idempotent retry deduplication BEFORE invoking handler or consuming new budget!
        if idem_key is not None:
            cached_reply = self._get_cached_idempotent(source_agent, idem_key)
            if cached_reply is not None:
                # Re-wrap cached result with deduplicated=True and current correlation IDs
                cached_dec = decode_frame(cached_reply)
                cached_payload = dict(cached_dec["body"]["payload"])
                cached_payload["deduplicated"] = True
                return self._encode_reply(
                    source_agent=target_agent,
                    target_agent=source_agent,
                    target=f"agent:{source_agent}",
                    intent="yield_result",
                    payload=cached_payload,
                    trace_id=trace_id,
                    span_id=span_id,
                    hop_depth=hop_depth + 1,
                )

        # 4. Independent receiver-side PolicyEngine guard-gate (reserves budget & records nonce)
        try:
            verdict = self.policy.evaluate_and_record(
                raw_request,
                signing_key=self.signing_key,
                now_ms=ts_now,
                public_keys=self.public_keys,
            )
        except ValueError as err:
            return self._encode_reply(
                source_agent=target_agent,
                target_agent=source_agent,
                target="rpc:error",
                intent="yield_result",
                payload={
                    "ok": False,
                    "reason_code": "AUTHENTICATION_FAILED",
                    "detail": str(err),
                },
                trace_id=trace_id,
                span_id=span_id,
                hop_depth=hop_depth,
            )

        if not verdict["allowed"]:
            return self._encode_reply(
                source_agent=target_agent,
                target_agent=source_agent,
                target="rpc:policy_rejected",
                intent="yield_result",
                payload={
                    "ok": False,
                    "reason_code": verdict["reason_code"],
                    "detail": verdict["detail"],
                },
                trace_id=trace_id,
                span_id=span_id,
                hop_depth=hop_depth,
            )

        # 5. Dispatch handler + independent usage metering + two-phase budget settlement
        handler = self._handlers.get(target_agent, self._default_handler)
        if handler is None:
            self.policy.release_reservation(trace_id, span_id)
            return self._encode_reply(
                source_agent=target_agent,
                target_agent=source_agent,
                target="rpc:no_handler",
                intent="yield_result",
                payload={
                    "ok": False,
                    "reason_code": "HANDLER_NOT_FOUND",
                    "detail": f"no RPC handler registered for target_agent '{target_agent}'",
                },
                trace_id=trace_id,
                span_id=span_id,
                hop_depth=hop_depth,
            )

        summary = decompile_frame(
            raw_request, signing_key=self.signing_key, public_keys=self.public_keys
        )
        try:
            result_payload, reported_tokens, reported_micro_usd = handler(decoded, summary)
            # Independent server-side metering floor prevents handlers from under-reporting usage
            measured = self.usage_meter.measure(decoded, summary, result_payload)
            reconciled_tokens = max(int(reported_tokens), measured.tokens)
            reconciled_micro_usd = max(int(reported_micro_usd), measured.micro_usd)
            receipt = self.policy.settle_usage(
                trace_id, span_id, reconciled_tokens, reconciled_micro_usd
            )
        except Exception as exc:
            self.policy.release_reservation(trace_id, span_id)
            return self._encode_reply(
                source_agent=target_agent,
                target_agent=source_agent,
                target="rpc:handler_error",
                intent="yield_result",
                payload={
                    "ok": False,
                    "reason_code": "HANDLER_EXECUTION_ERROR",
                    "detail": str(exc),
                },
                trace_id=trace_id,
                span_id=span_id,
                hop_depth=hop_depth,
            )

        reply_bytes = self._encode_reply(
            source_agent=target_agent,
            target_agent=source_agent,
            target=f"agent:{source_agent}",
            intent="yield_result",
            payload={
                "ok": True,
                "result": result_payload,
                "settled_tokens": receipt["actual_tokens"],
                "released_tokens": receipt["released_tokens"],
                "measured_tokens_floor": measured.tokens,
                "meter_source": measured.source,
                "deduplicated": False,
            },
            trace_id=trace_id,
            span_id=span_id,
            hop_depth=hop_depth + 1,
        )

        # Save idempotent result so a retry after client timeout returns cached receipt safely
        if idem_key is not None:
            self._save_cached_idempotent(source_agent, idem_key, reply_bytes, ts_now)

        return reply_bytes

    def start(self) -> tuple[str, int]:
        if self._server is not None:
            return self.address

        rpc_server = self

        class FrameRequestHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                sock: socket.socket = self.request
                sock.settimeout(rpc_server.socket_timeout_s)
                try:
                    if rpc_server.ssl_context is not None:
                        sock = rpc_server.ssl_context.wrap_socket(sock, server_side=True)
                    raw_req = recv_framed_bytes(sock)
                    raw_resp = rpc_server._handle_raw_request(raw_req)
                    send_framed_bytes(sock, raw_resp)
                except (EOFError, TimeoutError, OSError, ssl.SSLError, RpcTransportError):
                    pass

        self._server = _ThreadedTcpServer((self.host, self.requested_port), FrameRequestHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="agentwire-rpc-server",
            daemon=True,
        )
        self._thread.start()
        return self.address

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    def __enter__(self) -> AgentWireRpcServer:
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()


class AgentWireRpcClient:
    """TCP/TLS RPC client with Ed25519/HMAC signing, timeouts, idempotent retry safety,
    correlation checks, and exponential backoff.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        signing_key: bytes | None = None,
        private_key: bytes | None = None,
        server_public_keys: dict[str, bytes] | None = None,
        ssl_context: ssl.SSLContext | None = None,
        server_hostname: str | None = None,
        timeout_s: float = 3.0,
        max_retries: int = 2,
        retry_backoff_s: float = 0.05,
        auto_idempotency_key: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.signing_key = signing_key
        self.private_key = private_key
        self.server_public_keys = (
            dict(server_public_keys) if server_public_keys is not None else None
        )
        self.ssl_context = ssl_context
        self.server_hostname = server_hostname or host
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s
        self.auto_idempotency_key = auto_idempotency_key
        self._span_lock = threading.Lock()
        self._span_seq = 0

    def _next_span_id(self) -> int:
        with self._span_lock:
            self._span_seq += 1
            return self._span_seq

    def _open_socket(self) -> socket.socket:
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout_s)
        raw_sock.settimeout(self.timeout_s)
        if self.ssl_context is not None:
            try:
                return self.ssl_context.wrap_socket(
                    raw_sock, server_hostname=self.server_hostname
                )
            except Exception:
                raw_sock.close()
                raise
        return raw_sock

    def _decode_response(self, raw_resp: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.server_public_keys is not None:
            decoded = verify_frame_ed25519(raw_resp, self.server_public_keys)
            summary = decompile_frame(raw_resp, public_keys=self.server_public_keys)
        elif self.signing_key is not None:
            decoded = verify_frame(raw_resp, self.signing_key)
            summary = decompile_frame(raw_resp, signing_key=self.signing_key)
        else:
            decoded = decode_frame(raw_resp)
            summary = decompile_frame(raw_resp)
        return decoded, summary

    def send_raw(self, raw_frame: bytes) -> RpcResponse:
        t0 = time.perf_counter()
        with self._open_socket() as sock:
            send_framed_bytes(sock, raw_frame)
            raw_resp = recv_framed_bytes(sock)
        rtt_ms = (time.perf_counter() - t0) * 1000.0

        decoded, summary = self._decode_response(raw_resp)
        payload = dict(decoded["body"]["payload"])
        return RpcResponse(
            ok=bool(payload.get("ok", False)),
            trace_id=int(decoded["header"]["trace_id"]),
            span_id=int(decoded["header"]["span_id"]),
            payload=payload,
            reason_code=payload.get("reason_code"),
            detail=payload.get("detail"),
            raw_bytes=raw_resp,
            trace_summary=summary,
            rtt_ms=round(rtt_ms, 3),
            attempts=1,
            deduplicated=bool(payload.get("deduplicated", False)),
        )

    def call(
        self,
        source_agent: str,
        target_agent: str,
        action: str,
        target: str,
        intent: str,
        payload: dict[str, Any] | None = None,
        refs: list[str] | None = None,
        *,
        trace_id: int = 1,
        span_id: int | None = None,
        hop_depth: int = 1,
        max_tokens: int = 2048,
        max_micro_usd: int = 50_000,
        idempotency_key: str | None = None,
    ) -> RpcResponse:
        effective_span = span_id if span_id is not None else self._next_span_id()
        effective_payload = dict(payload) if payload is not None else {}

        # Guarantee a stable idempotency_key across retries to prevent duplicate execution on timeout
        if idempotency_key is not None:
            effective_payload["idempotency_key"] = idempotency_key
        elif (
            "idempotency_key" not in effective_payload
            and self.auto_idempotency_key
            and action.strip().upper() in ("MUTATE", "DELEGATE")
        ):
            effective_payload["idempotency_key"] = f"aw:{trace_id}:{effective_span}"

        is_mutate = action.strip().upper() == "MUTATE"
        has_idem = isinstance(effective_payload.get("idempotency_key"), str) and bool(
            str(effective_payload.get("idempotency_key")).strip()
        )
        # Never blindly retry non-idempotent MUTATE calls!
        allowed_retries = self.max_retries if (not is_mutate or has_idem) else 0

        last_err: Exception | None = None

        for attempt in range(1, allowed_retries + 2):
            try:
                if self.private_key is not None:
                    raw_req = sign_ast_ed25519(
                        source_agent=source_agent,
                        target_agent=target_agent,
                        action=action,
                        target=target,
                        intent=intent,
                        private_key=self.private_key,
                        nonce=secrets.randbits(63) or 1,
                        timestamp_ms=now_ms(),
                        payload=effective_payload,
                        refs=refs,
                        trace_id=trace_id,
                        span_id=effective_span,
                        hop_depth=hop_depth,
                        max_tokens=max_tokens,
                        max_micro_usd=max_micro_usd,
                    )
                elif self.signing_key is not None:
                    raw_req = sign_ast(
                        source_agent=source_agent,
                        target_agent=target_agent,
                        action=action,
                        target=target,
                        intent=intent,
                        signing_key=self.signing_key,
                        nonce=secrets.randbits(63) or 1,
                        timestamp_ms=now_ms(),
                        payload=effective_payload,
                        refs=refs,
                        trace_id=trace_id,
                        span_id=effective_span,
                        hop_depth=hop_depth,
                        max_tokens=max_tokens,
                        max_micro_usd=max_micro_usd,
                    )
                else:
                    raw_req = encode_ast(
                        source_agent=source_agent,
                        target_agent=target_agent,
                        action=action,
                        target=target,
                        intent=intent,
                        payload=effective_payload,
                        refs=refs,
                        trace_id=trace_id,
                        span_id=effective_span,
                        hop_depth=hop_depth,
                        max_tokens=max_tokens,
                        max_micro_usd=max_micro_usd,
                    )

                t0 = time.perf_counter()
                with self._open_socket() as sock:
                    send_framed_bytes(sock, raw_req)
                    raw_resp = recv_framed_bytes(sock)
                rtt_ms = (time.perf_counter() - t0) * 1000.0

                decoded, summary = self._decode_response(raw_resp)
                resp_trace = int(decoded["header"]["trace_id"])
                resp_span = int(decoded["header"]["span_id"])
                resp_payload = dict(decoded["body"]["payload"])
                ok = bool(resp_payload.get("ok", False))

                if ok and (resp_trace != trace_id or resp_span != effective_span):
                    raise RpcTransportError(
                        f"RPC correlation mismatch: expected ({trace_id}, {effective_span}), "
                        f"got ({resp_trace}, {resp_span})"
                    )

                return RpcResponse(
                    ok=ok,
                    trace_id=resp_trace,
                    span_id=resp_span,
                    payload=resp_payload,
                    reason_code=resp_payload.get("reason_code"),
                    detail=resp_payload.get("detail"),
                    raw_bytes=raw_resp,
                    trace_summary=summary,
                    rtt_ms=round(rtt_ms, 3),
                    attempts=attempt,
                    deduplicated=bool(resp_payload.get("deduplicated", False)),
                )
            except (TimeoutError, OSError, EOFError, ssl.SSLError) as err:
                last_err = err
                if attempt <= allowed_retries:
                    time.sleep(self.retry_backoff_s * (2 ** (attempt - 1)))
                    continue
                raise RpcTransportError(
                    f"RPC call to {self.host}:{self.port} failed after {attempt} attempt(s): {err}"
                ) from err

        raise RpcTransportError(f"RPC call failed: {last_err}")
