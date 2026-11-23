"""Cross-process / networked length-prefixed TCP RPC transport for AgentWire (`AW01`).

Wire Framing on TCP:
    [4-byte big-endian unsigned length N][N bytes of AW01 binary frame]

Security & Reliability Guarantees:
- Every inbound request on `AgentWireRpcServer` is independently verified:
  1. Constant-time HMAC-SHA256 verification via Rust `verify_frame` (when `signing_key` is set).
  2. Independent receiver-side Rust `PolicyEngine.evaluate_and_record` (sender's
     `GUARD_VERIFIED` bit is NEVER trusted).
  3. Replay nonce + timestamp skew enforcement.
  4. Two-phase budget accounting: reserves on acceptance, calls `settle_usage` with actual
     handler token/cost consumption on success, or calls `release_reservation` on handler error.
- `AgentWireRpcClient` supports connection timeouts, request/response `(trace_id, span_id)`
  correlation, and exponential-backoff retries with fresh nonces on transient transport errors.
"""

from __future__ import annotations

import secrets
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from agentwire._agentwire import (
    PolicyEngine,
    decompile_frame,
    decode_frame,
    encode_ast,
    sign_ast,
    verify_frame,
)
from agentwire.telemetry.stream import now_ms

MAX_RPC_FRAME_BYTES = 4 * 1024 * 1024  # 4 MiB hard cap against OOM framing attacks


class RpcTransportError(RuntimeError):
    """Raised on network framing, timeout, correlation, or authentication transport failure."""


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


# Handler signature: (decoded_frame, trace_summary) -> (response_payload_dict, actual_tokens, actual_micro_usd)
RpcHandler = Callable[
    [dict[str, Any], dict[str, Any]],
    tuple[dict[str, Any], int, int],
]


class _ThreadedTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class AgentWireRpcServer:
    """Networked TCP RPC server enforcing independent receiver-side HMAC + PolicyEngine guard-gates."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        policy: PolicyEngine | None = None,
        signing_key: bytes | None = None,
        server_agent_id: str = "rpc_server",
        socket_timeout_s: float = 5.0,
    ) -> None:
        self.host = host
        self.requested_port = port
        self.signing_key = signing_key
        if policy is not None:
            self.policy = policy
        elif signing_key is not None:
            self.policy = PolicyEngine.strict_authenticated()
        else:
            self.policy = PolicyEngine.default_multi_agent()
        self.server_agent_id = server_agent_id
        self.socket_timeout_s = socket_timeout_s
        self._handlers: dict[str, RpcHandler] = {}
        self._default_handler: RpcHandler | None = None
        self._server: _ThreadedTcpServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            return (self.host, self.requested_port)
        host, port = self._server.server_address[:2]
        return (str(host), int(port))

    def register_handler(self, target_agent: str, handler: RpcHandler) -> None:
        """Register an RPC handler for inbound frames addressed to `target_agent`."""
        self._handlers[target_agent] = handler

    def set_default_handler(self, handler: RpcHandler) -> None:
        """Fallback handler invoked when no specific `target_agent` handler is registered."""
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

    def _handle_raw_request(self, raw_request: bytes) -> bytes:
        ts_now = now_ms()
        # 1. Decode + optional mandatory constant-time HMAC-SHA256 verification
        try:
            if self.signing_key is not None:
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
        source_agent = str(hdr["source_agent"])
        target_agent = str(hdr["target_agent"])
        hop_depth = int(hdr["hop_depth"])

        # 2. Independent receiver-side PolicyEngine guard-gate (reserves budget & records nonce)
        try:
            verdict = self.policy.evaluate_and_record(
                raw_request,
                signing_key=self.signing_key,
                now_ms=ts_now,
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

        # 3. Dispatch to handler & settle (or release on failure) two-phase budget reservation
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

        summary = decompile_frame(raw_request, signing_key=self.signing_key)
        try:
            result_payload, actual_tokens, actual_micro_usd = handler(decoded, summary)
            receipt = self.policy.settle_usage(
                trace_id, span_id, int(actual_tokens), int(actual_micro_usd)
            )
        except Exception as exc:
            # Refund 100% of reserved budget on handler execution failure
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

        return self._encode_reply(
            source_agent=target_agent,
            target_agent=source_agent,
            target=f"agent:{source_agent}",
            intent="yield_result",
            payload={
                "ok": True,
                "result": result_payload,
                "settled_tokens": receipt["actual_tokens"],
                "released_tokens": receipt["released_tokens"],
            },
            trace_id=trace_id,
            span_id=span_id,
            hop_depth=hop_depth + 1,
        )

    def start(self) -> tuple[str, int]:
        """Bind TCP socket and start serving RPC frames in a background daemon thread."""
        if self._server is not None:
            return self.address

        rpc_server = self

        class FrameRequestHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(rpc_server.socket_timeout_s)
                try:
                    raw_req = recv_framed_bytes(self.request)
                    raw_resp = rpc_server._handle_raw_request(raw_req)
                    send_framed_bytes(self.request, raw_resp)
                except (EOFError, TimeoutError, OSError, RpcTransportError):
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
    """TCP RPC client with HMAC-SHA256 signing, timeouts, correlation checks, and backoff retries."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        signing_key: bytes | None = None,
        timeout_s: float = 3.0,
        max_retries: int = 2,
        retry_backoff_s: float = 0.05,
    ) -> None:
        self.host = host
        self.port = port
        self.signing_key = signing_key
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s
        self._span_lock = threading.Lock()
        self._span_seq = 0

    def _next_span_id(self) -> int:
        with self._span_lock:
            self._span_seq += 1
            return self._span_seq

    def send_raw(self, raw_frame: bytes) -> RpcResponse:
        """Transmit a pre-encoded/pre-signed binary frame over TCP (useful for testing/replay)."""
        t0 = time.perf_counter()
        with socket.create_connection((self.host, self.port), timeout=self.timeout_s) as sock:
            sock.settimeout(self.timeout_s)
            send_framed_bytes(sock, raw_frame)
            raw_resp = recv_framed_bytes(sock)
        rtt_ms = (time.perf_counter() - t0) * 1000.0

        if self.signing_key is not None:
            decoded = verify_frame(raw_resp, self.signing_key)
        else:
            decoded = decode_frame(raw_resp)
        summary = decompile_frame(raw_resp, signing_key=self.signing_key)
        payload = dict(decoded["body"]["payload"])
        ok = bool(payload.get("ok", False))
        return RpcResponse(
            ok=ok,
            trace_id=int(decoded["header"]["trace_id"]),
            span_id=int(decoded["header"]["span_id"]),
            payload=payload,
            reason_code=payload.get("reason_code"),
            detail=payload.get("detail"),
            raw_bytes=raw_resp,
            trace_summary=summary,
            rtt_ms=round(rtt_ms, 3),
            attempts=1,
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
    ) -> RpcResponse:
        """Encode/sign an AST operation, send over TCP with retry/timeout, and verify the reply."""
        effective_span = span_id if span_id is not None else self._next_span_id()
        last_err: Exception | None = None

        for attempt in range(1, self.max_retries + 2):
            try:
                if self.signing_key is not None:
                    raw_req = sign_ast(
                        source_agent=source_agent,
                        target_agent=target_agent,
                        action=action,
                        target=target,
                        intent=intent,
                        signing_key=self.signing_key,
                        nonce=secrets.randbits(63) or 1,
                        timestamp_ms=now_ms(),
                        payload=payload,
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
                        payload=payload,
                        refs=refs,
                        trace_id=trace_id,
                        span_id=effective_span,
                        hop_depth=hop_depth,
                        max_tokens=max_tokens,
                        max_micro_usd=max_micro_usd,
                    )

                t0 = time.perf_counter()
                with socket.create_connection(
                    (self.host, self.port), timeout=self.timeout_s
                ) as sock:
                    sock.settimeout(self.timeout_s)
                    send_framed_bytes(sock, raw_req)
                    raw_resp = recv_framed_bytes(sock)
                rtt_ms = (time.perf_counter() - t0) * 1000.0

                if self.signing_key is not None:
                    decoded = verify_frame(raw_resp, self.signing_key)
                else:
                    decoded = decode_frame(raw_resp)
                summary = decompile_frame(raw_resp, signing_key=self.signing_key)

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
                )
            except (TimeoutError, OSError, EOFError) as err:
                last_err = err
                if attempt <= self.max_retries:
                    time.sleep(self.retry_backoff_s * (2 ** (attempt - 1)))
                    continue
                raise RpcTransportError(
                    f"RPC call to {self.host}:{self.port} failed after {attempt} attempt(s): {err}"
                ) from err

        raise RpcTransportError(f"RPC call failed: {last_err}")
