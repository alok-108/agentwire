"""Real-time trace emitter supporting in-memory rings, JSONL log sinks, callbacks,
and a built-in zero-dependency SSE/HTTP server for the AgentWire observability dashboard.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable


@dataclass(slots=True)
class TraceEvent:
    """Single observed AgentWire frame hop with byte, token, latency, and guard-gate telemetry."""

    timestamp_ms: int
    trace_id: int
    span_id: int
    hop_depth: int
    source_agent: str
    target_agent: str
    action: str
    target: str
    intent: str
    allowed: bool
    reason_code: str | None
    detail: str | None
    wire_bytes: int
    baseline_bytes: int
    wire_tokens: int
    baseline_tokens: int
    encode_us: float
    validate_us: float
    decompile_us: float
    raw_hex: str
    human_readable: str
    canonical_ast: str
    structured_lines: list[str] = field(default_factory=list)
    budget_tokens: int = 0
    budget_usd: float = 0.0
    tokenizer: str = "heuristic"

    @property
    def byte_reduction_pct(self) -> float:
        if self.baseline_bytes <= 0:
            return 0.0
        return max(0.0, (1.0 - (self.wire_bytes / self.baseline_bytes)) * 100.0)

    @property
    def token_reduction_pct(self) -> float:
        if self.baseline_tokens <= 0:
            return 0.0
        return max(0.0, (1.0 - (self.wire_tokens / self.baseline_tokens)) * 100.0)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["byte_reduction_pct"] = round(self.byte_reduction_pct, 2)
        data["token_reduction_pct"] = round(self.token_reduction_pct, 2)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


class TelemetryStream:
    """Thread-safe observability sink for AgentWire frames.

    Supports:
    - In-memory event buffer (`events`)
    - Append-only JSONL file persistence (`jsonl_path`)
    - Synchronous subscriber callbacks (`subscribe`)
    - Live HTTP + Server-Sent Events (SSE) endpoint (`start_http_server`) for the React dashboard
    """

    def __init__(
        self,
        jsonl_path: str | Path | None = None,
        max_events: int = 2000,
    ) -> None:
        self._lock = threading.RLock()
        self._events: list[TraceEvent] = []
        self._max_events = max_events
        self._callbacks: list[Callable[[TraceEvent], None]] = []
        self._sse_clients: list[queue.Queue[str]] = []
        self._jsonl_path = Path(jsonl_path) if jsonl_path is not None else None
        self._server: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None

        if self._jsonl_path is not None:
            self._jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def events(self) -> list[TraceEvent]:
        with self._lock:
            return list(self._events)

    def subscribe(self, callback: Callable[[TraceEvent], None]) -> None:
        """Register a callback invoked whenever a new [`TraceEvent`] is emitted."""
        with self._lock:
            self._callbacks.append(callback)

    def emit(self, event: TraceEvent) -> None:
        """Record a [`TraceEvent`], append to JSONL if configured, and fan out to SSE/callbacks."""
        serialized = event.to_json()
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max_events:
                del self._events[0 : len(self._events) - self._max_events]

            if self._jsonl_path is not None:
                with self._jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(serialized + "\n")

            callbacks = list(self._callbacks)
            dead_queues: list[queue.Queue[str]] = []
            for client_q in self._sse_clients:
                try:
                    client_q.put_nowait(serialized)
                except queue.Full:
                    dead_queues.append(client_q)
            for dq in dead_queues:
                self._sse_clients.remove(dq)

        for cb in callbacks:
            cb(event)

    def export_jsonl(self, path: str | Path) -> Path:
        """Write all buffered trace events to a JSONL file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            lines = [ev.to_json() for ev in self._events]
        target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return target

    def summary(self, price_per_1m_tokens_usd: float = 3.0) -> dict[str, Any]:
        """Compute aggregate compression, token savings, latency, and safety statistics."""
        with self._lock:
            events = list(self._events)

        total = len(events)
        if total == 0:
            return {
                "total_frames": 0,
                "allowed_frames": 0,
                "rejected_frames": 0,
                "baseline_bytes": 0,
                "wire_bytes": 0,
                "byte_reduction_pct": 0.0,
                "baseline_tokens": 0,
                "wire_tokens": 0,
                "token_reduction_pct": 0.0,
                "estimated_usd_saved": 0.0,
                "avg_pipeline_us": 0.0,
            }

        allowed = sum(1 for e in events if e.allowed)
        rejected = total - allowed
        baseline_bytes = sum(e.baseline_bytes for e in events)
        wire_bytes = sum(e.wire_bytes for e in events)
        baseline_tokens = sum(e.baseline_tokens for e in events)
        wire_tokens = sum(e.wire_tokens for e in events)
        saved_tokens = max(0, baseline_tokens - wire_tokens)
        est_usd_saved = (saved_tokens / 1_000_000.0) * price_per_1m_tokens_usd
        avg_pipeline_us = (
            sum(e.encode_us + e.validate_us + e.decompile_us for e in events) / total
        )

        return {
            "total_frames": total,
            "allowed_frames": allowed,
            "rejected_frames": rejected,
            "baseline_bytes": baseline_bytes,
            "wire_bytes": wire_bytes,
            "byte_reduction_pct": round(
                (1.0 - wire_bytes / baseline_bytes) * 100.0 if baseline_bytes else 0.0, 2
            ),
            "baseline_tokens": baseline_tokens,
            "wire_tokens": wire_tokens,
            "token_reduction_pct": round(
                (1.0 - wire_tokens / baseline_tokens) * 100.0 if baseline_tokens else 0.0, 2
            ),
            "estimated_usd_saved": round(est_usd_saved, 6),
            "avg_pipeline_us": round(avg_pipeline_us, 2),
        }

    def start_http_server(self, host: str = "127.0.0.1", port: int = 8765) -> str:
        """Start a lightweight background HTTP + SSE server for the React TraceViewer dashboard.

        Endpoints:
        - `GET /api/events`  -> JSON array of buffered `TraceEvent` objects + aggregate summary
        - `GET /api/stream`  -> Server-Sent Events stream of live `TraceEvent` JSON payloads
        """
        if self._server is not None:
            return f"http://{host}:{port}"

        stream_ref = self

        class TelemetryHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _send_cors(self) -> None:
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")

            def do_OPTIONS(self) -> None:
                self.send_response(204)
                self._send_cors()
                self.end_headers()

            def do_GET(self) -> None:
                if self.path == "/api/events":
                    payload = json.dumps(
                        {
                            "summary": stream_ref.summary(),
                            "events": [e.to_dict() for e in stream_ref.events],
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self._send_cors()
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return

                if self.path == "/api/stream":
                    self.send_response(200)
                    self._send_cors()
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()

                    client_q: queue.Queue[str] = queue.Queue(maxsize=256)
                    with stream_ref._lock:
                        snapshot = [e.to_json() for e in stream_ref._events]
                        stream_ref._sse_clients.append(client_q)

                    try:
                        for item in snapshot:
                            self.wfile.write(f"data: {item}\n\n".encode("utf-8"))
                        self.wfile.flush()

                        while True:
                            try:
                                msg = client_q.get(timeout=15.0)
                                self.wfile.write(f"data: {msg}\n\n".encode("utf-8"))
                                self.wfile.flush()
                            except queue.Empty:
                                self.wfile.write(b": keepalive\n\n")
                                self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass
                    finally:
                        with stream_ref._lock:
                            if client_q in stream_ref._sse_clients:
                                stream_ref._sse_clients.remove(client_q)
                    return

                self.send_response(404)
                self._send_cors()
                self.end_headers()

        self._server = ThreadingHTTPServer((host, port), TelemetryHandler)
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            name="agentwire-telemetry-http",
            daemon=True,
        )
        self._server_thread.start()
        return f"http://{host}:{port}"

    def stop_http_server(self) -> None:
        """Gracefully stop the background HTTP/SSE server if running."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._server_thread = None


def now_ms() -> int:
    return int(time.time() * 1000)
