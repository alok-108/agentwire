"""High-level Python SDK client (`WireClient`) and token/byte savings telemetry."""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from typing import Any

from agentwire._agentwire import (
    PolicyEngine,
    decompile_frame,
    decode_frame,
    encode_ast,
)
from agentwire.telemetry.stream import TelemetryStream, TraceEvent, now_ms


class PolicyViolationError(RuntimeError):
    """Raised when a frame is blocked by the deterministic Rust `PolicyEngine` guard-gate."""

    def __init__(
        self,
        reason_code: str,
        detail: str,
        frame_bytes: bytes | None = None,
    ) -> None:
        super().__init__(f"[{reason_code}] {detail}")
        self.reason_code = reason_code
        self.detail = detail
        self.frame_bytes = frame_bytes


class TokenEstimator:
    """Counts LLM tokens using `tiktoken` when installed, or a deterministic BPE-calibrated fallback."""

    def __init__(self, encoding_name: str = "cl100k_base") -> None:
        self._encoding = None
        self.backend_label = "heuristic-bpe-approx"
        try:
            import tiktoken  # type: ignore[import-not-found]

            self._encoding = tiktoken.get_encoding(encoding_name)
            self.backend_label = f"tiktoken:{encoding_name}"
        except Exception:
            self._encoding = None

    def count_text(self, text: str) -> int:
        if not text:
            return 0
        if self._encoding is not None:
            return len(self._encoding.encode(text))
        # Deterministic approximation calibrated for English + JSON (~3.6 chars/token)
        return max(1, math.ceil(len(text) / 3.6))

    def count_json(self, obj: Any) -> int:
        return self.count_text(json.dumps(obj, ensure_ascii=False, indent=2))


@dataclass
class WireMetrics:
    """Running byte, token, latency, and safety counters for a `WireClient`."""

    frames_sent: int = 0
    frames_allowed: int = 0
    frames_rejected: int = 0
    baseline_bytes: int = 0
    wire_bytes: int = 0
    baseline_tokens: int = 0
    wire_tokens: int = 0
    total_encode_us: float = 0.0
    total_validate_us: float = 0.0
    total_decompile_us: float = 0.0

    @property
    def byte_reduction_pct(self) -> float:
        if self.baseline_bytes <= 0:
            return 0.0
        return (1.0 - (self.wire_bytes / self.baseline_bytes)) * 100.0

    @property
    def token_reduction_pct(self) -> float:
        if self.baseline_tokens <= 0:
            return 0.0
        return (1.0 - (self.wire_tokens / self.baseline_tokens)) * 100.0

    def estimated_usd_saved(self, price_per_1m_tokens: float = 3.0) -> float:
        saved = max(0, self.baseline_tokens - self.wire_tokens)
        return (saved / 1_000_000.0) * price_per_1m_tokens


@dataclass
class WireSendResult:
    """Result returned by `WireClient.send`."""

    allowed: bool
    frame_bytes: bytes
    trace_summary: dict[str, Any]
    validation: dict[str, Any]
    event: TraceEvent
    encode_us: float
    validate_us: float
    decompile_us: float


@dataclass
class WireReceiveResult:
    """Result returned by `WireClient.receive`."""

    decoded: dict[str, Any]
    trace_summary: dict[str, Any]
    validation: dict[str, Any] | None
    decode_us: float
    decompile_us: float


def _synthesize_verbose_baseline(
    source_agent: str,
    target_agent: str,
    action: str,
    target: str,
    intent: str,
    payload: dict[str, Any],
    refs: list[str],
    trace_id: int,
    span_id: int,
    hop_depth: int,
    max_tokens: int,
    max_micro_usd: int,
) -> dict[str, Any]:
    """Build the realistic equivalent verbose JSON/natural-language handoff payload that
    multi-agent frameworks (LangGraph/CrewAI/AutoGen) typically serialize between agents.
    """
    return {
        "protocol": "json-agent-message-v1",
        "metadata": {
            "trace_id": f"trace-{trace_id}",
            "span_id": f"span-{span_id}",
            "hop_depth": hop_depth,
            "sender_role": source_agent,
            "recipient_role": target_agent,
            "execution_constraints": {
                "max_output_tokens": max_tokens,
                "max_cost_usd": round(max_micro_usd / 1_000_000.0, 6),
                "require_structured_response": True,
            },
        },
        "messages": [
            {
                "role": "system",
                "content": (
                    f"You are the {target_agent} agent in a multi-agent workflow. "
                    f"Follow the structured instruction from {source_agent}, obey safety policies, "
                    f"and respond only with validated outputs for target '{target}'."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Please execute action {action} with intent '{intent}' on resource '{target}'. "
                    f"Use the attached parameters and context references to complete this step accurately."
                ),
                "tool_call_envelope": {
                    "type": "function",
                    "function": {
                        "name": f"{action.lower()}_{intent}",
                        "target_resource": target,
                        "arguments": payload,
                        "context_references": refs,
                    },
                },
            },
        ],
    }


class WireClient:
    """High-level AgentWire client combining the Rust binary codec, deterministic
    policy guard-gate, lossless decompiler, and telemetry stream.
    """

    def __init__(
        self,
        policy: PolicyEngine | None = None,
        telemetry: TelemetryStream | None = None,
        enable_safety_gate: bool = True,
        raise_on_reject: bool = True,
        token_estimator: TokenEstimator | None = None,
    ) -> None:
        self.policy = policy if policy is not None else PolicyEngine.default_multi_agent()
        self.telemetry = telemetry if telemetry is not None else TelemetryStream()
        self.enable_safety_gate = enable_safety_gate
        self.raise_on_reject = raise_on_reject
        self.token_estimator = token_estimator if token_estimator is not None else TokenEstimator()
        self.metrics = WireMetrics()
        self._span_counter = 0
        self._trace_counter = 1000

    def next_trace_id(self) -> int:
        self._trace_counter += 1
        return self._trace_counter

    def send(
        self,
        source_agent: str,
        target_agent: str,
        action: str,
        target: str,
        intent: str,
        payload: dict[str, Any] | None = None,
        refs: list[str] | None = None,
        *,
        trace_id: int | None = None,
        span_id: int | None = None,
        hop_depth: int = 0,
        max_tokens: int = 2048,
        max_micro_usd: int = 50_000,
        baseline_payload: dict[str, Any] | str | None = None,
    ) -> WireSendResult:
        """Compile AST -> binary wire frame -> evaluate Rust guard-gate -> decompile & emit trace."""
        payload_dict = payload or {}
        refs_list = refs or []
        effective_trace = trace_id if trace_id is not None else self.next_trace_id()
        if span_id is None:
            self._span_counter += 1
            effective_span = self._span_counter
        else:
            effective_span = span_id

        # 1. Encode binary frame via Rust core
        t0 = time.perf_counter_ns()
        raw_frame = encode_ast(
            source_agent=source_agent,
            target_agent=target_agent,
            action=action,
            target=target,
            intent=intent,
            payload=payload_dict,
            refs=refs_list,
            trace_id=effective_trace,
            span_id=effective_span,
            hop_depth=hop_depth,
            max_tokens=max_tokens,
            max_micro_usd=max_micro_usd,
            guard_verified=False,
        )
        t1 = time.perf_counter_ns()
        encode_us = (t1 - t0) / 1000.0

        # 2. Deterministic Rust policy guard-gate check (before any wire/LLM transmission!)
        t2 = time.perf_counter_ns()
        if self.enable_safety_gate:
            validation = self.policy.evaluate_and_record(raw_frame)
        else:
            validation = {"allowed": True, "reason_code": None, "detail": None}
        t3 = time.perf_counter_ns()
        validate_us = (t3 - t2) / 1000.0

        allowed = bool(validation["allowed"])

        # Stamp GUARD_VERIFIED flag into the final wire frame when approved
        if allowed and self.enable_safety_gate:
            raw_frame = encode_ast(
                source_agent=source_agent,
                target_agent=target_agent,
                action=action,
                target=target,
                intent=intent,
                payload=payload_dict,
                refs=refs_list,
                trace_id=effective_trace,
                span_id=effective_span,
                hop_depth=hop_depth,
                max_tokens=max_tokens,
                max_micro_usd=max_micro_usd,
                guard_verified=True,
            )

        # 3. Lossless decompilation for human observability & target agent context
        t4 = time.perf_counter_ns()
        summary = decompile_frame(raw_frame)
        t5 = time.perf_counter_ns()
        decompile_us = (t5 - t4) / 1000.0

        # 4. Compute baseline comparison metrics (verbose JSON vs AgentWire)
        if baseline_payload is None:
            baseline_obj = _synthesize_verbose_baseline(
                source_agent=source_agent,
                target_agent=target_agent,
                action=action,
                target=target,
                intent=intent,
                payload=payload_dict,
                refs=refs_list,
                trace_id=effective_trace,
                span_id=effective_span,
                hop_depth=hop_depth,
                max_tokens=max_tokens,
                max_micro_usd=max_micro_usd,
            )
            baseline_text = json.dumps(baseline_obj, ensure_ascii=False, indent=2)
        elif isinstance(baseline_payload, str):
            baseline_text = baseline_payload
        else:
            baseline_text = json.dumps(baseline_payload, ensure_ascii=False, indent=2)

        baseline_bytes = len(baseline_text.encode("utf-8"))
        wire_bytes = len(raw_frame)
        baseline_tokens = self.token_estimator.count_text(baseline_text)
        # Compact canonical AST is what gets projected into the receiving LLM's context window
        wire_tokens = self.token_estimator.count_text(summary["canonical_ast"])

        event = TraceEvent(
            timestamp_ms=now_ms(),
            trace_id=effective_trace,
            span_id=effective_span,
            hop_depth=hop_depth,
            source_agent=source_agent,
            target_agent=target_agent,
            action=summary["action"],
            target=summary["target"],
            intent=summary["intent"],
            allowed=allowed,
            reason_code=validation["reason_code"],
            detail=validation["detail"],
            wire_bytes=wire_bytes,
            baseline_bytes=baseline_bytes,
            wire_tokens=wire_tokens,
            baseline_tokens=baseline_tokens,
            encode_us=round(encode_us, 2),
            validate_us=round(validate_us, 2),
            decompile_us=round(decompile_us, 2),
            raw_hex=raw_frame.hex(" "),
            human_readable=summary["human_readable"],
            canonical_ast=summary["canonical_ast"],
            structured_lines=list(summary["structured_lines"]),
            budget_tokens=summary["budget_tokens"],
            budget_usd=summary["budget_usd"],
            tokenizer=self.token_estimator.backend_label,
        )

        # Update running metrics & stream telemetry
        self.metrics.frames_sent += 1
        if allowed:
            self.metrics.frames_allowed += 1
        else:
            self.metrics.frames_rejected += 1
        self.metrics.baseline_bytes += baseline_bytes
        self.metrics.wire_bytes += wire_bytes
        self.metrics.baseline_tokens += baseline_tokens
        self.metrics.wire_tokens += wire_tokens
        self.metrics.total_encode_us += encode_us
        self.metrics.total_validate_us += validate_us
        self.metrics.total_decompile_us += decompile_us

        self.telemetry.emit(event)

        if not allowed and self.raise_on_reject:
            raise PolicyViolationError(
                reason_code=str(validation["reason_code"]),
                detail=str(validation["detail"]),
                frame_bytes=raw_frame,
            )

        return WireSendResult(
            allowed=allowed,
            frame_bytes=raw_frame,
            trace_summary=summary,
            validation=validation,
            event=event,
            encode_us=encode_us,
            validate_us=validate_us,
            decompile_us=decompile_us,
        )

    def receive(
        self,
        raw_bytes: bytes,
        *,
        verify_policy: bool = True,
    ) -> WireReceiveResult:
        """Decode an inbound binary AgentWire frame, verify CRC32 + policy, and decompile."""
        t0 = time.perf_counter_ns()
        decoded = decode_frame(raw_bytes)
        t1 = time.perf_counter_ns()
        decode_us = (t1 - t0) / 1000.0

        validation: dict[str, Any] | None = None
        if verify_policy and self.enable_safety_gate:
            validation = self.policy.validate_frame(raw_bytes)
            if not validation["allowed"] and self.raise_on_reject:
                raise PolicyViolationError(
                    reason_code=str(validation["reason_code"]),
                    detail=str(validation["detail"]),
                    frame_bytes=raw_bytes,
                )

        t2 = time.perf_counter_ns()
        summary = decompile_frame(raw_bytes)
        t3 = time.perf_counter_ns()
        decompile_us = (t3 - t2) / 1000.0

        return WireReceiveResult(
            decoded=decoded,
            trace_summary=summary,
            validation=validation,
            decode_us=decode_us,
            decompile_us=decompile_us,
        )
