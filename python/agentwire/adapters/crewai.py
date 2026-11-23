"""Drop-in task & message bus adapter for CrewAI (`CrewAIWire`).

Gracefully supports environments both with and without `crewai` installed.
Provides deterministic capability-checked task delegation over binary AgentWire frames.
"""

from __future__ import annotations

import importlib.util
from typing import Any, Callable

from agentwire._agentwire import PolicyEngine
from agentwire.client import WireClient, WireSendResult
from agentwire.telemetry.stream import TelemetryStream

CREWAI_INSTALLED: bool = importlib.util.find_spec("crewai") is not None


class CrewAIWire:
    """Binary RPC task bus adapter for CrewAI role-based agent crews."""

    def __init__(
        self,
        *,
        policy: PolicyEngine | None = None,
        telemetry: TelemetryStream | None = None,
        enable_safety_gate: bool = True,
        raise_on_reject: bool = True,
    ) -> None:
        self.client = WireClient(
            policy=policy,
            telemetry=telemetry,
            enable_safety_gate=enable_safety_gate,
            raise_on_reject=raise_on_reject,
        )
        self.crewai_available = CREWAI_INSTALLED
        self._handlers: dict[str, Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]] = {}
        self._trace_id = self.client.next_trace_id()
        self._hop = 0

    @property
    def telemetry(self) -> TelemetryStream:
        return self.client.telemetry

    def register_role(
        self,
        role: str,
        handler: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> None:
        """Register a role handler `fn(payload, trace_summary) -> result_payload` on the bus."""
        self._handlers[role] = handler

    def dispatch_task(
        self,
        from_role: str,
        to_role: str,
        *,
        action: str = "DELEGATE",
        target: str | None = None,
        intent: str = "delegate_task",
        task_payload: dict[str, Any] | None = None,
        refs: list[str] | None = None,
        max_tokens: int = 2048,
        max_micro_usd: int = 50_000,
    ) -> dict[str, Any]:
        """Encode, guard-validate, and dispatch a CrewAI task over binary AgentWire frames.

        If a handler is registered for `to_role`, executes it with the decoded payload and
        returns both the outbound `send_result` and the handler's `response`.
        """
        self._hop += 1
        effective_target = target or f"agent:{to_role}"

        send_result: WireSendResult = self.client.send(
            source_agent=from_role,
            target_agent=to_role,
            action=action,
            target=effective_target,
            intent=intent,
            payload=task_payload or {},
            refs=refs,
            trace_id=self._trace_id,
            hop_depth=self._hop,
            max_tokens=max_tokens,
            max_micro_usd=max_micro_usd,
        )

        response_payload: dict[str, Any] | None = None
        if send_result.allowed and to_role in self._handlers:
            recv = self.client.receive(send_result.frame_bytes, verify_policy=False)
            response_payload = self._handlers[to_role](
                recv.decoded["body"]["payload"],
                recv.trace_summary,
            )

        return {
            "allowed": send_result.allowed,
            "frame_bytes": send_result.frame_bytes,
            "trace_summary": send_result.trace_summary,
            "response": response_payload,
        }
