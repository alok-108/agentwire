"""Drop-in channel & state serializer adapter for LangGraph (`LangGraphWire`).

Works seamlessly whether `langgraph` is installed or not:
- When `langgraph` is installed, integrates with `StateGraph` node execution and channels.
- When `langgraph` is absent, operates cleanly as a duck-typed state-transition wire
  serializer/middleware with full Rust codec, policy guard-gate, and telemetry support.
"""

from __future__ import annotations

import importlib.util
from typing import Any, Callable

from agentwire._agentwire import PolicyEngine
from agentwire.client import WireClient, WireReceiveResult, WireSendResult
from agentwire.telemetry.stream import TelemetryStream

LANGGRAPH_INSTALLED: bool = importlib.util.find_spec("langgraph") is not None


class LangGraphWire:
    """Drop-in binary wire protocol channel/serializer for LangGraph workflows.

    Example:
        ```python
        from agentwire.adapters import LangGraphWire

        wire = LangGraphWire(enable_safety_gate=True)
        frame_bytes = wire.serialize_state_update(
            source_agent="planner",
            target_agent="researcher",
            action="DELEGATE",
            target="repo:billing",
            intent="analyze_schema",
            state_delta={"module": "billing", "depth": 2},
        )
        ```
    """

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
        self.langgraph_available = LANGGRAPH_INSTALLED
        self._trace_id = self.client.next_trace_id()
        self._hop = 0

    @property
    def telemetry(self) -> TelemetryStream:
        return self.client.telemetry

    def serialize_state_update(
        self,
        source_agent: str,
        target_agent: str,
        state_delta: dict[str, Any],
        *,
        action: str = "DELEGATE",
        target: str | None = None,
        intent: str = "state_handoff",
        refs: list[str] | None = None,
        max_tokens: int = 2048,
        max_micro_usd: int = 50_000,
    ) -> WireSendResult:
        """Encode and policy-validate a LangGraph state delta into an AgentWire binary frame."""
        self._hop += 1
        effective_target = target or f"agent:{target_agent}"
        return self.client.send(
            source_agent=source_agent,
            target_agent=target_agent,
            action=action,
            target=effective_target,
            intent=intent,
            payload=state_delta,
            refs=refs,
            trace_id=self._trace_id,
            hop_depth=self._hop,
            max_tokens=max_tokens,
            max_micro_usd=max_micro_usd,
        )

    def deserialize_state_update(
        self,
        raw_bytes: bytes,
        *,
        verify_policy: bool = True,
    ) -> tuple[dict[str, Any], WireReceiveResult]:
        """Decode a binary AgentWire frame back into a LangGraph state dictionary + trace."""
        recv = self.client.receive(raw_bytes, verify_policy=verify_policy)
        payload = dict(recv.decoded["body"]["payload"])
        payload["_agentwire_ast"] = recv.trace_summary["canonical_ast"]
        payload["_agentwire_trace"] = recv.trace_summary["human_readable"]
        return payload, recv

    def wrap_node(
        self,
        source_agent: str,
        target_agent: str,
        fn: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        action: str = "DELEGATE",
        target: str | None = None,
        intent: str = "node_transition",
        max_tokens: int = 2048,
        max_micro_usd: int = 50_000,
    ) -> Callable[[dict[str, Any]], dict[str, Any]]:
        """Wrap any LangGraph node callable so its output state passes through AgentWire."""

        def _wrapped(state: dict[str, Any]) -> dict[str, Any]:
            # If inbound state carried a wire frame, decode & project it first
            if "_agentwire_frame" in state and isinstance(state["_agentwire_frame"], bytes):
                decoded_state, _ = self.deserialize_state_update(state["_agentwire_frame"])
                merged_in = {**state, **decoded_state}
            else:
                merged_in = state

            raw_output = fn(merged_in)
            clean_delta = {
                k: v for k, v in raw_output.items() if not k.startswith("_agentwire_")
            }
            sent = self.serialize_state_update(
                source_agent=source_agent,
                target_agent=target_agent,
                state_delta=clean_delta,
                action=action,
                target=target,
                intent=intent,
                max_tokens=max_tokens,
                max_micro_usd=max_micro_usd,
            )
            return {
                **clean_delta,
                "_agentwire_frame": sent.frame_bytes,
                "_agentwire_ast": sent.trace_summary["canonical_ast"],
            }

        _wrapped.__name__ = getattr(fn, "__name__", "agentwire_node")
        return _wrapped

    def attach_to_graph(self, graph: Any) -> Any:
        """Attach this `LangGraphWire` instance to a LangGraph `StateGraph` (or duck-typed graph).

        If the graph exposes `set_channel_protocol`, registers directly; otherwise attaches
        as `graph.agentwire` without breaking graph compilation.
        """
        if hasattr(graph, "set_channel_protocol") and callable(graph.set_channel_protocol):
            graph.set_channel_protocol(self)
        else:
            setattr(graph, "agentwire", self)
        return graph
