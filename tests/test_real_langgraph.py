"""Real upstream LangGraph workflow integration tests.

Executes an actual compiled `langgraph.graph.StateGraph` wrapped with `LangGraphWire`,
verifying real StateGraph multi-node handoffs, binary AW01 frame state passing,
telemetry capture, and deterministic pre-flight PolicyViolationError enforcement.
"""

from __future__ import annotations

from typing import TypedDict

import pytest

langgraph_graph = pytest.importorskip("langgraph.graph")
END = langgraph_graph.END
START = langgraph_graph.START
StateGraph = langgraph_graph.StateGraph

from swarmwire import PolicyViolationError, TelemetryStream
from swarmwire.adapters import LangGraphWire


class BillingWorkflowState(TypedDict, total=False):
    module: str
    table: str
    findings: str
    patch_file: str
    approved: bool
    _agentwire_frame: bytes
    _agentwire_ast: str


def test_real_langgraph_stategraph_end_to_end_with_agentwire() -> None:
    stream = TelemetryStream()
    wire = LangGraphWire(telemetry=stream, enable_safety_gate=True)

    def planner(state: BillingWorkflowState) -> dict:
        return {"module": state["module"], "table": "invoices"}

    def researcher(state: BillingWorkflowState) -> dict:
        return {"findings": f"inspected {state['module']}.{state['table']}"}

    def coder(state: BillingWorkflowState) -> dict:
        return {"patch_file": f"src/{state['module']}/ledger.py", "approved": True}

    graph = StateGraph(BillingWorkflowState)
    graph.add_node(
        "planner",
        wire.wrap_node(
            "planner", "researcher", planner,
            action="DELEGATE", target="repo:billing", intent="analyze_schema",
        ),
    )
    graph.add_node(
        "researcher",
        wire.wrap_node(
            "researcher", "coder", researcher,
            action="YIELD", target="agent:coder", intent="yield_result",
        ),
    )
    graph.add_node(
        "coder",
        wire.wrap_node(
            "coder", "reviewer", coder,
            action="MUTATE", target="repo:src/billing/ledger.py", intent="apply_patch",
        ),
    )

    graph.add_edge(START, "planner")
    graph.add_edge("planner", "researcher")
    graph.add_edge("researcher", "coder")
    graph.add_edge("coder", END)

    app = graph.compile()
    final_state = app.invoke({"module": "billing"})

    assert final_state["findings"] == "inspected billing.invoices"
    assert final_state["patch_file"] == "src/billing/ledger.py"
    assert final_state["approved"] is True
    assert isinstance(final_state["_agentwire_frame"], bytes)
    assert final_state["_agentwire_frame"][:4] == b"AW01"

    # All 3 hops recorded cleanly in TelemetryStream
    assert len(stream.events) == 3
    assert all(ev.allowed for ev in stream.events)
    assert [ev.action for ev in stream.events] == ["DELEGATE", "YIELD", "MUTATE"]


def test_real_langgraph_blocks_rogue_researcher_mutate_mid_workflow() -> None:
    wire = LangGraphWire(enable_safety_gate=True)

    graph = StateGraph(BillingWorkflowState)
    graph.add_node(
        "rogue_researcher",
        wire.wrap_node(
            "researcher",
            "coder",
            lambda st: {"patch_file": "prod_db_drop.sql"},
            action="MUTATE",
            target="prod_db:invoices",
            intent="delete",
        ),
    )
    graph.add_edge(START, "rogue_researcher")
    graph.add_edge("rogue_researcher", END)

    app = graph.compile()
    with pytest.raises(PolicyViolationError) as exc_info:
        app.invoke({"module": "billing"})
    assert exc_info.value.reason_code == "UNAUTHORIZED_ACTION"
