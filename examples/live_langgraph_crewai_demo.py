"""End-to-end live telemetry demo showcasing LangGraphWire + CrewAIWire streaming
real binary AW01 frames over Server-Sent Events (SSE) to the AgentWire Dashboard.

Usage:
    # 1. Start the dashboard in one terminal:
    cd dashboard && npm run dev

    # 2. Run this demo in another terminal:
    .venv/Scripts/python.exe examples/live_langgraph_crewai_demo.py

    # 3. Click "Connect SSE" in http://localhost:5173 (default http://127.0.0.1:8765/api/stream)
"""

from __future__ import annotations

import argparse
import time

from agentwire import (
    CrewAIWire,
    LangGraphWire,
    PolicyEngine,
    PolicyViolationError,
    TelemetryStream,
)


def run_demo(port: int, delay_s: float, keep_alive_s: float) -> None:
    stream = TelemetryStream()
    url = stream.start_http_server(host="127.0.0.1", port=port)
    print(f"[AgentWire] Live TelemetryStream SSE server listening at {url}/api/stream")

    policy = PolicyEngine.default_multi_agent()
    lg = LangGraphWire(policy=policy, telemetry=stream, enable_safety_gate=True)
    crew = CrewAIWire(policy=policy, telemetry=stream, enable_safety_gate=True)

    # Register a CrewAI role handler for researcher -> coder handoff
    crew.register_role(
        "coder",
        lambda payload, trace: {
            "status": "ok",
            "file": "src/billing/ledger.py",
            "summary": f"prepared patch for {payload.get('table', 'unknown')}",
        },
    )

    # Define a LangGraph-style planner node wrapped with LangGraphWire
    def planner_node(state: dict) -> dict:
        return {
            "module": state["module"],
            "table": "invoices",
            "depth": 2,
            "priority": "high",
            "strict": True,
        }

    wrapped_planner = lg.wrap_node(
        source_agent="planner",
        target_agent="researcher",
        fn=planner_node,
        action="DELEGATE",
        target="repo:billing",
        intent="analyze_schema",
        max_tokens=1200,
        max_micro_usd=15_000,
    )

    # Step 1 (LangGraphWire): planner -> researcher
    print("[1/5] LangGraphWire: planner -> researcher (DELEGATE repo:billing::analyze_schema)")
    out_lg = wrapped_planner({"module": "billing"})
    decoded_state, _ = lg.deserialize_state_update(out_lg["_agentwire_frame"])
    time.sleep(delay_s)

    # Step 2 (CrewAIWire): researcher -> coder
    print("[2/5] CrewAIWire:    researcher -> coder (YIELD agent:coder::yield_result)")
    crew.dispatch_task(
        from_role="researcher",
        to_role="coder",
        action="YIELD",
        target="agent:coder",
        intent="yield_result",
        task_payload={
            "status": "ok",
            "table": decoded_state["table"],
            "files": ["src/billing/ledger.py", "src/billing/tax.py"],
            "confidence": 0.97,
        },
        refs=["mem:schema_invoices_v2"],
        max_tokens=1500,
        max_micro_usd=20_000,
    )
    time.sleep(delay_s)

    # Step 3 (LangGraphWire): coder -> reviewer (authorized repo mutation)
    print("[3/5] LangGraphWire: coder -> reviewer (MUTATE repo:src/billing/ledger.py::apply_patch)")
    lg.serialize_state_update(
        source_agent="coder",
        target_agent="reviewer",
        action="MUTATE",
        target="repo:src/billing/ledger.py",
        intent="apply_patch",
        state_delta={
            "file": "src/billing/ledger.py",
            "language": "python",
            "tests": 24,
            "passed": True,
            "idempotency_key": "patch-418-live",
        },
        refs=["mem:diff_8821"],
        max_tokens=2048,
        max_micro_usd=35_000,
    )
    time.sleep(delay_s)

    # Step 4 (CrewAIWire): reviewer -> planner (verification assertion)
    print("[4/5] CrewAIWire:    reviewer -> planner (ASSERT tests:billing_suite::verify_tests)")
    crew.dispatch_task(
        from_role="reviewer",
        to_role="planner",
        action="ASSERT",
        target="tests:billing_suite",
        intent="verify_tests",
        task_payload={
            "approved": True,
            "passed": True,
            "score": 0.99,
            "severity": "low",
        },
        refs=["mem:diff_8821", "ctx://ci/run-991"],
        max_tokens=800,
        max_micro_usd=10_000,
    )
    time.sleep(delay_s)

    # Step 5 (Guard-Gate Block): read-only researcher attempts unauthorized DB MUTATE
    print("[5/5] Guard-Gate:    researcher -> coder (MUTATE prod_db:invoices::delete) [EXPECT BLOCK]")
    try:
        crew.dispatch_task(
            from_role="researcher",
            to_role="coder",
            action="MUTATE",
            target="prod_db:invoices",
            intent="delete",
            task_payload={"table": "invoices", "id": 9901},
            refs=["ctx://issue/418"],
        )
    except PolicyViolationError as exc:
        print(f"      -> Blocked locally before LLM call: [{exc.reason_code}] {exc.detail}")

    summary = stream.summary()
    print(
        f"\n[AgentWire] Live session summary: {summary['allowed_frames']} allowed / "
        f"{summary['rejected_frames']} blocked | "
        f"Byte reduction: {summary['byte_reduction_pct']}% | "
        f"Token reduction: {summary['token_reduction_pct']}% | "
        f"Avg Rust pipeline: {summary['avg_pipeline_us']} us"
    )
    if keep_alive_s <= 0:
        print(f"[AgentWire] SSE server running indefinitely at {url}/api/stream (Ctrl+C to stop)...", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            stream.stop_http_server()
    else:
        print(f"[AgentWire] Keeping SSE server alive for {keep_alive_s:.0f}s at {url}/api/stream ...", flush=True)
        try:
            time.sleep(keep_alive_s)
        except KeyboardInterrupt:
            pass
        finally:
            stream.stop_http_server()


def main() -> None:
    parser = argparse.ArgumentParser(description="Live LangGraph + CrewAI AgentWire SSE demo")
    parser.add_argument("--port", type=int, default=8765, help="SSE HTTP server port (default: 8765)")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="Delay in seconds between emitted hops (default: 0.15)",
    )
    parser.add_argument(
        "--keep-alive",
        type=float,
        default=60.0,
        help="Seconds to keep SSE server open for dashboard inspection (default: 60)",
    )
    args = parser.parse_args()
    run_demo(port=args.port, delay_s=args.delay, keep_alive_s=args.keep_alive)


if __name__ == "__main__":
    main()
