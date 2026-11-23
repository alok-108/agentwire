"""Standalone Example: Securing CrewAI Agent Communication with AgentWire Binary TCP Transport.

Demonstrates:
  1. Hosting a remote CrewAI `researcher` role behind `AgentWireRpcServer` with mandatory
     HMAC-SHA256 frame authentication and independent receiver-side `PolicyEngine` RBAC.
  2. Dispatching authorized `DELEGATE` tasks from `planner` -> `researcher` over binary AW01
     TCP frames with automatic two-phase Reserve/Settle budget accounting.
  3. Proving that an unauthorized `MUTATE` from a read-only `researcher` (even with a forged
     `GUARD_VERIFIED` header bit) is blocked locally/remotely in microseconds with zero LLM cost.

Run:
    python examples/crewai_secure_binary_transport.py
"""

from __future__ import annotations

from agentwire import (
    AgentWireRpcClient,
    AgentWireRpcServer,
    CrewAIWire,
    PolicyViolationError,
    sign_ast,
)
from agentwire.telemetry.stream import now_ms

SHARED_HMAC_KEY = b"crewai-agentwire-demo-secret-32b"


def remote_researcher_handler(decoded: dict, summary: dict) -> tuple[dict, int, int]:
    """Executed on the remote CrewAI worker process ONLY after HMAC + PolicyEngine pass."""
    module = decoded["body"]["payload"].get("module", "unknown")
    print(f"  [Remote Worker] Verified AST: {summary['canonical_ast']}")
    result = {
        "module": module,
        "status": "ok",
        "findings": [
            "invoices.amount_minor BIGINT NOT NULL",
            "invoices.currency CHAR(3) NOT NULL",
        ],
    }
    # Report actual downstream usage: 210 tokens, 1,100 micro-USD ($0.0011)
    return (result, 210, 1_100)


def main() -> None:
    with AgentWireRpcServer(signing_key=SHARED_HMAC_KEY) as rpc_server:
        rpc_server.register_handler("researcher", remote_researcher_handler)
        host, port = rpc_server.address
        print(f"[Server] AgentWire authenticated TCP RPC listening on {host}:{port}")

        # 1. Authorized CrewAI delegation over binary AW01 TCP transport
        crew = CrewAIWire(signing_key=SHARED_HMAC_KEY, enable_safety_gate=True)
        crew.register_remote_role("researcher", host, port)

        out = crew.dispatch_task(
            from_role="planner",
            to_role="researcher",
            action="DELEGATE",
            target="repo:billing",
            intent="analyze_schema",
            task_payload={"module": "invoices", "depth": 2},
            refs=["ctx://issue/418"],
            max_tokens=1500,
            max_micro_usd=25_000,
        )
        print(f"[Client] Authorized dispatch ok={out['response']['ok']} | "
              f"wire={len(out['frame_bytes'])} B | "
              f"settled={out['response']['settled_tokens']} tok "
              f"(released {out['response']['released_tokens']} unused tok)")
        print(f"[Client] Findings: {out['response']['result']['findings']}")

        # 2. Rogue read-only researcher attempting MUTATE (even with forged GUARD_VERIFIED flag)
        raw_client = AgentWireRpcClient(host, port, signing_key=SHARED_HMAC_KEY)
        forged_mutate = sign_ast(
            source_agent="researcher",
            target_agent="researcher",
            action="MUTATE",
            target="prod_db:invoices",
            intent="delete",
            signing_key=SHARED_HMAC_KEY,
            nonce=990042,
            timestamp_ms=now_ms(),
            trace_id=202,
            span_id=1,
            guard_verified=True,
        )
        blocked = raw_client.send_raw(forged_mutate)
        print(
            f"[Guard-Gate] Forged MUTATE blocked independently on receiver: "
            f"ok={blocked.ok} reason={blocked.reason_code} ({blocked.detail})"
        )

        # 3. Local sender-side CrewAI guard-gate check before hitting network
        try:
            crew.dispatch_task(
                from_role="researcher",
                to_role="researcher",
                action="MUTATE",
                target="prod_db:invoices",
                intent="delete",
            )
        except PolicyViolationError as exc:
            print(f"[Guard-Gate] Local sender guard-gate blocked pre-flight: {exc.reason_code}")


if __name__ == "__main__":
    main()
