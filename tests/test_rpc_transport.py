"""End-to-end networked TCP RPC transport tests for AgentWire v0.2.0.

Verifies cross-socket length-prefixed binary framing, independent receiver-side
HMAC-SHA256 verification & PolicyEngine authorization, replay blocking over TCP,
two-phase budget settlement/refund, retries, and CrewAIWire remote role dispatch.
"""

from __future__ import annotations

import pytest

from agentwire import (
    AgentWireRpcClient,
    AgentWireRpcServer,
    CrewAIWire,
    PolicyEngine,
    RpcTransportError,
    sign_ast,
)
from agentwire.telemetry.stream import now_ms

RPC_KEY = b"agentwire-tcp-rpc-shared-key-32b"
BAD_KEY = b"attacker-wrong-tcp-rpc-key-32byt"


def test_authenticated_tcp_rpc_roundtrip_and_budget_settlement() -> None:
    handler_calls: list[dict] = []

    def researcher_handler(decoded: dict, summary: dict) -> tuple[dict, int, int]:
        handler_calls.append(decoded)
        module = decoded["body"]["payload"]["module"]
        return ({"findings": f"verified schema for {module}", "columns": 12}, 220, 1_200)

    with AgentWireRpcServer(signing_key=RPC_KEY) as server:
        server.register_handler("researcher", researcher_handler)
        host, port = server.address

        client = AgentWireRpcClient(host, port, signing_key=RPC_KEY)
        resp = client.call(
            source_agent="planner",
            target_agent="researcher",
            action="DELEGATE",
            target="repo:billing",
            intent="analyze_schema",
            payload={"module": "invoices", "depth": 2},
            refs=["ctx://issue/418"],
            trace_id=901,
            max_tokens=1500,
            max_micro_usd=25_000,
        )

        assert resp.ok is True
        assert resp.trace_id == 901
        assert resp.payload["result"] == {
            "findings": "verified schema for invoices",
            "columns": 12,
        }
        assert resp.payload["settled_tokens"] == 220
        assert resp.payload["released_tokens"] == 1280
        assert len(handler_calls) == 1

        # Verify server ledger settled actual usage (220 tok) and released unused 1280 tok
        ledger = server.policy.budget_ledger()
        assert ledger["settled_tokens"] == 220
        assert ledger["reserved_tokens"] == 0
        assert ledger["active_reservations"] == 0


def test_receiver_independently_blocks_forged_mutate_wrong_key_and_replay_over_tcp() -> None:
    handler_invoked = False

    def coder_handler(decoded: dict, summary: dict) -> tuple[dict, int, int]:
        nonlocal handler_invoked
        handler_invoked = True
        return ({"applied": True}, 100, 500)

    with AgentWireRpcServer(signing_key=RPC_KEY) as server:
        server.register_handler("coder", coder_handler)
        host, port = server.address
        client = AgentWireRpcClient(host, port, signing_key=RPC_KEY, max_retries=0)

        # 1. Forged GUARD_VERIFIED=True on unauthorized researcher MUTATE -> rejected on server!
        forged_mutate = sign_ast(
            source_agent="researcher",
            target_agent="coder",
            action="MUTATE",
            target="repo:src/ledger.py",
            intent="apply_patch",
            signing_key=RPC_KEY,
            nonce=88001,
            timestamp_ms=now_ms(),
            trace_id=902,
            span_id=1,
            guard_verified=True,
        )
        r1 = client.send_raw(forged_mutate)
        assert r1.ok is False
        assert r1.reason_code == "UNAUTHORIZED_ACTION"
        assert handler_invoked is False

        # 2. Wrong HMAC signing key -> server rejects before policy or handler!
        wrong_key_frame = sign_ast(
            source_agent="planner",
            target_agent="coder",
            action="DELEGATE",
            target="repo:src/ledger.py",
            intent="apply_patch",
            signing_key=BAD_KEY,
            nonce=88002,
            timestamp_ms=now_ms(),
            trace_id=902,
            span_id=2,
        )
        r2 = client.send_raw(wrong_key_frame)
        assert r2.ok is False
        assert r2.reason_code == "AUTHENTICATION_OR_DECODE_FAILED"
        assert handler_invoked is False

        # 3. Valid signed frame succeeds once, then replaying exact bytes over TCP is rejected!
        valid_frame = sign_ast(
            source_agent="planner",
            target_agent="coder",
            action="DELEGATE",
            target="repo:src/ledger.py",
            intent="apply_patch",
            signing_key=RPC_KEY,
            nonce=88003,
            timestamp_ms=now_ms(),
            trace_id=902,
            span_id=3,
        )
        r3_ok = client.send_raw(valid_frame)
        assert r3_ok.ok is True
        assert handler_invoked is True

        r3_replay = client.send_raw(valid_frame)
        assert r3_replay.ok is False
        assert r3_replay.reason_code == "REPLAY_DETECTED"


def test_handler_exception_releases_budget_reservation_and_unreachable_server_retries() -> None:
    def failing_handler(decoded: dict, summary: dict) -> tuple[dict, int, int]:
        raise RuntimeError("downstream tool crashed")

    with AgentWireRpcServer(signing_key=RPC_KEY) as server:
        server.register_handler("researcher", failing_handler)
        host, port = server.address
        before = server.policy.budget_ledger()["remaining_tokens"]

        client = AgentWireRpcClient(host, port, signing_key=RPC_KEY)
        resp = client.call(
            source_agent="planner",
            target_agent="researcher",
            action="DELEGATE",
            target="repo:billing",
            intent="analyze_schema",
            max_tokens=1000,
            max_micro_usd=10_000,
        )
        assert resp.ok is False
        assert resp.reason_code == "HANDLER_EXECUTION_ERROR"
        # 100% of reservation refunded when handler throws
        assert server.policy.budget_ledger()["remaining_tokens"] == before
        assert server.policy.budget_ledger()["active_reservations"] == 0

    # After server stops, client retries and raises RpcTransportError cleanly
    dead_client = AgentWireRpcClient(
        host, port, signing_key=RPC_KEY, timeout_s=0.2, max_retries=1, retry_backoff_s=0.01
    )
    with pytest.raises(RpcTransportError, match="failed after 2 attempt"):
        dead_client.call(
            source_agent="planner",
            target_agent="researcher",
            action="DELEGATE",
            target="repo:billing",
            intent="analyze_schema",
        )


def test_crewai_wire_remote_role_over_tcp() -> None:
    with AgentWireRpcServer(signing_key=RPC_KEY) as server:
        server.register_handler(
            "researcher",
            lambda dec, _sum: (
                {"scanned": dec["body"]["payload"]["module"], "remote_tcp": True},
                180,
                900,
            ),
        )
        host, port = server.address

        crew = CrewAIWire(signing_key=RPC_KEY)
        crew.register_remote_role("researcher", host, port)
        out = crew.dispatch_task(
            from_role="planner",
            to_role="researcher",
            action="DELEGATE",
            target="repo:payments",
            intent="analyze_schema",
            task_payload={"module": "settlement"},
        )
        assert out["allowed"] is True
        assert out["response"]["ok"] is True
        assert out["response"]["result"] == {"scanned": "settlement", "remote_tcp": True}
