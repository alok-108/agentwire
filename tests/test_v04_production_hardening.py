"""v0.4.0 production-hardening test suite verifying all 6 security & distributed-systems properties:
1. Native TLS encryption on TCP transport (and rejection of plaintext clients).
2. Per-agent asymmetric Ed25519 identity (compromised peer cannot impersonate another agent).
3. Idempotent retry semantics (timeout retry returns cached response without double-executing).
4. Independent server-side usage metering floor (handlers cannot zero-out usage to evade budgets).
5. Persistent cross-restart & multi-instance replay + idempotency store (SQLite WAL).
"""

from __future__ import annotations

import shutil
import ssl
import subprocess
import time
from pathlib import Path

import pytest

import swarmwire
from swarmwire import (
    AgentWireRpcClient,
    AgentWireRpcServer,
    IndependentTokenMeter,
    RpcTransportError,
    SqliteStateStore,
    generate_ed25519_keypair,
    sign_ast_ed25519,
    verify_frame_ed25519,
)
from agentwire.telemetry.stream import now_ms


def _generate_self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    """Generate a localhost self-signed X.509 certificate + key for real TLS testing."""
    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"

    openssl_bin = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    if not Path(openssl_bin).exists() and shutil.which(openssl_bin) is None:
        pytest.skip("openssl binary not available to generate ephemeral test certificate")

    subprocess.run(
        [
            openssl_bin,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path


def test_ed25519_per_agent_identity_prevents_impersonation_over_tcp() -> None:
    planner_priv, planner_pub = generate_ed25519_keypair()
    researcher_priv, researcher_pub = generate_ed25519_keypair()
    coder_priv, coder_pub = generate_ed25519_keypair()
    server_priv, server_pub = generate_ed25519_keypair()

    server_registry = {
        "planner": planner_pub,
        "researcher": researcher_pub,
        "coder": coder_pub,
    }
    client_server_keys = {"coder": server_pub, "rpc_server": server_pub}

    handler_calls = 0

    def coder_handler(dec: dict, summary: dict) -> tuple[dict, int, int]:
        nonlocal handler_calls
        handler_calls += 1
        return ({"patched": dec["body"]["payload"]["file"]}, 150, 800)

    with AgentWireRpcServer(
        public_keys=server_registry,
        server_private_key=server_priv,
    ) as server:
        server.register_handler("coder", coder_handler)
        host, port = server.address

        # 1. Legitimate planner signed with planner's private key -> SUCCEEDS
        planner_client = AgentWireRpcClient(
            host,
            port,
            private_key=planner_priv,
            server_public_keys=client_server_keys,
        )
        ok_resp = planner_client.call(
            source_agent="planner",
            target_agent="coder",
            action="DELEGATE",
            target="repo:src/auth.py",
            intent="apply_patch",
            payload={"file": "src/auth.py"},
        )
        assert ok_resp.ok is True
        assert ok_resp.payload["result"] == {"patched": "src/auth.py"}
        assert handler_calls == 1

        # 2. Compromised researcher tries to IMPERSONATE `coder` (signing with researcher's private key!)
        forged_as_coder = sign_ast_ed25519(
            source_agent="coder",
            target_agent="coder",
            action="MUTATE",
            target="repo:src/auth.py",
            intent="apply_patch",
            private_key=researcher_priv,  # Wrong identity key!
            nonce=77001,
            timestamp_ms=now_ms(),
            payload={"file": "src/auth.py"},
        )
        # Direct verification also rejects it
        with pytest.raises(ValueError, match="authentication failed"):
            verify_frame_ed25519(forged_as_coder, server_registry)

        impersonation_resp = planner_client.send_raw(forged_as_coder)
        assert impersonation_resp.ok is False
        assert impersonation_resp.reason_code == "AUTHENTICATION_OR_DECODE_FAILED"
        assert handler_calls == 1  # Handler NEVER invoked!


def test_tls_encrypted_tcp_rpc_and_plaintext_rejection(tmp_path: Path) -> None:
    cert_path, key_path = _generate_self_signed_cert(tmp_path)
    planner_priv, planner_pub = generate_ed25519_keypair()
    server_priv, server_pub = generate_ed25519_keypair()

    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    server_ssl.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    client_ssl = ssl.create_default_context(cafile=str(cert_path))
    client_ssl.minimum_version = ssl.TLSVersion.TLSv1_2

    with AgentWireRpcServer(
        public_keys={"planner": planner_pub},
        server_private_key=server_priv,
        ssl_context=server_ssl,
    ) as server:
        server.register_handler(
            "researcher",
            lambda dec, _sum: ({"encrypted_ok": True, "module": dec["body"]["payload"]["module"]}, 100, 500),
        )
        host, port = server.address

        # TLS client succeeds cleanly with encrypted transport + Ed25519 identity
        tls_client = AgentWireRpcClient(
            host,
            port,
            private_key=planner_priv,
            server_public_keys={"researcher": server_pub, "rpc_server": server_pub},
            ssl_context=client_ssl,
            server_hostname="127.0.0.1",
        )
        resp = tls_client.call(
            source_agent="planner",
            target_agent="researcher",
            action="DELEGATE",
            target="repo:billing",
            intent="analyze_schema",
            payload={"module": "invoices"},
        )
        assert resp.ok is True
        assert resp.payload["result"] == {"encrypted_ok": True, "module": "invoices"}

        # Plaintext (non-TLS) client is rejected by the TLS server
        plain_client = AgentWireRpcClient(
            host,
            port,
            private_key=planner_priv,
            server_public_keys={"researcher": server_pub, "rpc_server": server_pub},
            ssl_context=None,
            timeout_s=0.5,
            max_retries=0,
        )
        with pytest.raises(RpcTransportError):
            plain_client.call(
                source_agent="planner",
                target_agent="researcher",
                action="DELEGATE",
                target="repo:billing",
                intent="analyze_schema",
                payload={"module": "invoices"},
            )


def test_idempotent_retry_deduplicates_slow_mutate_after_client_timeout(tmp_path: Path) -> None:
    """Simulate a slow MUTATE that finishes on the server just after attempt 1 times out on the client.
    Attempt 2 retries with the same idempotency_key + fresh nonce -> handler executes ONLY ONCE!
    """
    coder_priv, coder_pub = generate_ed25519_keypair()
    server_priv, server_pub = generate_ed25519_keypair()
    store = SqliteStateStore(tmp_path / "idem.sqlite3")
    executions = 0

    def slow_mutate_handler(dec: dict, summary: dict) -> tuple[dict, int, int]:
        nonlocal executions
        executions += 1
        time.sleep(0.25)  # Longer than client's initial timeout (0.12s), finishes before retry!
        return ({"applied_patch": dec["body"]["payload"]["file"], "run": executions}, 200, 1_000)

    try:
        with AgentWireRpcServer(
            public_keys={"coder": coder_pub},
            server_private_key=server_priv,
            state_store=store,
        ) as server:
            server.register_handler("reviewer", slow_mutate_handler)
            host, port = server.address

            # Attempt 1 times out at 0.12s while server is still finishing slow_mutate_handler (0.25s)
            short_timeout_client = AgentWireRpcClient(
                host,
                port,
                private_key=coder_priv,
                server_public_keys={"reviewer": server_pub, "rpc_server": server_pub},
                timeout_s=0.12,
                max_retries=0,
            )
            with pytest.raises(RpcTransportError):
                short_timeout_client.call(
                    source_agent="coder",
                    target_agent="reviewer",
                    action="MUTATE",
                    target="repo:src/ledger.py",
                    intent="apply_patch",
                    payload={"file": "src/ledger.py"},
                    idempotency_key="patch-idem-9001",
                )

            # Wait for attempt 1 to complete on server and persist its idempotent result
            time.sleep(0.30)
            assert executions == 1

            # Client retries with same idempotency_key (and fresh transport nonce) -> cached reply!
            retry_client = AgentWireRpcClient(
                host,
                port,
                private_key=coder_priv,
                server_public_keys={"reviewer": server_pub, "rpc_server": server_pub},
                timeout_s=2.0,
            )
            retry_resp = retry_client.call(
                source_agent="coder",
                target_agent="reviewer",
                action="MUTATE",
                target="repo:src/ledger.py",
                intent="apply_patch",
                payload={"file": "src/ledger.py"},
                idempotency_key="patch-idem-9001",
            )
            assert retry_resp.ok is True
            assert retry_resp.deduplicated is True
            assert retry_resp.payload["result"] == {"applied_patch": "src/ledger.py", "run": 1}
            assert executions == 1  # ZERO duplicate mutation!
    finally:
        store.close()


def test_independent_usage_meter_prevents_handler_zero_reporting() -> None:
    """A handler attempting to report (0 tokens, 0 micro-USD) is overridden by the
    server's IndependentTokenMeter floor so session budgets cannot be evaded.
    """
    planner_priv, planner_pub = generate_ed25519_keypair()
    server_priv, server_pub = generate_ed25519_keypair()

    def underreporting_handler(dec: dict, summary: dict) -> tuple[dict, int, int]:
        # Dishonestly claims 0 tokens / 0 cost while returning a substantial payload
        return (
            {
                "analysis": "Detailed schema audit across invoices, customers, and tax_rates tables.",
                "columns": ["id", "amount_minor", "currency", "created_at", "updated_at"],
            },
            0,
            0,
        )

    meter = IndependentTokenMeter(micro_usd_per_1k_tokens=3_000)
    with AgentWireRpcServer(
        public_keys={"planner": planner_pub},
        server_private_key=server_priv,
        usage_meter=meter,
    ) as server:
        server.register_handler("researcher", underreporting_handler)
        host, port = server.address

        client = AgentWireRpcClient(
            host,
            port,
            private_key=planner_priv,
            server_public_keys={"researcher": server_pub, "rpc_server": server_pub},
        )
        resp = client.call(
            source_agent="planner",
            target_agent="researcher",
            action="DELEGATE",
            target="repo:billing",
            intent="analyze_schema",
            payload={"module": "invoices"},
            max_tokens=1000,
            max_micro_usd=20_000,
        )
        assert resp.ok is True
        measured_floor = resp.payload["measured_tokens_floor"]
        assert measured_floor >= 25
        assert resp.payload["settled_tokens"] == measured_floor
        assert server.policy.budget_ledger()["settled_tokens"] == measured_floor
        assert server.policy.budget_ledger()["settled_micro_usd"] > 0


def test_sqlite_replay_and_idempotency_persist_across_restarts_and_multiple_servers(
    tmp_path: Path,
) -> None:
    """Verify:
    1. Replaying a frame after Server A restarts is blocked (`REPLAY_DETECTED`).
    2. Replaying Server A's frame against a second concurrent Server B sharing the same
       SQLite WAL store is blocked (`REPLAY_DETECTED`).
    3. Retrying with the same idempotency_key after restart returns cached response with 0 re-execution.
    """
    db_file = tmp_path / "shared_state.sqlite3"
    planner_priv, planner_pub = generate_ed25519_keypair()
    server_priv, server_pub = generate_ed25519_keypair()
    server_pub_map = {"researcher": server_pub, "rpc_server": server_pub}

    captured_signed = sign_ast_ed25519(
        source_agent="planner",
        target_agent="researcher",
        action="DELEGATE",
        target="repo:billing",
        intent="analyze_schema",
        private_key=planner_priv,
        nonce=555_001,
        timestamp_ms=now_ms(),
        payload={"module": "invoices", "idempotency_key": "shared-idem-77"},
        trace_id=801,
        span_id=1,
    )

    # --- Server A processes captured_signed once ---
    store_a = SqliteStateStore(db_file)
    a_calls = 0

    def handler_a(dec: dict, _s: dict) -> tuple[dict, int, int]:
        nonlocal a_calls
        a_calls += 1
        return ({"origin": "server-A", "count": a_calls}, 120, 600)

    try:
        with AgentWireRpcServer(
            public_keys={"planner": planner_pub},
            server_private_key=server_priv,
            state_store=store_a,
        ) as server_a:
            server_a.register_handler("researcher", handler_a)
            host_a, port_a = server_a.address
            client_a = AgentWireRpcClient(
                host_a, port_a, private_key=planner_priv, server_public_keys=server_pub_map
            )
            r1 = client_a.send_raw(captured_signed)
            assert r1.ok is True
            assert r1.payload["result"] == {"origin": "server-A", "count": 1}

            # --- Concurrent Server B sharing the same SQLite WAL DB blocks replay! ---
            store_b = SqliteStateStore(db_file)
            b_calls = 0
            try:
                with AgentWireRpcServer(
                    public_keys={"planner": planner_pub},
                    server_private_key=server_priv,
                    state_store=store_b,
                ) as server_b:
                    server_b.register_handler(
                        "researcher",
                        lambda d, s: ({"origin": "server-B"}, 100, 500),
                    )
                    host_b, port_b = server_b.address
                    client_b = AgentWireRpcClient(
                        host_b, port_b, private_key=planner_priv, server_public_keys=server_pub_map
                    )
                    r_cross = client_b.send_raw(captured_signed)
                    assert r_cross.ok is False
                    assert r_cross.reason_code == "REPLAY_DETECTED"
            finally:
                store_b.close()
    finally:
        store_a.close()

    # --- Server A' (fresh restart with same DB) blocks replay AND deduplicates idempotent retry! ---
    store_restarted = SqliteStateStore(db_file)
    restarted_calls = 0

    def handler_restarted(dec: dict, _s: dict) -> tuple[dict, int, int]:
        nonlocal restarted_calls
        restarted_calls += 1
        return ({"origin": "server-A-restarted"}, 100, 500)

    try:
        with AgentWireRpcServer(
            public_keys={"planner": planner_pub},
            server_private_key=server_priv,
            state_store=store_restarted,
        ) as server_restarted:
            server_restarted.register_handler("researcher", handler_restarted)
            host_r, port_r = server_restarted.address
            client_r = AgentWireRpcClient(
                host_r, port_r, private_key=planner_priv, server_public_keys=server_pub_map
            )

            # 1. Exact replay blocked across restart
            r_replay = client_r.send_raw(captured_signed)
            assert r_replay.ok is False
            assert r_replay.reason_code == "REPLAY_DETECTED"

            # 2. Fresh nonce + same idempotency_key returns persisted Server-A response (0 re-execution!)
            r_idem = client_r.call(
                source_agent="planner",
                target_agent="researcher",
                action="DELEGATE",
                target="repo:billing",
                intent="analyze_schema",
                payload={"module": "invoices"},
                idempotency_key="shared-idem-77",
            )
            assert r_idem.ok is True
            assert r_idem.deduplicated is True
            assert r_idem.payload["result"] == {"origin": "server-A", "count": 1}
            assert restarted_calls == 0
    finally:
        store_restarted.close()
