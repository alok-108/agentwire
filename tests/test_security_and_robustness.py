"""Adversarial security, replay protection, two-phase budget accounting,
malformed-frame fuzzing, and concurrent session tests for AgentWire v0.2.0.
"""

from __future__ import annotations

import concurrent.futures
import json
import random
import zlib

import pytest

from agentwire import (
    PolicyEngine,
    PolicyViolationError,
    TelemetryStream,
    WireClient,
    decode_frame,
    encode_ast,
    sign_ast,
    verify_frame,
)
from agentwire.telemetry.stream import now_ms

KEY = b"test-hmac-sha256-secret-key-32by"
WRONG_KEY = b"wrong-hmac-sha256-secret-key-32b"


def test_forged_guard_verified_flag_cannot_bypass_receiver_policy() -> None:
    """An attacker setting GUARD_VERIFIED=True on a signed or unsigned frame MUST still
    be rejected independently by the receiver's PolicyEngine.
    """
    receiver_policy = PolicyEngine.strict_authenticated()
    ts = now_ms()
    forged = sign_ast(
        source_agent="researcher",
        target_agent="coder",
        action="MUTATE",
        target="repo:src/auth.py",
        intent="apply_patch",
        signing_key=KEY,
        nonce=1001,
        timestamp_ms=ts,
        guard_verified=True,  # Forged header bit!
    )
    verdict = receiver_policy.evaluate_and_record(forged, signing_key=KEY, now_ms=ts)
    assert verdict["allowed"] is False
    assert verdict["reason_code"] == "UNAUTHORIZED_ACTION"


def test_hmac_authentication_rejects_tampering_wrong_key_and_unsigned() -> None:
    ts = now_ms()
    signed = sign_ast(
        source_agent="planner",
        target_agent="researcher",
        action="DELEGATE",
        target="repo:billing",
        intent="analyze_schema",
        signing_key=KEY,
        nonce=2001,
        timestamp_ms=ts,
        payload={"module": "billing"},
    )

    # Valid verification sets mac_verified=True
    verified = verify_frame(signed, KEY)
    assert verified["header"]["authenticated"] is True
    assert verified["header"]["mac_verified"] is True
    assert verified["header"]["nonce"] == 2001

    # Unverified decode always leaves mac_verified=False
    unverified = decode_frame(signed)
    assert unverified["header"]["mac_verified"] is False

    # Wrong key fails constant-time HMAC check
    with pytest.raises(ValueError, match="HMAC-SHA256 authentication failed"):
        verify_frame(signed, WRONG_KEY)

    # Attacker modifies payload byte AND recomputes CRC32 -> still rejected by HMAC!
    tampered = bytearray(signed)
    tampered[12] ^= 0x55
    crc = zlib.crc32(bytes(tampered[:-4])) & 0xFFFFFFFF
    tampered[-4:] = crc.to_bytes(4, "little")
    with pytest.raises(ValueError, match="HMAC-SHA256 authentication failed"):
        verify_frame(bytes(tampered), KEY)

    # Strict policy rejects unsigned frames
    unsigned = encode_ast(
        source_agent="planner",
        target_agent="researcher",
        action="DELEGATE",
        target="repo:billing",
        intent="analyze_schema",
    )
    strict = PolicyEngine.strict_authenticated()
    verdict = strict.validate_frame(unsigned)
    assert verdict["allowed"] is False
    assert verdict["reason_code"] == "UNAUTHENTICATED_FRAME"


def test_replay_protection_and_clock_skew_window() -> None:
    engine = PolicyEngine.strict_authenticated()
    ts = now_ms()

    frame1 = sign_ast(
        source_agent="planner",
        target_agent="researcher",
        action="DELEGATE",
        target="repo:billing",
        intent="analyze_schema",
        signing_key=KEY,
        nonce=55555,
        timestamp_ms=ts,
        trace_id=10,
        span_id=1,
    )
    assert engine.evaluate_and_record(frame1, signing_key=KEY, now_ms=ts)["allowed"] is True

    # Replaying identical (source_agent, nonce) with a new span_id is blocked
    replay = sign_ast(
        source_agent="planner",
        target_agent="researcher",
        action="DELEGATE",
        target="repo:billing",
        intent="analyze_schema",
        signing_key=KEY,
        nonce=55555,
        timestamp_ms=ts,
        trace_id=10,
        span_id=2,
    )
    replay_res = engine.evaluate_and_record(replay, signing_key=KEY, now_ms=ts)
    assert replay_res["allowed"] is False
    assert replay_res["reason_code"] == "REPLAY_DETECTED"

    # Expired timestamp (> 5 min default skew) is blocked
    stale = sign_ast(
        source_agent="planner",
        target_agent="researcher",
        action="DELEGATE",
        target="repo:billing",
        intent="analyze_schema",
        signing_key=KEY,
        nonce=55556,
        timestamp_ms=ts - 600_000,
        trace_id=10,
        span_id=3,
    )
    stale_res = engine.evaluate_and_record(stale, signing_key=KEY, now_ms=ts)
    assert stale_res["allowed"] is False
    assert stale_res["reason_code"] == "EXPIRED_TIMESTAMP"


def test_two_phase_budget_reserve_settle_and_release() -> None:
    spec = json.loads(PolicyEngine.default_multi_agent().to_json())
    spec["session_max_tokens"] = 3000
    spec["session_max_micro_usd"] = 60_000
    engine = PolicyEngine.from_json(json.dumps(spec))

    f1 = encode_ast(
        source_agent="planner",
        target_agent="researcher",
        action="DELEGATE",
        target="repo:core",
        intent="analyze_schema",
        trace_id=42,
        span_id=1,
        max_tokens=2000,
        max_micro_usd=40_000,
    )
    assert engine.evaluate_and_record(f1)["allowed"] is True
    ledger1 = engine.budget_ledger()
    assert ledger1["reserved_tokens"] == 2000
    assert ledger1["settled_tokens"] == 0
    assert ledger1["remaining_tokens"] == 1000
    assert ledger1["active_reservations"] == 1

    # Settle span 1 with only 350 actual tokens -> 1650 returned to session pool!
    receipt = engine.settle_usage(42, 1, 350, 5_000)
    assert receipt["released_tokens"] == 1650
    assert receipt["released_micro_usd"] == 35_000
    ledger2 = engine.budget_ledger()
    assert ledger2["settled_tokens"] == 350
    assert ledger2["reserved_tokens"] == 0
    assert ledger2["remaining_tokens"] == 2650
    assert ledger2["active_reservations"] == 0

    # Reserve span 2 (2000 tokens), then cancel/release -> 100% refunded back to 2650!
    f2 = encode_ast(
        source_agent="planner",
        target_agent="coder",
        action="DELEGATE",
        target="repo:core",
        intent="implement",
        trace_id=42,
        span_id=2,
        max_tokens=2000,
        max_micro_usd=30_000,
    )
    assert engine.evaluate_and_record(f2)["allowed"] is True
    assert engine.budget_ledger()["remaining_tokens"] == 650

    refunded = engine.release_reservation(42, 2)
    assert refunded["reserved_tokens"] == 2000
    assert engine.budget_ledger()["remaining_tokens"] == 2650


def test_malformed_frame_fuzz_never_panics_across_ffi() -> None:
    """Feed 500 randomized, mutated, and truncated buffers across the Rust PyO3 boundary."""
    rng = random.Random(108)
    valid = bytearray(
        sign_ast(
            source_agent="planner",
            target_agent="coder",
            action="DELEGATE",
            target="repo:billing",
            intent="apply_patch",
            signing_key=KEY,
            nonce=999,
            timestamp_ms=now_ms(),
            payload={"file": "ledger.py", "tests": 12},
        )
    )

    for i in range(500):
        mode = i % 4
        if mode == 0:
            # Completely random bytes
            sample = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 256)))
        elif mode == 1:
            # Valid AW01 magic + random payload + valid CRC32 (forces deep parser fuzzing!)
            body = bytearray(b"AW01\x01")
            body.extend(rng.getrandbits(8) for _ in range(rng.randint(1, 128)))
            crc = zlib.crc32(bytes(body)) & 0xFFFFFFFF
            body.extend(crc.to_bytes(4, "little"))
            sample = bytes(body)
        elif mode == 2:
            # Random truncation of a valid signed frame
            cut = rng.randint(0, len(valid) - 1)
            sample = bytes(valid[:cut])
        else:
            # Random byte mutation of a valid signed frame
            mut = bytearray(valid)
            pos = rng.randint(0, len(mut) - 1)
            mut[pos] ^= rng.randint(1, 255)
            sample = bytes(mut)

        for fn in (decode_frame, lambda b: verify_frame(b, KEY)):
            try:
                fn(sample)
            except ValueError:
                pass  # Expected clean error; must never panic or segfault!


def test_concurrent_multithreaded_session_accounting() -> None:
    """Verify thread safety and exact deterministic budget accounting under 8 concurrent threads."""
    spec = json.loads(PolicyEngine.strict_authenticated().to_json())
    spec["session_max_tokens"] = 1_000_000
    spec["session_max_micro_usd"] = 100_000_000
    spec["max_identical_hops_per_trace"] = 0  # Disable cycle cap for stress test
    engine = PolicyEngine.from_json(json.dumps(spec))
    stream = TelemetryStream()
    client = WireClient(
        policy=engine,
        telemetry=stream,
        signing_key=KEY,
        enable_safety_gate=True,
        raise_on_reject=True,
    )

    def worker(idx: int) -> None:
        res = client.send(
            source_agent="planner",
            target_agent="researcher",
            action="DELEGATE",
            target=f"repo:mod_{idx % 10}",
            intent="analyze_schema",
            payload={"id": idx},
            trace_id=5000 + idx,
            max_tokens=500,
            max_micro_usd=2_000,
        )
        assert res.allowed is True
        client.settle_usage(res.event.trace_id, res.event.span_id, 100, 500)

    total_calls = 160
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(worker, i) for i in range(total_calls)]
        for fut in futures:
            fut.result()

    ledger = engine.budget_ledger()
    assert ledger["evaluated_frames"] == total_calls
    assert ledger["rejected_frames"] == 0
    assert ledger["active_reservations"] == 0
    assert ledger["reserved_tokens"] == 0
    assert ledger["settled_tokens"] == total_calls * 100
    assert ledger["settled_micro_usd"] == total_calls * 500
    assert len(stream.events) == total_calls
