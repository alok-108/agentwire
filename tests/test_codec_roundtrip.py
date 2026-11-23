"""Unit tests covering AgentWire binary codec round-trips, dictionary compression,
lossless AST decompilation, and corruption/CRC32 rejection.
"""

from __future__ import annotations

import json
import pytest

import agentwire
from agentwire import (
    decompile_ast_dict,
    decompile_frame,
    decode_frame,
    encode_ast,
    protocol_info,
)


def test_protocol_metadata() -> None:
    info = protocol_info()
    assert info["magic"] == "AW01"
    assert info["version"] == 1
    assert 50 <= info["static_dict_size"] <= 127


@pytest.mark.parametrize("action", ["QUERY", "MUTATE", "DELEGATE", "YIELD", "ASSERT"])
def test_roundtrip_all_actions(action: str) -> None:
    raw = encode_ast(
        source_agent="planner",
        target_agent="researcher",
        action=action,
        target="postgres.users",
        intent="fetch_delta",
        payload={"user_id": 123, "strict": True},
        refs=["ctx://session/42"],
        trace_id=9001,
        span_id=3,
        hop_depth=1,
        max_tokens=1024,
        max_micro_usd=25_000,
    )
    assert raw[:4] == b"AW01"

    decoded = decode_frame(raw)
    assert decoded["header"]["version"] == 1
    assert decoded["header"]["trace_id"] == 9001
    assert decoded["header"]["span_id"] == 3
    assert decoded["header"]["hop_depth"] == 1
    assert decoded["header"]["source_agent"] == "planner"
    assert decoded["header"]["target_agent"] == "researcher"
    assert decoded["header"]["max_tokens"] == 1024
    assert decoded["header"]["max_micro_usd"] == 25_000
    assert decoded["body"]["action"] == action
    assert decoded["body"]["target"] == "postgres.users"
    assert decoded["body"]["intent"] == "fetch_delta"
    assert decoded["body"]["payload"] == {"user_id": 123, "strict": True}
    assert decoded["body"]["refs"] == ["ctx://session/42"]


def test_roundtrip_all_typed_ast_values() -> None:
    long_text = "agentwire-unicode-payload-🚀-" + ("a" * 180)
    payload = {
        "null_val": None,
        "flag_true": True,
        "flag_false": False,
        "neg_int": -987_654_321,
        "pos_int": 2**40,
        "confidence": 0.9925,
        "summary": "ok",
        "long_note": long_text,
        "files": ["src/auth.rs", "tests/auth_test.rs", 42, True],
        "metadata": {
            "severity": "high",
            "context_ref": {"$ref": "mem:audit_snapshot_7"},
            "nested_scores": [0.1, 0.5, 0.99],
        },
    }

    raw = encode_ast(
        source_agent="coder",
        target_agent="reviewer",
        action="YIELD",
        target="repo:src/auth.rs",
        intent="yield_result",
        payload=payload,
        refs=["mem:diff_88", "ctx://pr/108"],
        trace_id=42,
        span_id=19,
        hop_depth=3,
        guard_verified=True,
    )

    decoded = decode_frame(raw)
    assert decoded["header"]["guard_verified"] is True
    assert decoded["body"]["payload"] == payload
    assert decoded["body"]["refs"] == ["mem:diff_88", "ctx://pr/108"]


def test_dictionary_compression_beats_compact_json() -> None:
    payload = {
        "user_id": 12345,
        "status": "ok",
        "priority": "high",
        "module": "postgres",
        "language": "rust",
        "passed": True,
        "strict": True,
        "limit": 50,
    }
    raw = encode_ast(
        source_agent="planner",
        target_agent="researcher",
        action="QUERY",
        target="postgres",
        intent="fetch_delta",
        payload=payload,
    )
    compact_json = json.dumps(
        {
            "version": 1,
            "trace_id": 1,
            "span_id": 1,
            "hop_depth": 0,
            "source_agent": "planner",
            "target_agent": "researcher",
            "action": "QUERY",
            "target": "postgres",
            "intent": "fetch_delta",
            "payload": payload,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    # Binary frame with 1-byte static dictionary tokens must be dramatically smaller than even compact JSON
    assert len(raw) < len(compact_json) * 0.45


def test_lossless_decompilation_accuracy() -> None:
    raw = encode_ast(
        source_agent="planner",
        target_agent="coder",
        action="DELEGATE",
        target="repo:billing",
        intent="apply_patch",
        payload={
            "file": "src/invoice.py",
            "dry_run": False,
            "context": {"$ref": "ctx://issue/77"},
        },
        refs=["mem:schema_v4"],
        trace_id=505,
        span_id=11,
        hop_depth=2,
        max_tokens=1500,
        max_micro_usd=20_000,
        guard_verified=True,
    )

    summary = decompile_frame(raw)
    assert summary["trace_id"] == 505
    assert summary["span_id"] == 11
    assert summary["hop_depth"] == 2
    assert summary["guard_verified"] is True
    assert summary["action"] == "DELEGATE"
    assert "planner -> coder" in summary["human_readable"]
    assert "apply_patch" in summary["human_readable"]
    assert "@ctx://issue/77" in summary["canonical_ast"]
    assert "refs=[@mem:schema_v4]" in summary["canonical_ast"]

    direct_ast = decompile_ast_dict(
        action="DELEGATE",
        target="repo:billing",
        intent="apply_patch",
        payload={
            "file": "src/invoice.py",
            "dry_run": False,
            "context": {"$ref": "ctx://issue/77"},
        },
        refs=["mem:schema_v4"],
    )
    assert summary["canonical_ast"] == direct_ast


def test_corrupted_frame_rejections() -> None:
    raw = bytearray(
        encode_ast(
            source_agent="planner",
            target_agent="researcher",
            action="QUERY",
            target="docs:api",
            intent="search_docs",
            payload={"query": "rate_limits", "limit": 5},
        )
    )

    # 1. Flip a single bit in the middle -> CRC32 mismatch
    corrupted = bytearray(raw)
    corrupted[len(corrupted) // 2] ^= 0x04
    with pytest.raises(ValueError, match="CRC32 checksum mismatch"):
        decode_frame(bytes(corrupted))

    # 2. Bad magic bytes
    bad_magic = bytearray(raw)
    bad_magic[0:4] = b"NOPE"
    with pytest.raises(ValueError, match="invalid magic bytes"):
        decode_frame(bytes(bad_magic))

    # 3. Truncated buffer
    with pytest.raises(ValueError):
        decode_frame(bytes(raw[:6]))

    # 4. Trailing garbage bytes
    with pytest.raises(ValueError, match="CRC32 checksum mismatch"):
        decode_frame(bytes(raw) + b"\x00")

    # 5. Invalid action name at encode time
    with pytest.raises(ValueError, match="invalid AgentAction"):
        encode_ast("planner", "coder", "DROP_TABLE", "postgres", "boom")
