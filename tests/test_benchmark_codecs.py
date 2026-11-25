"""Optional benchmark formats preserve the logical frame used for comparison."""
from pathlib import Path
import sys

import pytest

from benchmarks.comparison_codecs import optional_codecs
from benchmarks.token_latency_bench import build_workflow_hops, hop_to_equivalent_ast_struct


def frame():
    hop = build_workflow_hops(1001)[0]
    result = hop_to_equivalent_ast_struct(hop, trace_id=2**63 + 1, span_id=7)
    result["payload"] = {"nested": [None, False, -(2**62 + 1), 2.5, "Δ", {}, [], {"$ref": "ctx://x"}]}
    return result


def test_messagepack_round_trip():
    pytest.importorskip("msgpack")
    encode, decode = optional_codecs()["MessagePack"]
    source = frame()
    assert decode(encode(source)) == source


def test_protobuf_round_trip():
    pytest.importorskip("google.protobuf")
    encode, decode = optional_codecs()["Protobuf"]
    source = frame()
    parsed = decode(encode(source))
    for field in source.keys() - {"payload", "action"}:
        assert getattr(parsed, field) == source[field]
    actions = parsed.DESCRIPTOR.fields_by_name["action"].enum_type
    assert actions.values_by_number[parsed.action].name == source["action"]
    values = parsed.payload["nested"].sequence.values
    assert [v.WhichOneof("kind") for v in values] == [
        "null_value", "boolean", "integer", "floating", "text", "mapping", "sequence", "ref",
    ]
    assert not values[1].boolean
    assert values[2].integer == -(2**62 + 1)
    assert values[3].floating == 2.5
    assert values[4].text == "Δ"
    assert values[7].ref == "ctx://x"


def test_missing_optional_codecs(monkeypatch):
    monkeypatch.setitem(sys.modules, "msgpack", None)
    monkeypatch.setitem(sys.modules, "google.protobuf", None)
    assert optional_codecs() == {}


def test_descriptor_matches_schema(tmp_path):
    protoc = pytest.importorskip("grpc_tools.protoc")
    directory = Path(__file__).resolve().parents[1] / "benchmarks"
    result = tmp_path / "compiled.desc"
    assert protoc.main(["protoc", f"-I{directory}", f"--descriptor_set_out={result}",
                        str(directory / "wire_frame.proto")]) == 0
    assert result.read_bytes() == (directory / "wire_frame.desc").read_bytes()
