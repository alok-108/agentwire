"""Optional comparison codecs for the AW01 benchmark."""
from __future__ import annotations

from pathlib import Path
from typing import Any


def protobuf_encoder(frame_type):
    def value(item: Any) -> dict:
        if item is None:
            return {"null_value": True}
        if isinstance(item, bool):
            return {"boolean": item}
        if isinstance(item, int):
            return {"integer": item}
        if isinstance(item, float):
            return {"floating": item}
        if isinstance(item, str):
            return {"text": item}
        if isinstance(item, list):
            return {"sequence": {"values": [value(x) for x in item]}}
        if isinstance(item, dict):
            if set(item) == {"$ref"} and isinstance(item["$ref"], str):
                return {"ref": item["$ref"]}
            return {"mapping": {"fields": {k: value(v) for k, v in item.items()}}}
        raise TypeError(f"unsupported AST value: {type(item)}")

    def encode(frame):
        fields = {**frame, "payload": {k: value(v) for k, v in frame["payload"].items()}}
        return frame_type(**fields).SerializeToString(deterministic=True)

    return encode


def optional_codecs():
    codecs = {}
    try:
        import msgpack
    except ModuleNotFoundError as exc:
        if exc.name != "msgpack":
            raise
    else:
        codecs["MessagePack"] = (msgpack.packb, msgpack.unpackb)

    try:
        from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    except ModuleNotFoundError as exc:
        if exc.name not in {"google", "google.protobuf"}:
            raise
    else:
        schema = Path(__file__).with_name("wire_frame.desc").read_bytes()
        file, = descriptor_pb2.FileDescriptorSet.FromString(schema).file
        descriptor = descriptor_pool.DescriptorPool().Add(file).message_types_by_name["WireFrame"]
        frame = message_factory.GetMessageClass(descriptor)
        codecs["Protobuf"] = (protobuf_encoder(frame), frame.FromString)
    return codecs
