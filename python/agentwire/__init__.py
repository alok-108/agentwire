"""AgentWire — Binary RPC wire protocol and verifiable AST runtime for multi-agent AI systems."""

from __future__ import annotations

from agentwire._agentwire import (
    PolicyEngine,
    decompile_ast_dict,
    decompile_frame,
    decode_frame,
    encode_ast,
    protocol_info,
    validate_frame,
)
from agentwire.adapters.crewai import CrewAIWire
from agentwire.adapters.langgraph import LangGraphWire
from agentwire.client import (
    PolicyViolationError,
    TokenEstimator,
    WireClient,
    WireMetrics,
    WireReceiveResult,
    WireSendResult,
)
from agentwire.telemetry.stream import TelemetryStream, TraceEvent

__all__ = [
    "CrewAIWire",
    "LangGraphWire",
    "PolicyEngine",
    "PolicyViolationError",
    "TelemetryStream",
    "TokenEstimator",
    "TraceEvent",
    "WireClient",
    "WireMetrics",
    "WireReceiveResult",
    "WireSendResult",
    "decompile_ast_dict",
    "decompile_frame",
    "decode_frame",
    "encode_ast",
    "protocol_info",
    "validate_frame",
]

__version__ = "0.1.0"
