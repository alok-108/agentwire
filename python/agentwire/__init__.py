"""AgentWire — Compact, cryptographically verifiable binary wire protocol and deterministic
policy runtime for multi-agent AI systems.
"""

from __future__ import annotations

from agentwire._agentwire import (
    PolicyEngine,
    decompile_ast_dict,
    decompile_frame,
    decode_frame,
    encode_ast,
    protocol_info,
    sign_ast,
    validate_frame,
    verify_frame,
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
from agentwire.transport import (
    AgentWireRpcClient,
    AgentWireRpcServer,
    RpcResponse,
    RpcTransportError,
)

__all__ = [
    "AgentWireRpcClient",
    "AgentWireRpcServer",
    "CrewAIWire",
    "LangGraphWire",
    "PolicyEngine",
    "PolicyViolationError",
    "RpcResponse",
    "RpcTransportError",
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
    "sign_ast",
    "validate_frame",
    "verify_frame",
]

__version__ = "0.3.1"
