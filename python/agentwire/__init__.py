"""AgentWire (`swarmwire`) — Compact, cryptographically verifiable binary wire protocol
and deterministic policy runtime for multi-agent AI systems.
"""

from __future__ import annotations

from agentwire._agentwire import (
    PolicyEngine,
    decompile_ast_dict,
    decompile_frame,
    decode_frame,
    encode_ast,
    generate_ed25519_keypair,
    protocol_info,
    sign_ast,
    sign_ast_ed25519,
    validate_frame,
    verify_frame,
    verify_frame_ed25519,
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
from agentwire.state import SqliteStateStore, StateStore
from agentwire.telemetry.stream import TelemetryStream, TraceEvent
from agentwire.transport import (
    AgentWireRpcClient,
    AgentWireRpcServer,
    IndependentTokenMeter,
    RpcResponse,
    RpcTransportError,
    UsageMeasurement,
    UsageMeter,
)

__all__ = [
    "AgentWireRpcClient",
    "AgentWireRpcServer",
    "CrewAIWire",
    "IndependentTokenMeter",
    "LangGraphWire",
    "PolicyEngine",
    "PolicyViolationError",
    "RpcResponse",
    "RpcTransportError",
    "SqliteStateStore",
    "StateStore",
    "TelemetryStream",
    "TokenEstimator",
    "TraceEvent",
    "UsageMeasurement",
    "UsageMeter",
    "WireClient",
    "WireMetrics",
    "WireReceiveResult",
    "WireSendResult",
    "decompile_ast_dict",
    "decompile_frame",
    "decode_frame",
    "encode_ast",
    "generate_ed25519_keypair",
    "protocol_info",
    "sign_ast",
    "sign_ast_ed25519",
    "validate_frame",
    "verify_frame",
    "verify_frame_ed25519",
]

__version__ = "0.4.0"
