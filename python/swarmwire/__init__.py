"""SwarmWire — Top-level import alias for AgentWire (`pip install swarmwire`).

Supports both `import swarmwire` and `import agentwire` interchangeably.
"""

from __future__ import annotations

import agentwire as _agentwire_pkg
from agentwire import (
    AgentWireRpcClient,
    AgentWireRpcServer,
    CrewAIWire,
    IndependentTokenMeter,
    LangGraphWire,
    PolicyEngine,
    PolicyViolationError,
    RpcResponse,
    RpcTransportError,
    SqliteStateStore,
    StateStore,
    TelemetryStream,
    TokenEstimator,
    TraceEvent,
    UsageMeasurement,
    UsageMeter,
    WireClient,
    WireMetrics,
    WireReceiveResult,
    WireSendResult,
    __all__,
    __version__,
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

__all__ = list(__all__)
__version__ = _agentwire_pkg.__version__
