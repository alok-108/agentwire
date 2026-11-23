"""SwarmWire — Top-level import alias for AgentWire (`pip install swarmwire`).

Supports both `import swarmwire` and `import agentwire` interchangeably.
"""

from __future__ import annotations

import agentwire as _agentwire_pkg
from agentwire import (
    AgentWireRpcClient,
    AgentWireRpcServer,
    CrewAIWire,
    LangGraphWire,
    PolicyEngine,
    PolicyViolationError,
    RpcResponse,
    RpcTransportError,
    TelemetryStream,
    TokenEstimator,
    TraceEvent,
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
    protocol_info,
    sign_ast,
    validate_frame,
    verify_frame,
)

__all__ = list(__all__)
__version__ = _agentwire_pkg.__version__
