# AgentWire (`AW01`)

[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **The binary RPC wire protocol and verifiable AST runtime for multi-agent AI systems.**
> Slash inter-agent payload bytes by **90%**, cut LLM handoff tokens by **83%–87%**, enforce deterministic sub-10µs Rust policy guard-gates before any API call is sent, and stream 100% lossless human-readable decompiled traces to a live dark-mode observer UI.

![AgentWire Live SSE Observability Dashboard](docs/dashboard-live-sse.png)

---

## Why AgentWire?

Multi-agent frameworks (LangGraph, CrewAI, AutoGen, Swarm) pass verbose natural-language system prompts and deeply nested JSON envelopes between agents on every hop. That creates three production bottlenecks:

1. **Exploding LLM token bills** from repeating JSON boilerplate and redundant conversation history on every handoff.
2. **Rogue tool calls & infinite loops** discovered only *after* paying for downstream model/API execution.
3. **Opaque JSON traces** that are painful to audit and verify in production.

**AgentWire** brings **gRPC/Protobuf discipline to LLM agent swarms**:

```text
[Agent A (Planner)]
        │ (Typed Intent / Dict / Pydantic)
        ▼
┌───────────────────────────────────────────────────────────┐
│  Layer 1: Semantic AST Compiler (agentwire-core)          │
│  Actions: QUERY | MUTATE | DELEGATE | YIELD | ASSERT      │
└───────────────────────────────────────────────────────────┘
        ▼
┌───────────────────────────────────────────────────────────┐
│  Layer 2: Binary Wire Codec (AW01 + Static Dict + CRC32)  │
│  1-byte dictionary tokens, LEB128/ZigZag varints, bitmask │
└───────────────────────────────────────────────────────────┘
        ▼
┌───────────────────────────────────────────────────────────┐
│  Layer 3: Deterministic Policy Guard-Gate (validator)     │
│  RBAC, target prefixes, hop depth, cycle & budget caps    │
└───────────────────────────────────────────────────────────┘
        │  ==== Wire Transmission (~115 B / ~15.6 µs) ====
        ▼
┌───────────────────────────────────────────────────────────┐
│  Layer 4: Lossless Decompiler & Live Telemetry Stream     │
│  ├─ Projects compact 1:1 Canonical AST for Agent B        │
│  └─ Streams Hex + Human Trace via SSE/JSONL to Dashboard  │
└───────────────────────────────────────────────────────────┘
        ▼
[Agent B (Worker)]
```

---

## Reproducible Benchmarks

Measured on local Windows (`rustc 1.99.1`, `--release` PyO3 wheel, `Python 3.12`, `tiktoken:cl100k_base`) across **1,000 multi-agent hops** (`planner -> researcher -> coder -> reviewer`):

```bash
python benchmarks/token_latency_bench.py --iterations 250 --export-trace dashboard/public/sample-trace.jsonl
```

| Workload / Capture | Frames | Wire Byte Reduction | Token Reduction (`cl100k_base`) | Est. Savings / 100k Hops (@ \$3/1M) | Guard-Gate Verdicts |
| --- | ---: | ---: | ---: | ---: | --- |
| **1,000-Hop Benchmark** (4-stage allowed loop) | 1,000 | **-90.45%** (`1207.0 B → 115.2 B`) | **-83.11%** (`312.2 → 52.8 tok`) | **\$77.85** | 1,000 ok + 1 rogue test blocked |
| **Exported Dashboard Trace** (`public/sample-trace.jsonl`) | 6 | **-90.7%** | **-85.1%** | **\$79.00** | `4 ok / 2 blocked` |
| **Live LangGraph + CrewAI SSE Demo** (`examples/live_langgraph_crewai_demo.py`) | 5 | **-92.6%** | **-87.0%** | **\$82.62** | `4 ok / 1 blocked` |

| Rust Core + PyO3 Operation (1,000-Hop Steady State) | Mean Latency | p99 Latency |
| --- | ---: | ---: |
| Encode AST → `AW01` Binary Frame | **3.01 µs** | 7.90 µs |
| Deterministic Policy Guard-Gate Check | **2.63 µs** | 5.60 µs |
| Decode + CRC32 Integrity Verification | **2.87 µs** | — |
| Lossless 1:1 AST Decompilation | **8.45 µs** | — |
| **Full Roundtrip Pipeline** | **16.96 µs** | **43.70 µs** |
| Rogue `MUTATE` Blocked Pre-Flight (`UNAUTHORIZED_ACTION`) | **2.90 µs** | Zero API cost |

---

## Quickstart (3-Line Developer Experience)

### LangGraph Drop-in Adapter

```python
from agentwire.adapters import LangGraphWire

wire = LangGraphWire(enable_safety_gate=True)

# Wrap any node or serialize state deltas directly over AW01 binary frames
result = wire.serialize_state_update(
    source_agent="planner",
    target_agent="researcher",
    action="DELEGATE",
    target="repo:billing",
    intent="analyze_schema",
    state_delta={"module": "billing", "depth": 2},
    refs=["ctx://issue/418"],
)
print(result.trace_summary["human_readable"])
```

### CrewAI Drop-in Task Bus

```python
from agentwire.adapters import CrewAIWire

bus = CrewAIWire(enable_safety_gate=True)
bus.register_role("researcher", lambda payload, trace: {"findings": f"scanned {payload['module']}"})

out = bus.dispatch_task(
    from_role="planner",
    to_role="researcher",
    target="repo:billing",
    intent="analyze_schema",
    task_payload={"module": "ledger"},
)
```

### Deterministic Guard-Gate Protection

```python
from agentwire import WireClient, PolicyViolationError

client = WireClient(enable_safety_gate=True)

try:
    # Read-only researcher attempting an unauthorized database mutation:
    client.send(
        source_agent="researcher",
        target_agent="coder",
        action="MUTATE",
        target="prod_db:invoices",
        intent="delete",
    )
except PolicyViolationError as err:
    # Intercepted locally in ~2-3 µs before any downstream LLM/API call!
    print(err.reason_code, err.detail)
    # -> UNAUTHORIZED_ACTION agent 'researcher' is not permitted to execute action MUTATE
```

---

## Repository Structure

```text
agentwire/
├── Cargo.toml
├── pyproject.toml
├── LICENSE
├── crates/
│   ├── agentwire-core/       # Typed AST, AW01 binary codec, static dict, CRC32, lossless decompiler
│   ├── agentwire-validator/  # Deterministic RBAC, target prefix, hop/cycle & budget guard-gates
│   └── agentwire-py/         # PyO3 + maturin native Python bindings
├── python/agentwire/
│   ├── client.py             # High-level WireClient, TokenEstimator & WireMetrics
│   ├── adapters/             # Drop-in LangGraphWire & CrewAIWire adapters
│   └── telemetry/            # TelemetryStream (JSONL sink + live HTTP/SSE trace server)
├── dashboard/                # Dark-mode React + TypeScript + Tailwind split-pane TraceViewer
├── benchmarks/
│   └── token_latency_bench.py
└── tests/
    ├── test_codec_roundtrip.py
    └── test_policy_guard.py
```

---

## Local Development & Verification (Windows / macOS / Linux)

### 1. Run Rust Core & Validator Tests
```bash
cargo test --workspace
```

### 2. Build Python Extension & Run `pytest`
```bash
uv venv .venv
uv pip install --python .venv/Scripts/python.exe maturin pytest tiktoken
.venv/Scripts/maturin.exe develop --release
.venv/Scripts/pytest.exe
```

### 3. Run Benchmarks & Export Live Trace for the Dashboard
```bash
.venv/Scripts/python.exe benchmarks/token_latency_bench.py \
  --iterations 250 \
  --export-trace dashboard/public/sample-trace.jsonl
```

### 4. Launch the Dark-Mode Observability Dashboard & Live SSE Demo
```bash
# Terminal 1: Start the React TraceViewer UI
cd dashboard
npm install
npm run dev

# Terminal 2: Stream live LangGraphWire + CrewAIWire traces over SSE
.venv/Scripts/python.exe examples/live_langgraph_crewai_demo.py --keep-alive 0
```
Open `http://localhost:5173` and click **Connect SSE** (`http://127.0.0.1:8765/api/stream`) to watch live multi-agent frames stream in real time:
- **Left Pane:** Color-coded `AW01` raw binary hex bytes (`Magic`, `Header/Varints`, `Dict+AST`, `CRC32`), wire footprint comparison bar, and per-stage microsecond latencies.
- **Right Pane:** Lossless human-readable narrative, 1:1 Canonical AST, and Policy Guard-Gate pass/block verdict cards.
- **CI/CD:** GitHub Actions workflow in `.github/workflows/ci.yml` automatically validates `cargo test --workspace`, `maturin develop --release`, `pytest`, `benchmarks/token_latency_bench.py`, and `dashboard` production builds on both Linux and Windows.
