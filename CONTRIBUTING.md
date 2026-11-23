# Contributing to AgentWire

Thank you for your interest in contributing to **AgentWire**! We welcome contributions across the Rust core (`agentwire-core`, `agentwire-validator`), PyO3 bindings (`agentwire-py`), Python transports & framework adapters, benchmarks, and the React observability dashboard.

## Finding Something to Work On

Look for issues labeled [`good first issue`](https://github.com/alok-108/agentwire/labels/good%20first%20issue) or [`help wanted`](https://github.com/alok-108/agentwire/labels/help%20wanted). Comment on an issue before opening a PR so we can coordinate cleanly.

## Local Setup

### Prerequisites
- Rust stable toolchain (`rustc` + `cargo`, Edition 2021)
- Python 3.10–3.13 + [`uv`](https://docs.astral.sh/uv/)
- Node.js 20+ (only if modifying `dashboard/`)

### Build & Test Everything

```bash
# 1. Rust unit tests + proptest fuzz suite
cargo test --workspace

# 2. Build PyO3 release wheel & run Python test suite (27 tests)
uv venv .venv
uv pip install --python .venv/bin/python maturin pytest tiktoken   # or .venv\Scripts\python.exe on Windows
.venv/bin/maturin develop --release
.venv/bin/pytest

# 3. Verify apples-to-apples benchmark
.venv/bin/python benchmarks/token_latency_bench.py --iterations 100

# 4. Build dashboard (if modified)
cd dashboard && npm install && npm run build
```

## Pull Request Guidelines
1. Keep changes focused and well-tested (add unit tests or `proptest` cases for protocol/validator changes).
2. Never trust sender-set flags (such as `GUARD_VERIFIED`) on receiver-side authorization paths.
3. Ensure `cargo test --workspace` produces zero compiler warnings and `pytest` passes 100%.
4. For benchmark changes, clearly separate wire serialization bytes from LLM input context tokens.
