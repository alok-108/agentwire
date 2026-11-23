# Security Model & Threat Boundaries (`AW01` v0.4.0)

AgentWire (`swarmwire`) is engineered with explicit, verifiable security boundaries. This document distinguishes **what the protocol and runtime enforce** from **what remains an operational responsibility of the deployer**.

---

## 1. Enforced Security Properties (Tested in CI)

| Property | Mechanism | Verification |
| --- | --- | --- |
| **Transport Confidentiality** | Optional TLS 1.2 / 1.3 (+ mTLS) via `ssl.SSLContext` on `AgentWireRpcServer` & `AgentWireRpcClient` | `tests/test_v04_production_hardening.py::test_tls_encrypted_tcp_rpc_and_plaintext_rejection` |
| **Per-Agent Asymmetric Identity** | Per-agent Ed25519 keypairs (`sign_ast_ed25519` / `verify_frame_ed25519`); receiver binds signature strictly to `public_keys[source_agent]` so no compromised peer can impersonate another role | `crates/agentwire-core/src/frame.rs` + `tests/test_v04_production_hardening.py` |
| **Zero-Trust Receiver Authorization** | Sender `GUARD_VERIFIED` header bit is advisory-only and ignored by `PolicyEngine`; `FrameHeader::mac_verified` is never serialized on the wire | `tests/test_security_and_robustness.py` |
| **Cross-Restart & Multi-Instance Replay Protection** | Persistent `SqliteStateStore` (SQLite WAL + atomic `BEGIN IMMEDIATE`) or pluggable `StateStore` (`record_nonce_if_new`) + clock-skew bounds (`max_clock_skew_ms`) | `tests/test_v04_production_hardening.py::test_sqlite_replay_and_idempotency_persist_across_restarts_and_multiple_servers` |
| **Idempotent Retry Safety** | Requests carrying `idempotency_key` are deduplicated in `StateStore` before handler execution; `AgentWireRpcClient` refuses blind retries on non-idempotent `MUTATE` calls | `tests/test_v04_production_hardening.py::test_idempotent_retry_deduplicates_slow_mutate_after_client_timeout` |
| **Independent Server-Side Usage Floor** | `IndependentTokenMeter` meters actual inbound AST + outbound payload tokens on the server and settles `max(measured, handler_reported)` so handlers cannot zero-out usage | `tests/test_v04_production_hardening.py::test_independent_usage_meter_prevents_handler_zero_reporting` |
| **Parser DoS & Memory Safety** | Rust `agentwire-core` enforces `MAX_NESTING_DEPTH = 32`, `MAX_COLLECTION_ITEMS = 4096`, `MAX_RPC_FRAME_BYTES = 4 MiB`, and CRC32 framing checks | Rust `proptest` fuzzing + 500-case FFI fuzz suite |

---

## 2. Explicit Scope Boundaries & Operational Responsibilities

AgentWire is a **wire protocol and policy runtime**, not a full cloud security suite. Production deployers must still provide:

1. **Key Management & Rotation:** Ed25519 private keys and TLS certificates should be provisioned and rotated via a KMS / Vault / SPIFFE workload identity system rather than static files.
2. **Distributed Multi-Node State Store:** `SqliteStateStore` (WAL) provides zero-dependency persistence across restarts and local multi-process instances sharing a disk volume. Across separate machines or multi-region clusters, implement the `StateStore` protocol backed by Redis (`SET NX EX`) or PostgreSQL.
3. **Upstream LLM Provider Billing Reconciliation:** `IndependentTokenMeter` enforces a verifiable floor on wire AST + response payload tokens. If a handler invokes external LLM APIs with large internal system prompts or chain-of-thought reasoning, plug in a custom `UsageMeter` wired to your LLM gateway/proxy's actual provider receipt (`usage.prompt_tokens + usage.completion_tokens`).
4. **TLS Certificate Provisioning:** `AgentWireRpcServer` supports TLS/mTLS via `ssl.SSLContext`, and plaintext TCP remains allowed only when `ssl_context=None` (intended for local loopback development). Always configure TLS 1.3 in non-loopback deployments.

## Reporting a Vulnerability

Please open a private security advisory on GitHub (`https://github.com/alok-108/agentwire/security/advisories/new`) rather than filing a public issue for security vulnerabilities.
