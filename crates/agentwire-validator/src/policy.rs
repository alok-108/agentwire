//! Deterministic state-machine, replay protection, and two-phase budget guard-gates
//! for AgentWire.
//!
//! Every outbound or inbound [`WireFrame`] is evaluated independently (receivers NEVER trust
//! the sender's `GUARD_VERIFIED` flag):
//! 1. **Cryptographic auth & freshness**: optionally requires verified HMAC-SHA256
//!    (`header.mac_verified == true`), rejects replayed `(source_agent, nonce)` pairs, and
//!    enforces timestamp clock-skew bounds.
//! 2. **Structural sanity**: non-empty target/intent, non-empty agent IDs.
//! 3. **Capability RBAC**: sender must be permitted to perform `frame.body.action` and access
//!    `frame.body.target` (exact or prefix wildcard).
//! 4. **Security & schema filters**: blocks forbidden payload fields recursively and enforces
//!    required fields per action.
//! 5. **Hop-depth & cycle guards**: prevents runaway multi-agent delegation loops.
//! 6. **Two-phase budget reservation & settlement**: reserves `header.budget` on acceptance,
//!    settles actual downstream token/micro-USD consumption via [`PolicyEngine::settle_usage`]
//!    (returning unused delta to the session pool), or refunds 100% via
//!    [`PolicyEngine::release_reservation`] on failure/cancellation.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use agentwire_core::{AgentAction, AstValue, WireFrame};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Machine-readable rejection reason emitted when a frame fails guard-gate validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectionCode {
    UnauthenticatedFrame,
    ReplayDetected,
    ExpiredTimestamp,
    EmptyRoutingOrAstField,
    UnknownAgent,
    UnauthorizedAction,
    DisallowedTarget,
    MaxHopDepthExceeded,
    SelfDelegationLoop,
    RepeatedCycleDetected,
    BudgetTokensExceeded,
    BudgetCostExceeded,
    SessionBudgetExhausted,
    DuplicateActiveReservation,
    ForbiddenPayloadField,
    MissingRequiredField,
}

impl RejectionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnauthenticatedFrame => "UNAUTHENTICATED_FRAME",
            Self::ReplayDetected => "REPLAY_DETECTED",
            Self::ExpiredTimestamp => "EXPIRED_TIMESTAMP",
            Self::EmptyRoutingOrAstField => "EMPTY_ROUTING_OR_AST_FIELD",
            Self::UnknownAgent => "UNKNOWN_AGENT",
            Self::UnauthorizedAction => "UNAUTHORIZED_ACTION",
            Self::DisallowedTarget => "DISALLOWED_TARGET",
            Self::MaxHopDepthExceeded => "MAX_HOP_DEPTH_EXCEEDED",
            Self::SelfDelegationLoop => "SELF_DELEGATION_LOOP",
            Self::RepeatedCycleDetected => "REPEATED_CYCLE_DETECTED",
            Self::BudgetTokensExceeded => "BUDGET_TOKENS_EXCEEDED",
            Self::BudgetCostExceeded => "BUDGET_COST_EXCEEDED",
            Self::SessionBudgetExhausted => "SESSION_BUDGET_EXHAUSTED",
            Self::DuplicateActiveReservation => "DUPLICATE_ACTIVE_RESERVATION",
            Self::ForbiddenPayloadField => "FORBIDDEN_PAYLOAD_FIELD",
            Self::MissingRequiredField => "MISSING_REQUIRED_FIELD",
        }
    }
}

impl fmt::Display for RejectionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of evaluating a [`WireFrame`] through the deterministic guard-gate engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationResult {
    Allowed,
    Rejected {
        reason_code: RejectionCode,
        detail: String,
    },
}

impl ValidationResult {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    pub fn reason_code(&self) -> Option<RejectionCode> {
        match self {
            Self::Allowed => None,
            Self::Rejected { reason_code, .. } => Some(*reason_code),
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Allowed => None,
            Self::Rejected { detail, .. } => Some(detail.as_str()),
        }
    }
}

/// Errors encountered when loading a policy or settling/releasing budget reservations.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("no active budget reservation found for trace_id={trace_id}, span_id={span_id}")]
    ReservationNotFound { trace_id: u64, span_id: u32 },
}

/// Active in-flight budget hold created when a frame is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetReservation {
    pub trace_id: u64,
    pub span_id: u32,
    pub reserved_tokens: u32,
    pub reserved_micro_usd: u64,
}

/// Receipt produced when an active reservation is settled against actual downstream usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub trace_id: u64,
    pub span_id: u32,
    pub reserved_tokens: u32,
    pub actual_tokens: u32,
    /// Positive when unused tokens were returned to the pool; negative if actual exceeded reservation.
    pub released_tokens: i64,
    pub reserved_micro_usd: u64,
    pub actual_micro_usd: u64,
    pub released_micro_usd: i64,
}

/// Snapshot of two-phase session budget accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLedger {
    pub session_max_tokens: u64,
    pub session_max_micro_usd: u64,
    pub settled_tokens: u64,
    pub settled_micro_usd: u64,
    pub reserved_tokens: u64,
    pub reserved_micro_usd: u64,
    pub remaining_tokens: u64,
    pub remaining_micro_usd: u64,
    pub active_reservations: usize,
    pub evaluated_frames: u64,
    pub rejected_frames: u64,
}

/// Capability grant for an individual agent role/ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapability {
    pub agent_id: String,
    pub allowed_actions: Vec<AgentAction>,
    /// Allowed target resource patterns: exact match, prefix with `*` (e.g. `repo:*`), or `*`.
    pub allowed_targets: Vec<String>,
    pub max_tokens_per_frame: u32,
    pub max_micro_usd_per_frame: u64,
    #[serde(default)]
    pub allow_self_call: bool,
}

impl AgentCapability {
    pub fn permits_target(&self, target: &str) -> bool {
        self.allowed_targets.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }
            if let Some(prefix) = pattern.strip_suffix('*') {
                target.starts_with(prefix)
            } else {
                pattern == target
            }
        })
    }
}

/// Declarative safety, authentication, replay, and budget policy enforced by [`PolicyEngine`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySpec {
    /// Maximum allowed `header.hop_depth` before breaking delegation chains.
    pub max_hop_depth: u16,
    /// Cumulative token ceiling across an entire session (settled + active reservations).
    pub session_max_tokens: u64,
    /// Cumulative micro-USD ceiling across an entire session (`1 USD = 1_000_000`).
    pub session_max_micro_usd: u64,
    /// Maximum times the exact same `(source, target, action, intent)` tuple may repeat in one trace.
    #[serde(default = "default_max_identical_hops")]
    pub max_identical_hops_per_trace: usize,
    /// If `true`, any sender not present in `capabilities` is immediately rejected.
    pub strict_agent_registry: bool,
    /// If `true`, frames MUST have `header.mac_verified == true` (verified via HMAC-SHA256).
    #[serde(default)]
    pub require_authenticated_frames: bool,
    /// Maximum permitted absolute clock skew (`|now_ms - header.timestamp_ms|`). `0` disables check.
    #[serde(default = "default_max_clock_skew_ms")]
    pub max_clock_skew_ms: u64,
    /// Payload keys rejected anywhere in the AST (including nested maps).
    #[serde(default)]
    pub forbidden_payload_keys: Vec<String>,
    /// Required top-level payload keys indexed by action name (`"MUTATE"`, `"DELEGATE"`, etc.).
    #[serde(default)]
    pub required_fields_by_action: BTreeMap<String, Vec<String>>,
    /// Per-agent capability definitions.
    pub capabilities: BTreeMap<String, AgentCapability>,
}

fn default_max_identical_hops() -> usize {
    3
}

fn default_max_clock_skew_ms() -> u64 {
    300_000 // 5 minutes
}

impl PolicySpec {
    /// Default policy for a 4-role software engineering swarm (`planner`, `researcher`, `coder`, `reviewer`).
    pub fn default_multi_agent() -> Self {
        let mut capabilities = BTreeMap::new();

        capabilities.insert(
            "planner".to_string(),
            AgentCapability {
                agent_id: "planner".to_string(),
                allowed_actions: vec![
                    AgentAction::Query,
                    AgentAction::Delegate,
                    AgentAction::Yield,
                    AgentAction::Assert,
                ],
                allowed_targets: vec!["*".to_string()],
                max_tokens_per_frame: 4096,
                max_micro_usd_per_frame: 100_000,
                allow_self_call: false,
            },
        );

        capabilities.insert(
            "researcher".to_string(),
            AgentCapability {
                agent_id: "researcher".to_string(),
                allowed_actions: vec![
                    AgentAction::Query,
                    AgentAction::Yield,
                    AgentAction::Assert,
                ],
                allowed_targets: vec![
                    "repo:*".to_string(),
                    "docs:*".to_string(),
                    "postgres.*".to_string(),
                    "memory:*".to_string(),
                    "agent:*".to_string(),
                    "planner".to_string(),
                    "coder".to_string(),
                ],
                max_tokens_per_frame: 4096,
                max_micro_usd_per_frame: 80_000,
                allow_self_call: false,
            },
        );

        capabilities.insert(
            "coder".to_string(),
            AgentCapability {
                agent_id: "coder".to_string(),
                allowed_actions: vec![
                    AgentAction::Query,
                    AgentAction::Mutate,
                    AgentAction::Yield,
                    AgentAction::Assert,
                ],
                allowed_targets: vec![
                    "repo:*".to_string(),
                    "fs:*".to_string(),
                    "workspace:*".to_string(),
                    "tests:*".to_string(),
                    "agent:*".to_string(),
                    "reviewer".to_string(),
                    "planner".to_string(),
                ],
                max_tokens_per_frame: 8192,
                max_micro_usd_per_frame: 150_000,
                allow_self_call: false,
            },
        );

        capabilities.insert(
            "reviewer".to_string(),
            AgentCapability {
                agent_id: "reviewer".to_string(),
                allowed_actions: vec![
                    AgentAction::Query,
                    AgentAction::Assert,
                    AgentAction::Yield,
                ],
                allowed_targets: vec!["*".to_string()],
                max_tokens_per_frame: 4096,
                max_micro_usd_per_frame: 80_000,
                allow_self_call: false,
            },
        );

        let forbidden_payload_keys = vec![
            "system_prompt_override".to_string(),
            "raw_sql_override".to_string(),
            "api_key".to_string(),
            "secret_token".to_string(),
            "__proto__".to_string(),
        ];

        Self {
            max_hop_depth: 8,
            session_max_tokens: 250_000,
            session_max_micro_usd: 5_000_000,
            max_identical_hops_per_trace: 3,
            strict_agent_registry: true,
            require_authenticated_frames: false,
            max_clock_skew_ms: default_max_clock_skew_ms(),
            forbidden_payload_keys,
            required_fields_by_action: BTreeMap::new(),
            capabilities,
        }
    }

    /// Strict production multi-agent policy requiring cryptographically verified HMAC-SHA256 frames.
    pub fn strict_authenticated() -> Self {
        let mut spec = Self::default_multi_agent();
        spec.require_authenticated_frames = true;
        spec
    }

    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn to_json(&self) -> Result<String, PolicyError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Stateful deterministic guard-gate engine with replay detection and two-phase budget accounting.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    spec: PolicySpec,
    settled_tokens: u64,
    settled_micro_usd: u64,
    active_reservations: BTreeMap<(u64, u32), BudgetReservation>,
    seen_nonces: HashSet<(String, u64)>,
    trace_hop_counts: BTreeMap<(u64, String, String, AgentAction, String), usize>,
    evaluated_frames: u64,
    rejected_frames: u64,
}

impl PolicyEngine {
    pub fn new(spec: PolicySpec) -> Self {
        Self {
            spec,
            settled_tokens: 0,
            settled_micro_usd: 0,
            active_reservations: BTreeMap::new(),
            seen_nonces: HashSet::new(),
            trace_hop_counts: BTreeMap::new(),
            evaluated_frames: 0,
            rejected_frames: 0,
        }
    }

    pub fn default_multi_agent() -> Self {
        Self::new(PolicySpec::default_multi_agent())
    }

    pub fn strict_authenticated() -> Self {
        Self::new(PolicySpec::strict_authenticated())
    }

    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        Ok(Self::new(PolicySpec::from_json(json)?))
    }

    pub fn spec(&self) -> &PolicySpec {
        &self.spec
    }

    pub fn reserved_tokens(&self) -> u64 {
        self.active_reservations
            .values()
            .map(|r| r.reserved_tokens as u64)
            .sum()
    }

    pub fn reserved_micro_usd(&self) -> u64 {
        self.active_reservations
            .values()
            .map(|r| r.reserved_micro_usd)
            .sum()
    }

    pub fn remaining_tokens(&self) -> u64 {
        let committed = self.settled_tokens.saturating_add(self.reserved_tokens());
        self.spec.session_max_tokens.saturating_sub(committed)
    }

    pub fn remaining_micro_usd(&self) -> u64 {
        let committed = self
            .settled_micro_usd
            .saturating_add(self.reserved_micro_usd());
        self.spec.session_max_micro_usd.saturating_sub(committed)
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.evaluated_frames, self.rejected_frames)
    }

    pub fn budget_ledger(&self) -> BudgetLedger {
        let reserved_tokens = self.reserved_tokens();
        let reserved_micro_usd = self.reserved_micro_usd();
        BudgetLedger {
            session_max_tokens: self.spec.session_max_tokens,
            session_max_micro_usd: self.spec.session_max_micro_usd,
            settled_tokens: self.settled_tokens,
            settled_micro_usd: self.settled_micro_usd,
            reserved_tokens,
            reserved_micro_usd,
            remaining_tokens: self.remaining_tokens(),
            remaining_micro_usd: self.remaining_micro_usd(),
            active_reservations: self.active_reservations.len(),
            evaluated_frames: self.evaluated_frames,
            rejected_frames: self.rejected_frames,
        }
    }

    /// Reset mutable session counters, reservations, and replay caches.
    pub fn reset_session(&mut self) {
        self.settled_tokens = 0;
        self.settled_micro_usd = 0;
        self.active_reservations.clear();
        self.seen_nonces.clear();
        self.trace_hop_counts.clear();
        self.evaluated_frames = 0;
        self.rejected_frames = 0;
    }

    /// Pure deterministic validation without mutating state (no wall-clock skew check).
    pub fn validate_frame(&self, frame: &WireFrame) -> ValidationResult {
        self.validate_frame_at(frame, None)
    }

    /// Pure deterministic validation with optional current Unix timestamp (`now_ms`) for freshness check.
    ///
    /// Note: `frame.header.flags & FrameFlags::GUARD_VERIFIED` is **intentionally ignored** so a
    /// malicious sender cannot bypass receiver-side authorization by forging header bits.
    pub fn validate_frame_at(
        &self,
        frame: &WireFrame,
        now_ms: Option<u64>,
    ) -> ValidationResult {
        self.check_frame_internal(frame, now_ms, false)
    }

    fn check_frame_internal(
        &self,
        frame: &WireFrame,
        now_ms: Option<u64>,
        check_reservation_collision: bool,
    ) -> ValidationResult {
        let h = &frame.header;
        let b = &frame.body;

        // 0. Cryptographic authentication & replay/freshness checks
        if self.spec.require_authenticated_frames && !h.mac_verified {
            return ValidationResult::Rejected {
                reason_code: RejectionCode::UnauthenticatedFrame,
                detail: "policy requires HMAC-SHA256 verified frames (mac_verified=false)"
                    .to_string(),
            };
        }

        if h.nonce > 0 && self.seen_nonces.contains(&(h.source_agent.clone(), h.nonce)) {
            return ValidationResult::Rejected {
                reason_code: RejectionCode::ReplayDetected,
                detail: format!(
                    "replayed nonce {} detected for source agent '{}'",
                    h.nonce, h.source_agent
                ),
            };
        }

        if let Some(now) = now_ms {
            if self.spec.max_clock_skew_ms > 0 && h.timestamp_ms > 0 {
                let skew = now.abs_diff(h.timestamp_ms);
                if skew > self.spec.max_clock_skew_ms {
                    return ValidationResult::Rejected {
                        reason_code: RejectionCode::ExpiredTimestamp,
                        detail: format!(
                            "frame timestamp_ms={} skew {}ms exceeds max_clock_skew_ms={}ms",
                            h.timestamp_ms, skew, self.spec.max_clock_skew_ms
                        ),
                    };
                }
            }
        }

        // 1. Structural non-empty invariants
        if h.source_agent.trim().is_empty()
            || h.target_agent.trim().is_empty()
            || b.target.trim().is_empty()
            || b.intent.trim().is_empty()
        {
            return ValidationResult::Rejected {
                reason_code: RejectionCode::EmptyRoutingOrAstField,
                detail: "source_agent, target_agent, body.target, and body.intent must be non-empty"
                    .to_string(),
            };
        }

        // 2. Hop depth guard
        if h.hop_depth > self.spec.max_hop_depth {
            return ValidationResult::Rejected {
                reason_code: RejectionCode::MaxHopDepthExceeded,
                detail: format!(
                    "hop_depth {} exceeds policy limit {}",
                    h.hop_depth, self.spec.max_hop_depth
                ),
            };
        }

        // 3. Agent capability lookup & RBAC checks
        if let Some(cap) = self.spec.capabilities.get(&h.source_agent) {
            if h.source_agent == h.target_agent && !cap.allow_self_call {
                return ValidationResult::Rejected {
                    reason_code: RejectionCode::SelfDelegationLoop,
                    detail: format!(
                        "agent '{}' is not permitted to send frames to itself",
                        h.source_agent
                    ),
                };
            }

            if !cap.allowed_actions.contains(&b.action) {
                return ValidationResult::Rejected {
                    reason_code: RejectionCode::UnauthorizedAction,
                    detail: format!(
                        "agent '{}' is not permitted to execute action {}",
                        h.source_agent,
                        b.action.as_str()
                    ),
                };
            }

            if !cap.permits_target(&b.target) {
                return ValidationResult::Rejected {
                    reason_code: RejectionCode::DisallowedTarget,
                    detail: format!(
                        "agent '{}' cannot access target '{}'",
                        h.source_agent, b.target
                    ),
                };
            }

            if h.budget.max_tokens > cap.max_tokens_per_frame {
                return ValidationResult::Rejected {
                    reason_code: RejectionCode::BudgetTokensExceeded,
                    detail: format!(
                        "requested max_tokens {} exceeds agent '{}' per-frame cap {}",
                        h.budget.max_tokens, h.source_agent, cap.max_tokens_per_frame
                    ),
                };
            }

            if h.budget.max_micro_usd > cap.max_micro_usd_per_frame {
                return ValidationResult::Rejected {
                    reason_code: RejectionCode::BudgetCostExceeded,
                    detail: format!(
                        "requested max_micro_usd {} exceeds agent '{}' per-frame cap {}",
                        h.budget.max_micro_usd, h.source_agent, cap.max_micro_usd_per_frame
                    ),
                };
            }
        } else if self.spec.strict_agent_registry {
            return ValidationResult::Rejected {
                reason_code: RejectionCode::UnknownAgent,
                detail: format!(
                    "unregistered source agent '{}' blocked by strict_agent_registry",
                    h.source_agent
                ),
            };
        }

        // 4. Recursive forbidden payload key check (security invariants take priority over budget)
        if !self.spec.forbidden_payload_keys.is_empty() {
            let forbidden: HashSet<&str> = self
                .spec
                .forbidden_payload_keys
                .iter()
                .map(String::as_str)
                .collect();
            if let Some(offending_key) = find_forbidden_key_in_map(&b.payload, &forbidden) {
                return ValidationResult::Rejected {
                    reason_code: RejectionCode::ForbiddenPayloadField,
                    detail: format!(
                        "forbidden payload field '{}' blocked by policy guard-gate",
                        offending_key
                    ),
                };
            }
        }

        // 5. Required top-level fields by action
        if let Some(required_keys) = self.spec.required_fields_by_action.get(b.action.as_str()) {
            for req in required_keys {
                if !b.payload.contains_key(req) {
                    return ValidationResult::Rejected {
                        reason_code: RejectionCode::MissingRequiredField,
                        detail: format!(
                            "action {} requires payload field '{}'",
                            b.action.as_str(),
                            req
                        ),
                    };
                }
            }
        }

        // 6. Active reservation collision check + two-phase cumulative session budget check
        if check_reservation_collision
            && self.active_reservations.contains_key(&(h.trace_id, h.span_id))
        {
            return ValidationResult::Rejected {
                reason_code: RejectionCode::DuplicateActiveReservation,
                detail: format!(
                    "active budget reservation already exists for trace_id={} span_id={}",
                    h.trace_id, h.span_id
                ),
            };
        }

        let committed_tokens = self.settled_tokens.saturating_add(self.reserved_tokens());
        let committed_cost = self
            .settled_micro_usd
            .saturating_add(self.reserved_micro_usd());
        let next_tokens = committed_tokens.saturating_add(h.budget.max_tokens as u64);
        let next_cost = committed_cost.saturating_add(h.budget.max_micro_usd);
        if next_tokens > self.spec.session_max_tokens
            || next_cost > self.spec.session_max_micro_usd
        {
            return ValidationResult::Rejected {
                reason_code: RejectionCode::SessionBudgetExhausted,
                detail: format!(
                    "session budget exhausted (remaining: {} tokens / {} micro-USD; frame requests: {} tokens / {} micro-USD)",
                    self.remaining_tokens(),
                    self.remaining_micro_usd(),
                    h.budget.max_tokens,
                    h.budget.max_micro_usd
                ),
            };
        }

        // 7. Cycle / repeated identical hop check per trace
        let hop_key = (
            h.trace_id,
            h.source_agent.clone(),
            h.target_agent.clone(),
            b.action,
            b.intent.clone(),
        );
        let prior_count = self.trace_hop_counts.get(&hop_key).copied().unwrap_or(0);
        if self.spec.max_identical_hops_per_trace > 0
            && prior_count >= self.spec.max_identical_hops_per_trace
        {
            return ValidationResult::Rejected {
                reason_code: RejectionCode::RepeatedCycleDetected,
                detail: format!(
                    "trace {} repeated identical hop ({} -> {} {}::{}) {} times (limit: {})",
                    h.trace_id,
                    h.source_agent,
                    h.target_agent,
                    b.action.as_str(),
                    b.intent,
                    prior_count + 1,
                    self.spec.max_identical_hops_per_trace
                ),
            };
        }

        ValidationResult::Allowed
    }

    /// Evaluate a frame and, if `Allowed`, reserve its declared budget and record nonce + hop signature.
    pub fn evaluate_and_record(&mut self, frame: &WireFrame) -> ValidationResult {
        self.evaluate_and_record_at(frame, None)
    }

    /// Evaluate a frame at wall-clock `now_ms`, reserving budget and recording nonce on acceptance.
    pub fn evaluate_and_record_at(
        &mut self,
        frame: &WireFrame,
        now_ms: Option<u64>,
    ) -> ValidationResult {
        self.evaluated_frames += 1;
        let result = self.check_frame_internal(frame, now_ms, true);
        if result.is_allowed() {
            let h = &frame.header;
            self.active_reservations.insert(
                (h.trace_id, h.span_id),
                BudgetReservation {
                    trace_id: h.trace_id,
                    span_id: h.span_id,
                    reserved_tokens: h.budget.max_tokens,
                    reserved_micro_usd: h.budget.max_micro_usd,
                },
            );

            if h.nonce > 0 {
                self.seen_nonces.insert((h.source_agent.clone(), h.nonce));
            }

            let hop_key = (
                h.trace_id,
                h.source_agent.clone(),
                h.target_agent.clone(),
                frame.body.action,
                frame.body.intent.clone(),
            );
            *self.trace_hop_counts.entry(hop_key).or_insert(0) += 1;
        } else {
            self.rejected_frames += 1;
        }
        result
    }

    /// Phase 2 (Settlement): finalize an active reservation with actual downstream usage,
    /// returning unused reserved budget back to the session pool.
    pub fn settle_usage(
        &mut self,
        trace_id: u64,
        span_id: u32,
        actual_tokens: u32,
        actual_micro_usd: u64,
    ) -> Result<SettlementReceipt, PolicyError> {
        let reservation = self
            .active_reservations
            .remove(&(trace_id, span_id))
            .ok_or(PolicyError::ReservationNotFound { trace_id, span_id })?;

        self.settled_tokens = self.settled_tokens.saturating_add(actual_tokens as u64);
        self.settled_micro_usd = self.settled_micro_usd.saturating_add(actual_micro_usd);

        let released_tokens = (reservation.reserved_tokens as i64) - (actual_tokens as i64);
        let released_micro_usd =
            (reservation.reserved_micro_usd as i64) - (actual_micro_usd as i64);

        Ok(SettlementReceipt {
            trace_id,
            span_id,
            reserved_tokens: reservation.reserved_tokens,
            actual_tokens,
            released_tokens,
            reserved_micro_usd: reservation.reserved_micro_usd,
            actual_micro_usd,
            released_micro_usd,
        })
    }

    /// Phase 2 (Release): cancel an active reservation and refund 100% of reserved budget
    /// (e.g., when a downstream tool call times out or is aborted before incurring LLM cost).
    pub fn release_reservation(
        &mut self,
        trace_id: u64,
        span_id: u32,
    ) -> Result<BudgetReservation, PolicyError> {
        self.active_reservations
            .remove(&(trace_id, span_id))
            .ok_or(PolicyError::ReservationNotFound { trace_id, span_id })
    }
}

fn find_forbidden_key_in_map<'a>(
    map: &'a BTreeMap<String, AstValue>,
    forbidden: &HashSet<&str>,
) -> Option<&'a str> {
    for (k, v) in map {
        if forbidden.contains(k.as_str()) {
            return Some(k.as_str());
        }
        if let Some(found) = find_forbidden_key_in_value(v, forbidden) {
            return Some(found);
        }
    }
    None
}

fn find_forbidden_key_in_value<'a>(
    value: &'a AstValue,
    forbidden: &HashSet<&str>,
) -> Option<&'a str> {
    match value {
        AstValue::Map(nested) => find_forbidden_key_in_map(nested, forbidden),
        AstValue::List(items) => {
            for item in items {
                if let Some(found) = find_forbidden_key_in_value(item, forbidden) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentwire_core::{AstNode, BudgetCap, FrameFlags, FrameHeader};

    #[test]
    fn blocks_read_only_researcher_even_with_forged_guard_verified_flag() {
        let engine = PolicyEngine::default_multi_agent();
        let mut header = FrameHeader::new("researcher", "coder", 1, 1);
        // Attacker attempts to forge GUARD_VERIFIED flag
        header.flags |= FrameFlags::GUARD_VERIFIED;
        let body = AstNode::new(AgentAction::Mutate, "repo:src/main.rs", "apply_patch");
        let frame = WireFrame::new(header, body);

        let res = engine.validate_frame(&frame);
        assert_eq!(res.reason_code(), Some(RejectionCode::UnauthorizedAction));
    }

    #[test]
    fn enforces_hmac_auth_replay_protection_and_clock_skew() {
        let mut engine = PolicyEngine::strict_authenticated();
        let mut header = FrameHeader::new("planner", "researcher", 10, 1);
        header.nonce = 99001;
        header.timestamp_ms = 1_763_900_000_000;
        let body = AstNode::new(AgentAction::Delegate, "repo:core", "analyze_schema");

        // Unverified frame rejected under strict_authenticated policy
        let unverified = WireFrame::new(header.clone(), body.clone());
        assert_eq!(
            engine
                .validate_frame_at(&unverified, Some(1_763_900_005_000))
                .reason_code(),
            Some(RejectionCode::UnauthenticatedFrame)
        );

        // Verified frame accepted on first sight
        let mut verified_header = header.clone();
        verified_header.mac_verified = true;
        let verified = WireFrame::new(verified_header.clone(), body.clone());
        assert!(engine
            .evaluate_and_record_at(&verified, Some(1_763_900_005_000))
            .is_allowed());

        // Replaying the same (source_agent, nonce) rejected even with new span_id
        let mut replay_header = verified_header.clone();
        replay_header.span_id = 2;
        assert_eq!(
            engine
                .evaluate_and_record_at(&WireFrame::new(replay_header, body.clone()), Some(1_763_900_006_000))
                .reason_code(),
            Some(RejectionCode::ReplayDetected)
        );

        // Stale timestamp beyond max_clock_skew_ms (5 min) rejected
        let mut stale_header = verified_header;
        stale_header.nonce = 99002;
        stale_header.span_id = 3;
        assert_eq!(
            engine
                .validate_frame_at(&WireFrame::new(stale_header, body), Some(1_763_900_999_000))
                .reason_code(),
            Some(RejectionCode::ExpiredTimestamp)
        );
    }

    #[test]
    fn two_phase_budget_reserve_settle_and_release() {
        let mut spec = PolicySpec::default_multi_agent();
        spec.session_max_tokens = 2500;
        spec.session_max_micro_usd = 50_000;
        let mut engine = PolicyEngine::new(spec);

        let mut h1 = FrameHeader::new("planner", "researcher", 7, 1);
        h1.budget = BudgetCap {
            max_tokens: 2000,
            max_micro_usd: 40_000,
        };
        let b1 = AstNode::new(AgentAction::Delegate, "repo:core", "analyze_schema");

        // Phase 1: Reserve 2000 tokens -> 500 remaining
        assert!(engine
            .evaluate_and_record(&WireFrame::new(h1.clone(), b1.clone()))
            .is_allowed());
        assert_eq!(engine.remaining_tokens(), 500);
        assert_eq!(engine.reserved_tokens(), 2000);

        // Second 1000-token frame blocked while reservation is active
        let mut h2 = h1.clone();
        h2.span_id = 2;
        h2.budget.max_tokens = 1000;
        h2.budget.max_micro_usd = 5_000;
        assert_eq!(
            engine
                .validate_frame(&WireFrame::new(h2.clone(), b1.clone()))
                .reason_code(),
            Some(RejectionCode::SessionBudgetExhausted)
        );

        // Phase 2: Settle span 1 with only 300 actual tokens -> 1700 released! Remaining = 2200
        let receipt = engine.settle_usage(7, 1, 300, 4_000).unwrap();
        assert_eq!(receipt.released_tokens, 1700);
        assert_eq!(receipt.released_micro_usd, 36_000);
        assert_eq!(engine.remaining_tokens(), 2200);
        assert_eq!(engine.reserved_tokens(), 0);

        // Now h2 (1000 tokens) fits comfortably -> reserve & then release (cancel) -> back to 2200
        assert!(engine
            .evaluate_and_record(&WireFrame::new(h2, b1))
            .is_allowed());
        assert_eq!(engine.remaining_tokens(), 1200);
        let refunded = engine.release_reservation(7, 2).unwrap();
        assert_eq!(refunded.reserved_tokens, 1000);
        assert_eq!(engine.remaining_tokens(), 2200);
    }

    #[test]
    fn enforces_target_prefix_and_hop_depth() {
        let engine = PolicyEngine::default_multi_agent();

        let header = FrameHeader::new("coder", "reviewer", 10, 1);
        let bad_target = AstNode::new(AgentAction::Mutate, "prod_db:users", "delete");
        assert_eq!(
            engine
                .validate_frame(&WireFrame::new(header.clone(), bad_target))
                .reason_code(),
            Some(RejectionCode::DisallowedTarget)
        );

        let ok_target = AstNode::new(AgentAction::Mutate, "repo:src/auth.rs", "apply_patch");
        assert!(engine
            .validate_frame(&WireFrame::new(header, ok_target.clone()))
            .is_allowed());

        let mut deep_header = FrameHeader::new("coder", "reviewer", 10, 2);
        deep_header.hop_depth = 99;
        assert_eq!(
            engine
                .validate_frame(&WireFrame::new(deep_header, ok_target))
                .reason_code(),
            Some(RejectionCode::MaxHopDepthExceeded)
        );
    }
}
