//! Binary wire frame codec and HMAC-SHA256 frame authentication for AgentWire (`AW01`).
//!
//! # Wire Layout
//!
//! ```text
//! +----------+---------+-------+-----------+---------+-----------+
//! | Magic(4) | Ver (1) | Flg(1)| trace_id  | span_id | hop_depth |
//! |  "AW01"  |   0x01  |  u8   |  varuint  | varuint |  varuint  |
//! +----------+---------+-------+-----------+---------+-----------+
//! | [nonce, timestamp_ms] (varuints, if FLAG_AUTHENTICATED)      |
//! +--------------------------------------------------------------+
//! | source_agent | target_agent | [budget: max_tok, max_uusd]    |
//! |  compact_str |  compact_str | (if FLAG_HAS_BUDGET)           |
//! +--------------+--------------+--------------------------------+
//! | action(1) | target (cstr) | intent (cstr) | [refs] | payload |
//! +-----------+---------------+---------------+--------+---------+
//! | [HMAC-SHA256 (32 bytes, if FLAG_AUTHENTICATED)]              |
//! +--------------------------------------------------------------+
//! | CRC32 (4 bytes, little-endian, covering all preceding bytes) |
//! +--------------------------------------------------------------+
//! ```
//!
//! # Security Model
//! - **CRC32** detects accidental transport corruption only; it provides **no** authenticity.
//! - **HMAC-SHA256** (`sign_frame` / `verify_and_decode_frame`) authenticates the entire
//!   canonical wire header, nonce, timestamp, and AST body with constant-time tag verification.
//! - **`FrameHeader::mac_verified`** is a local runtime proof bit that is **never** serialized
//!   on the wire: `decode_frame` always sets it to `false`, and only `verify_and_decode_frame`
//!   sets it to `true` after cryptographic verification succeeds.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::ast::{AgentAction, AstNode, AstValue};

type HmacSha256 = Hmac<Sha256>;

/// 4-byte protocol magic header (`AW01`).
pub const MAGIC_BYTES: [u8; 4] = *b"AW01";

/// Current binary wire protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Length in bytes of an HMAC-SHA256 authentication tag.
pub const HMAC_TAG_LEN: usize = 32;

/// Length in bytes of an Ed25519 private seed or public key.
pub const ED25519_KEY_LEN: usize = 32;

/// Length in bytes of an Ed25519 detached signature.
pub const ED25519_SIG_LEN: usize = 64;

/// Maximum AST nesting depth accepted by the decoder to prevent stack exhaustion attacks.
const MAX_NESTING_DEPTH: usize = 32;

/// Maximum collection element count allowed in a single decoded list/map/ref array to
/// bound memory allocation against adversarial frames.
const MAX_COLLECTION_ITEMS: usize = 4096;

/// Static 1-byte dictionary (up to 127 entries: indices `0..=126` encoded as `0x80 | idx`).
pub const STATIC_DICT: &[&str] = &[
    // Agent roles (0..11)
    "planner",
    "researcher",
    "coder",
    "reviewer",
    "executor",
    "coordinator",
    "architect",
    "tester",
    "verifier",
    "router",
    "orchestrator",
    "supervisor",
    // Common operations & intents (12..35)
    "tool_call",
    "memory_lookup",
    "context_handshake",
    "fetch_delta",
    "analyze_schema",
    "apply_patch",
    "verify_tests",
    "review_diff",
    "plan_steps",
    "search_docs",
    "query_records",
    "run_checks",
    "delegate_task",
    "yield_result",
    "assert_invariant",
    "fetch",
    "search",
    "analyze",
    "implement",
    "review",
    "verify",
    "update",
    "create",
    "delete",
    // Common payload keys (36..95)
    "id",
    "user_id",
    "task_id",
    "session_id",
    "trace_id",
    "status",
    "result",
    "error",
    "summary",
    "files",
    "file",
    "path",
    "line",
    "diff",
    "patch",
    "tests",
    "passed",
    "failed",
    "task",
    "goal",
    "priority",
    "limit",
    "offset",
    "filter",
    "query",
    "table",
    "schema",
    "delta",
    "confidence",
    "approved",
    "comments",
    "language",
    "module",
    "depth",
    "scope",
    "output",
    "input",
    "metadata",
    "timestamp",
    "context",
    "citations",
    "score",
    "severity",
    "reason",
    "action",
    "target",
    "content",
    "message",
    "role",
    "model",
    "tokens",
    "cost",
    "latency_ms",
    "checksum",
    "version",
    "idempotency_key",
    "dry_run",
    "strict",
    "tags",
    "artifacts",
    // Common targets & values (96..119)
    "postgres",
    "redis",
    "github",
    "repo",
    "workspace",
    "memory",
    "vector_db",
    "ok",
    "true",
    "false",
    "high",
    "medium",
    "low",
    "critical",
    "read_only",
    "read_write",
    "python",
    "rust",
    "typescript",
    "sql",
    "json",
    "approved_by",
    "findings",
    "next_step",
];

// Value type tags in binary payload encoding.
const TAG_NULL: u8 = 0x00;
const TAG_BOOL_FALSE: u8 = 0x01;
const TAG_BOOL_TRUE: u8 = 0x02;
const TAG_INT: u8 = 0x03;
const TAG_FLOAT: u8 = 0x04;
const TAG_STRING: u8 = 0x05;
const TAG_LIST: u8 = 0x06;
const TAG_MAP: u8 = 0x07;
const TAG_REF: u8 = 0x08;

/// Bitmask constants for [`FrameHeader::flags`].
pub struct FrameFlags;

impl FrameFlags {
    /// Static dictionary string compression enabled.
    pub const DICT_COMPRESSED: u8 = 0b0000_0001;
    /// Receiver should emit an explicit acknowledgement frame.
    pub const REQUIRE_ACK: u8 = 0b0000_0010;
    /// Advisory flag set by sender after local guard-gate check (NEVER trusted by receivers
    /// for authorization — receivers always run independent policy validation).
    pub const GUARD_VERIFIED: u8 = 0b0000_0100;
    /// Explicit token/cost budget cap is serialized in the header.
    pub const HAS_BUDGET: u8 = 0b0000_1000;
    /// AST body includes one or more external context references.
    pub const HAS_REFS: u8 = 0b0001_0000;
    /// Frame carries `nonce`, `timestamp_ms`, and a 32-byte HMAC-SHA256 authentication tag.
    pub const AUTHENTICATED: u8 = 0b0010_0000;
    /// Frame carries `nonce`, `timestamp_ms`, and a 64-byte per-agent Ed25519 signature.
    pub const SIGNED_ED25519: u8 = 0b0100_0000;
}

/// Execution budget cap carried in the frame header.
///
/// Costs are tracked in integer micro-USD (`1 USD = 1_000_000 micro_usd`)
/// to guarantee deterministic comparisons with zero floating-point drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetCap {
    pub max_tokens: u32,
    pub max_micro_usd: u64,
}

impl Default for BudgetCap {
    fn default() -> Self {
        Self {
            max_tokens: 2048,
            max_micro_usd: 50_000, // $0.05
        }
    }
}

/// Wire frame routing, tracing, authentication metadata, and budget header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    pub version: u8,
    pub flags: u8,
    pub trace_id: u64,
    pub span_id: u32,
    pub hop_depth: u16,
    /// Per-message replay-protection nonce (serialized when `FLAG_AUTHENTICATED` is set).
    #[serde(default)]
    pub nonce: u64,
    /// Sender wall-clock timestamp in Unix milliseconds (serialized when `FLAG_AUTHENTICATED` is set).
    #[serde(default)]
    pub timestamp_ms: u64,
    pub source_agent: String,
    pub target_agent: String,
    pub budget: BudgetCap,
    /// Local runtime verification state: **never** serialized on wire. Only `true` when
    /// returned by [`verify_and_decode_frame`] after constant-time HMAC-SHA256 verification.
    #[serde(default)]
    pub mac_verified: bool,
}

impl FrameHeader {
    /// Create a default v1 header between two agents with dictionary compression enabled.
    pub fn new(
        source_agent: impl Into<String>,
        target_agent: impl Into<String>,
        trace_id: u64,
        span_id: u32,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            flags: FrameFlags::DICT_COMPRESSED | FrameFlags::HAS_BUDGET,
            trace_id,
            span_id,
            hop_depth: 0,
            nonce: 0,
            timestamp_ms: 0,
            source_agent: source_agent.into(),
            target_agent: target_agent.into(),
            budget: BudgetCap::default(),
            mac_verified: false,
        }
    }
}

/// Complete binary-serializable AgentWire frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireFrame {
    pub header: FrameHeader,
    pub body: AstNode,
}

impl WireFrame {
    /// Construct a new [`WireFrame`] with header flags synchronized to its body.
    pub fn new(mut header: FrameHeader, body: AstNode) -> Self {
        if !body.refs.is_empty() {
            header.flags |= FrameFlags::HAS_REFS;
        } else {
            header.flags &= !FrameFlags::HAS_REFS;
        }
        Self { header, body }
    }
}

/// Errors produced during binary wire encoding, decoding, or cryptographic verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("invalid magic bytes: expected 'AW01'")]
    InvalidMagic,

    #[error("unsupported protocol version: {0} (expected {PROTOCOL_VERSION})")]
    UnsupportedVersion(u8),

    #[error("CRC32 checksum mismatch: expected 0x{expected:08x}, computed 0x{actual:08x}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    #[error("unexpected end of wire frame buffer")]
    UnexpectedEof,

    #[error("invalid AST value tag: 0x{0:02x}")]
    InvalidTag(u8),

    #[error("invalid AgentAction opcode: 0x{0:02x}")]
    InvalidAction(u8),

    #[error("invalid AgentAction name: '{0}'")]
    InvalidActionName(String),

    #[error("invalid static dictionary index: {0}")]
    InvalidDictIndex(u8),

    #[error("invalid UTF-8 string in wire frame")]
    InvalidUtf8,

    #[error("malformed varint encoding (overflow)")]
    InvalidVarint,

    #[error("trailing unread bytes at end of frame: {0} byte(s)")]
    TrailingBytes(usize),

    #[error("maximum AST nesting depth ({MAX_NESTING_DEPTH}) exceeded")]
    MaxNestingExceeded,

    #[error("collection length {0} exceeds protocol safety limit ({MAX_COLLECTION_ITEMS})")]
    CollectionLimitExceeded(usize),

    #[error("signing key must be non-empty")]
    InvalidKey,

    #[error("frame is not cryptographically authenticated (missing HMAC or Ed25519 flag)")]
    UnauthenticatedFrame,

    #[error("cryptographic authentication failed (tampered payload, wrong key, or forged identity)")]
    AuthenticationFailed,

    #[error("unknown signer identity '{0}': no Ed25519 public key registered")]
    UnknownSigner(String),

    #[error("mutually exclusive auth flags set (both HMAC and Ed25519)")]
    ConflictingAuthFlags,

    #[error("OS CSPRNG failure while generating Ed25519 keypair")]
    RngError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    Unsigned,
    HmacSha256,
    Ed25519,
}

/// Generate a fresh 32-byte Ed25519 `(private_key, public_key)` pair using the OS CSPRNG.
pub fn generate_ed25519_keypair() -> Result<([u8; ED25519_KEY_LEN], [u8; ED25519_KEY_LEN]), WireError> {
    let mut seed = [0u8; ED25519_KEY_LEN];
    getrandom::getrandom(&mut seed).map_err(|_| WireError::RngError)?;
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    Ok((signing.to_bytes(), verifying.to_bytes()))
}

/// Internal encoder returning frame bytes up to the end of the AST body (before MAC/sig & CRC32).
fn encode_body_prefix(frame: &WireFrame, auth_mode: AuthMode) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::with_capacity(160);

    // Synchronize dynamic header flags.
    let mut flags = frame.header.flags | FrameFlags::DICT_COMPRESSED;
    if frame.header.budget.max_tokens > 0 || frame.header.budget.max_micro_usd > 0 {
        flags |= FrameFlags::HAS_BUDGET;
    } else {
        flags &= !FrameFlags::HAS_BUDGET;
    }
    if !frame.body.refs.is_empty() {
        flags |= FrameFlags::HAS_REFS;
    } else {
        flags &= !FrameFlags::HAS_REFS;
    }
    flags &= !(FrameFlags::AUTHENTICATED | FrameFlags::SIGNED_ED25519);
    match auth_mode {
        AuthMode::Unsigned => {}
        AuthMode::HmacSha256 => flags |= FrameFlags::AUTHENTICATED,
        AuthMode::Ed25519 => flags |= FrameFlags::SIGNED_ED25519,
    }

    // 1. Fixed prefix: Magic + Version + Flags
    buf.extend_from_slice(&MAGIC_BYTES);
    buf.push(frame.header.version);
    buf.push(flags);

    // 2. Varint trace/span/hop identifiers
    write_varuint(&mut buf, frame.header.trace_id);
    write_varuint(&mut buf, frame.header.span_id as u64);
    write_varuint(&mut buf, frame.header.hop_depth as u64);

    // 2b. Authentication replay/freshness metadata
    if auth_mode != AuthMode::Unsigned {
        write_varuint(&mut buf, frame.header.nonce);
        write_varuint(&mut buf, frame.header.timestamp_ms);
    }

    // 3. Routing endpoints (1-byte encoded when in STATIC_DICT)
    let use_dict = (flags & FrameFlags::DICT_COMPRESSED) != 0;
    write_compact_str(&mut buf, &frame.header.source_agent, use_dict);
    write_compact_str(&mut buf, &frame.header.target_agent, use_dict);

    // 4. Optional BudgetCap
    if (flags & FrameFlags::HAS_BUDGET) != 0 {
        write_varuint(&mut buf, frame.header.budget.max_tokens as u64);
        write_varuint(&mut buf, frame.header.budget.max_micro_usd);
    }

    // 5. AST Body
    buf.push(frame.body.action.as_code());
    write_compact_str(&mut buf, &frame.body.target, use_dict);
    write_compact_str(&mut buf, &frame.body.intent, use_dict);

    if (flags & FrameFlags::HAS_REFS) != 0 {
        write_varuint(&mut buf, frame.body.refs.len() as u64);
        for reference in &frame.body.refs {
            write_compact_str(&mut buf, reference, use_dict);
        }
    }

    write_varuint(&mut buf, frame.body.payload.len() as u64);
    for (key, value) in &frame.body.payload {
        write_compact_str(&mut buf, key, use_dict);
        write_ast_value(&mut buf, value, use_dict, 0)?;
    }

    Ok(buf)
}

/// Encode an unsigned [`WireFrame`] into its compact binary representation with a trailing CRC32 checksum.
pub fn encode_frame(frame: &WireFrame) -> Result<Vec<u8>, WireError> {
    let mut buf = encode_body_prefix(frame, AuthMode::Unsigned)?;
    let crc = crc32fast::hash(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());
    Ok(buf)
}

/// Encode and cryptographically sign a [`WireFrame`] using HMAC-SHA256 over the full canonical
/// wire frame (magic, version, flags, trace/span/hop, nonce, timestamp, endpoints, budget, and AST).
pub fn sign_frame(frame: &WireFrame, key: &[u8]) -> Result<Vec<u8>, WireError> {
    if key.is_empty() {
        return Err(WireError::InvalidKey);
    }
    let mut buf = encode_body_prefix(frame, AuthMode::HmacSha256)?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| WireError::InvalidKey)?;
    mac.update(&buf);
    let tag = mac.finalize().into_bytes();
    buf.extend_from_slice(&tag);

    let crc = crc32fast::hash(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());
    Ok(buf)
}

/// Encode and asymmetrically sign a [`WireFrame`] using the sender's 32-byte Ed25519 private key.
///
/// Unlike shared-secret HMAC, each agent holds its own Ed25519 private key while receivers hold
/// only public keys (`source_agent -> [u8; 32]`), preventing any compromised peer from
/// impersonating another agent's `source_agent` identity.
pub fn sign_frame_ed25519(frame: &WireFrame, private_key: &[u8]) -> Result<Vec<u8>, WireError> {
    let key_bytes: [u8; ED25519_KEY_LEN] = private_key
        .try_into()
        .map_err(|_| WireError::InvalidKey)?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let mut buf = encode_body_prefix(frame, AuthMode::Ed25519)?;
    let sig = signing_key.sign(&buf);
    buf.extend_from_slice(&sig.to_bytes());

    let crc = crc32fast::hash(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());
    Ok(buf)
}

enum VerifyMode<'a> {
    None,
    Hmac(&'a [u8]),
    Ed25519(&'a BTreeMap<String, [u8; ED25519_KEY_LEN]>),
}

/// Internal decoder supporting optional mandatory HMAC-SHA256 or per-agent Ed25519 verification.
fn decode_frame_internal(bytes: &[u8], verify_mode: VerifyMode<'_>) -> Result<WireFrame, WireError> {
    if bytes.len() < 10 {
        return Err(WireError::UnexpectedEof);
    }
    if bytes[0..4] != MAGIC_BYTES {
        return Err(WireError::InvalidMagic);
    }

    let crc_start = bytes.len() - 4;
    let expected_crc = u32::from_le_bytes([
        bytes[crc_start],
        bytes[crc_start + 1],
        bytes[crc_start + 2],
        bytes[crc_start + 3],
    ]);
    let actual_crc = crc32fast::hash(&bytes[..crc_start]);
    if expected_crc != actual_crc {
        return Err(WireError::ChecksumMismatch {
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    let version = bytes[4];
    if version != PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }

    let flags = bytes[5];
    let has_hmac = (flags & FrameFlags::AUTHENTICATED) != 0;
    let has_ed25519 = (flags & FrameFlags::SIGNED_ED25519) != 0;
    if has_hmac && has_ed25519 {
        return Err(WireError::ConflictingAuthFlags);
    }

    let has_auth_fields = has_hmac || has_ed25519;

    let (body_end, mut mac_verified, ed25519_sig_slice) = if has_hmac {
        if crc_start < 6 + HMAC_TAG_LEN {
            return Err(WireError::UnexpectedEof);
        }
        let mac_start = crc_start - HMAC_TAG_LEN;
        let tag_slice = &bytes[mac_start..crc_start];
        match verify_mode {
            VerifyMode::Hmac(key) => {
                if key.is_empty() {
                    return Err(WireError::InvalidKey);
                }
                let mut mac = HmacSha256::new_from_slice(key).map_err(|_| WireError::InvalidKey)?;
                mac.update(&bytes[..mac_start]);
                mac.verify_slice(tag_slice)
                    .map_err(|_| WireError::AuthenticationFailed)?;
                (mac_start, true, None)
            }
            VerifyMode::Ed25519(_) => return Err(WireError::UnauthenticatedFrame),
            VerifyMode::None => (mac_start, false, None),
        }
    } else if has_ed25519 {
        if crc_start < 6 + ED25519_SIG_LEN {
            return Err(WireError::UnexpectedEof);
        }
        let sig_start = crc_start - ED25519_SIG_LEN;
        let sig_slice = &bytes[sig_start..crc_start];
        match verify_mode {
            VerifyMode::Hmac(_) => return Err(WireError::UnauthenticatedFrame),
            VerifyMode::Ed25519(_) => (sig_start, false, Some((sig_start, sig_slice))),
            VerifyMode::None => (sig_start, false, None),
        }
    } else {
        match verify_mode {
            VerifyMode::None => (crc_start, false, None),
            VerifyMode::Hmac(_) | VerifyMode::Ed25519(_) => {
                return Err(WireError::UnauthenticatedFrame)
            }
        }
    };

    let use_dict = (flags & FrameFlags::DICT_COMPRESSED) != 0;
    let mut cursor = Cursor::new(&bytes[6..body_end]);

    let trace_id = cursor.read_varuint()?;
    let span_id = u32::try_from(cursor.read_varuint()?).map_err(|_| WireError::InvalidVarint)?;
    let hop_depth = u16::try_from(cursor.read_varuint()?).map_err(|_| WireError::InvalidVarint)?;

    let (nonce, timestamp_ms) = if has_auth_fields {
        (cursor.read_varuint()?, cursor.read_varuint()?)
    } else {
        (0, 0)
    };

    let source_agent = cursor.read_compact_str(use_dict)?;
    let target_agent = cursor.read_compact_str(use_dict)?;

    // Verify per-agent Ed25519 signature bound strictly to `source_agent`'s registered public key!
    if let (VerifyMode::Ed25519(registry), Some((sig_start, sig_slice))) =
        (verify_mode, ed25519_sig_slice)
    {
        let pub_bytes = registry
            .get(&source_agent)
            .ok_or_else(|| WireError::UnknownSigner(source_agent.clone()))?;
        let verifying_key =
            VerifyingKey::from_bytes(pub_bytes).map_err(|_| WireError::InvalidKey)?;
        let sig_arr: [u8; ED25519_SIG_LEN] = sig_slice
            .try_into()
            .map_err(|_| WireError::AuthenticationFailed)?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&bytes[..sig_start], &sig)
            .map_err(|_| WireError::AuthenticationFailed)?;
        mac_verified = true;
    }

    let budget = if (flags & FrameFlags::HAS_BUDGET) != 0 {
        let max_tokens =
            u32::try_from(cursor.read_varuint()?).map_err(|_| WireError::InvalidVarint)?;
        let max_micro_usd = cursor.read_varuint()?;
        BudgetCap {
            max_tokens,
            max_micro_usd,
        }
    } else {
        BudgetCap {
            max_tokens: 0,
            max_micro_usd: 0,
        }
    };

    let action = AgentAction::from_code(cursor.read_u8()?)?;
    let target = cursor.read_compact_str(use_dict)?;
    let intent = cursor.read_compact_str(use_dict)?;

    let mut refs = Vec::new();
    if (flags & FrameFlags::HAS_REFS) != 0 {
        let ref_count_u64 = cursor.read_varuint()?;
        let ref_count = usize::try_from(ref_count_u64).map_err(|_| WireError::InvalidVarint)?;
        if ref_count > MAX_COLLECTION_ITEMS {
            return Err(WireError::CollectionLimitExceeded(ref_count));
        }
        refs.reserve(ref_count.min(64));
        for _ in 0..ref_count {
            refs.push(cursor.read_compact_str(use_dict)?);
        }
    }

    let payload_len_u64 = cursor.read_varuint()?;
    let payload_len = usize::try_from(payload_len_u64).map_err(|_| WireError::InvalidVarint)?;
    if payload_len > MAX_COLLECTION_ITEMS {
        return Err(WireError::CollectionLimitExceeded(payload_len));
    }
    let mut payload = BTreeMap::new();
    for _ in 0..payload_len {
        let key = cursor.read_compact_str(use_dict)?;
        let val = cursor.read_ast_value(use_dict, 0)?;
        payload.insert(key, val);
    }

    if cursor.remaining() != 0 {
        return Err(WireError::TrailingBytes(cursor.remaining()));
    }

    Ok(WireFrame {
        header: FrameHeader {
            version,
            flags,
            trace_id,
            span_id,
            hop_depth,
            nonce,
            timestamp_ms,
            source_agent,
            target_agent,
            budget,
            mac_verified,
        },
        body: AstNode {
            action,
            target,
            intent,
            payload,
            refs,
        },
    })
}

/// Decode and CRC32-check a binary AgentWire frame without verifying cryptographic MAC/signature.
///
/// Always returns `header.mac_verified == false`.
pub fn decode_frame(bytes: &[u8]) -> Result<WireFrame, WireError> {
    decode_frame_internal(bytes, VerifyMode::None)
}

/// Cryptographically verify the HMAC-SHA256 tag (constant-time) and decode a signed AgentWire frame.
pub fn verify_and_decode_frame(bytes: &[u8], key: &[u8]) -> Result<WireFrame, WireError> {
    decode_frame_internal(bytes, VerifyMode::Hmac(key))
}

/// Cryptographically verify an Ed25519 signature against the sender's registered public key
/// (`pubkeys[frame.header.source_agent]`) and decode the frame (`header.mac_verified == true`).
pub fn verify_and_decode_ed25519(
    bytes: &[u8],
    pubkeys: &BTreeMap<String, [u8; ED25519_KEY_LEN]>,
) -> Result<WireFrame, WireError> {
    decode_frame_internal(bytes, VerifyMode::Ed25519(pubkeys))
}

#[inline]
fn dict_lookup(s: &str) -> Option<u8> {
    STATIC_DICT
        .iter()
        .position(|&entry| entry == s)
        .and_then(|idx| if idx < 127 { Some(idx as u8) } else { None })
}

#[inline]
fn write_varuint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[inline]
fn write_varsint(buf: &mut Vec<u8>, value: i64) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    write_varuint(buf, zigzag);
}

fn write_compact_str(buf: &mut Vec<u8>, s: &str, use_dict: bool) {
    if use_dict {
        if let Some(idx) = dict_lookup(s) {
            buf.push(0x80 | idx);
            return;
        }
    }
    let raw = s.as_bytes();
    if raw.len() <= 127 {
        buf.push(raw.len() as u8);
    } else {
        buf.push(0xFF);
        write_varuint(buf, raw.len() as u64);
    }
    buf.extend_from_slice(raw);
}

fn write_ast_value(
    buf: &mut Vec<u8>,
    value: &AstValue,
    use_dict: bool,
    depth: usize,
) -> Result<(), WireError> {
    if depth >= MAX_NESTING_DEPTH {
        return Err(WireError::MaxNestingExceeded);
    }
    match value {
        AstValue::Null => buf.push(TAG_NULL),
        AstValue::Bool(false) => buf.push(TAG_BOOL_FALSE),
        AstValue::Bool(true) => buf.push(TAG_BOOL_TRUE),
        AstValue::Int(i) => {
            buf.push(TAG_INT);
            write_varsint(buf, *i);
        }
        AstValue::Float(f) => {
            buf.push(TAG_FLOAT);
            buf.extend_from_slice(&f.to_le_bytes());
        }
        AstValue::String(s) => {
            buf.push(TAG_STRING);
            write_compact_str(buf, s, use_dict);
        }
        AstValue::List(items) => {
            buf.push(TAG_LIST);
            write_varuint(buf, items.len() as u64);
            for item in items {
                write_ast_value(buf, item, use_dict, depth + 1)?;
            }
        }
        AstValue::Map(map) => {
            buf.push(TAG_MAP);
            write_varuint(buf, map.len() as u64);
            for (k, v) in map {
                write_compact_str(buf, k, use_dict);
                write_ast_value(buf, v, use_dict, depth + 1)?;
            }
        }
        AstValue::Ref(uri) => {
            buf.push(TAG_REF);
            write_compact_str(buf, uri, use_dict);
        }
    }
    Ok(())
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, WireError> {
        if self.pos >= self.data.len() {
            return Err(WireError::UnexpectedEof);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(len).ok_or(WireError::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(WireError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_varuint(&mut self) -> Result<u64, WireError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.read_u8()?;
            if shift >= 64 || (shift == 63 && (byte & 0x7F) > 1) {
                return Err(WireError::InvalidVarint);
            }
            result |= ((byte & 0x7F) as u64) << shift;
            if (byte & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    fn read_varsint(&mut self) -> Result<i64, WireError> {
        let zigzag = self.read_varuint()?;
        Ok(((zigzag >> 1) as i64) ^ (-((zigzag & 1) as i64)))
    }

    fn read_compact_str(&mut self, use_dict: bool) -> Result<String, WireError> {
        let prefix = self.read_u8()?;
        if (prefix & 0x80) != 0 {
            if prefix == 0xFF {
                let len_u64 = self.read_varuint()?;
                let len = usize::try_from(len_u64).map_err(|_| WireError::InvalidVarint)?;
                let raw = self.read_slice(len)?;
                return std::str::from_utf8(raw)
                    .map(ToOwned::to_owned)
                    .map_err(|_| WireError::InvalidUtf8);
            }
            if !use_dict {
                return Err(WireError::InvalidDictIndex(prefix & 0x7F));
            }
            let idx = (prefix & 0x7F) as usize;
            return STATIC_DICT
                .get(idx)
                .map(|&s| s.to_owned())
                .ok_or(WireError::InvalidDictIndex(idx as u8));
        }
        let len = prefix as usize;
        let raw = self.read_slice(len)?;
        std::str::from_utf8(raw)
            .map(ToOwned::to_owned)
            .map_err(|_| WireError::InvalidUtf8)
    }

    fn read_ast_value(&mut self, use_dict: bool, depth: usize) -> Result<AstValue, WireError> {
        if depth >= MAX_NESTING_DEPTH {
            return Err(WireError::MaxNestingExceeded);
        }
        let tag = self.read_u8()?;
        match tag {
            TAG_NULL => Ok(AstValue::Null),
            TAG_BOOL_FALSE => Ok(AstValue::Bool(false)),
            TAG_BOOL_TRUE => Ok(AstValue::Bool(true)),
            TAG_INT => Ok(AstValue::Int(self.read_varsint()?)),
            TAG_FLOAT => {
                let raw = self.read_slice(8)?;
                let mut arr = [0u8; 8];
                arr.copy_from_slice(raw);
                Ok(AstValue::Float(f64::from_le_bytes(arr)))
            }
            TAG_STRING => Ok(AstValue::String(self.read_compact_str(use_dict)?)),
            TAG_LIST => {
                let len_u64 = self.read_varuint()?;
                let len = usize::try_from(len_u64).map_err(|_| WireError::InvalidVarint)?;
                if len > MAX_COLLECTION_ITEMS {
                    return Err(WireError::CollectionLimitExceeded(len));
                }
                let mut items = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    items.push(self.read_ast_value(use_dict, depth + 1)?);
                }
                Ok(AstValue::List(items))
            }
            TAG_MAP => {
                let len_u64 = self.read_varuint()?;
                let len = usize::try_from(len_u64).map_err(|_| WireError::InvalidVarint)?;
                if len > MAX_COLLECTION_ITEMS {
                    return Err(WireError::CollectionLimitExceeded(len));
                }
                let mut map = BTreeMap::new();
                for _ in 0..len {
                    let k = self.read_compact_str(use_dict)?;
                    let v = self.read_ast_value(use_dict, depth + 1)?;
                    map.insert(k, v);
                }
                Ok(AstValue::Map(map))
            }
            TAG_REF => Ok(AstValue::Ref(self.read_compact_str(use_dict)?)),
            other => Err(WireError::InvalidTag(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn static_dict_fits_in_7bit_index_space() {
        assert!(STATIC_DICT.len() <= 127);
        let mut seen = std::collections::HashSet::new();
        for &entry in STATIC_DICT {
            assert!(seen.insert(entry), "duplicate static dict entry: {entry}");
        }
    }

    #[test]
    fn roundtrip_all_ast_value_types() {
        let mut nested = BTreeMap::new();
        nested.insert("passed".to_string(), AstValue::Bool(true));
        nested.insert("score".to_string(), AstValue::Float(0.985));
        nested.insert(
            "ref_doc".to_string(),
            AstValue::Ref("ctx://session/42".to_string()),
        );

        let long_str = "x".repeat(220);

        let body = AstNode::new(AgentAction::Delegate, "repo:billing", "implement")
            .with_arg("user_id", AstValue::Int(-42_000_000))
            .with_arg("priority", AstValue::String("high".to_string()))
            .with_arg("null_field", AstValue::Null)
            .with_arg("dry_run", AstValue::Bool(false))
            .with_arg("long_note", AstValue::String(long_str))
            .with_arg(
                "files",
                AstValue::List(vec![
                    AstValue::String("src/lib.rs".to_string()),
                    AstValue::Int(128),
                ]),
            )
            .with_arg("metadata", AstValue::Map(nested))
            .with_ref("mem:plan_v2");

        let mut header = FrameHeader::new("planner", "coder", 987_654_321, 7);
        header.hop_depth = 2;
        header.budget = BudgetCap {
            max_tokens: 1500,
            max_micro_usd: 12_500,
        };
        let frame = WireFrame::new(header, body);

        let encoded = encode_frame(&frame).expect("encode should succeed");
        assert_eq!(&encoded[0..4], &MAGIC_BYTES);

        let decoded = decode_frame(&encoded).expect("decode should succeed");
        assert_eq!(decoded, frame);
        assert!(!decoded.header.mac_verified);
    }

    #[test]
    fn sign_and_verify_hmac_sha256_frame() {
        let key = b"super-secret-agentwire-hmac-key-32b";
        let wrong_key = b"wrong-secret-agentwire-hmac-key-32b";

        let mut header = FrameHeader::new("planner", "coder", 55, 9);
        header.nonce = 0xDEADBEEF_12345678;
        header.timestamp_ms = 1_763_900_000_000;
        let body = AstNode::new(AgentAction::Delegate, "repo:core", "apply_patch")
            .with_arg("file", AstValue::String("src/main.rs".to_string()));
        let frame = WireFrame::new(header, body);

        let signed = sign_frame(&frame, key).expect("sign should succeed");

        // Unverified decode sees mac_verified == false
        let unverified = decode_frame(&signed).expect("unverified decode should succeed");
        assert!(!unverified.header.mac_verified);
        assert_eq!(unverified.header.nonce, 0xDEADBEEF_12345678);

        // Verified decode sets mac_verified == true
        let verified = verify_and_decode_frame(&signed, key).expect("verify should succeed");
        assert!(verified.header.mac_verified);
        assert_eq!(verified.body, frame.body);
        assert_eq!(verified.header.nonce, frame.header.nonce);
        assert_eq!(verified.header.timestamp_ms, frame.header.timestamp_ms);

        // Wrong key fails authentication
        assert_eq!(
            verify_and_decode_frame(&signed, wrong_key).unwrap_err(),
            WireError::AuthenticationFailed
        );

        // Unsigned frame rejected by verify_and_decode_frame
        let unsigned = encode_frame(&frame).unwrap();
        assert_eq!(
            verify_and_decode_frame(&unsigned, key).unwrap_err(),
            WireError::UnauthenticatedFrame
        );

        // Forging payload + recomputing CRC32 without key still fails HMAC
        let mut forged = signed.clone();
        forged[12] ^= 0xFF;
        let crc_pos = forged.len() - 4;
        let new_crc = crc32fast::hash(&forged[..crc_pos]);
        forged[crc_pos..].copy_from_slice(&new_crc.to_le_bytes());
        assert_eq!(
            verify_and_decode_frame(&forged, key).unwrap_err(),
            WireError::AuthenticationFailed
        );
    }

    #[test]
    fn ed25519_per_agent_identity_blocks_impersonation() {
        let (planner_priv, planner_pub) = generate_ed25519_keypair().unwrap();
        let (researcher_priv, researcher_pub) = generate_ed25519_keypair().unwrap();

        let mut pubkeys = BTreeMap::new();
        pubkeys.insert("planner".to_string(), planner_pub);
        pubkeys.insert("researcher".to_string(), researcher_pub);

        let mut header = FrameHeader::new("planner", "coder", 77, 1);
        header.nonce = 44001;
        header.timestamp_ms = 1_763_900_000_000;
        let body = AstNode::new(AgentAction::Delegate, "repo:core", "apply_patch");
        let frame = WireFrame::new(header, body);

        // Legitimate planner signature verifies cleanly
        let signed_by_planner = sign_frame_ed25519(&frame, &planner_priv).unwrap();
        let verified = verify_and_decode_ed25519(&signed_by_planner, &pubkeys).unwrap();
        assert!(verified.header.mac_verified);
        assert_eq!(verified.header.source_agent, "planner");

        // Compromised researcher tries to impersonate `planner` using researcher's own private key -> REJECTED!
        let impersonation = sign_frame_ed25519(&frame, &researcher_priv).unwrap();
        assert_eq!(
            verify_and_decode_ed25519(&impersonation, &pubkeys).unwrap_err(),
            WireError::AuthenticationFailed
        );

        // Unregistered agent rejected with UnknownSigner
        let mut unknown_hdr = FrameHeader::new("rogue_agent", "coder", 77, 2);
        unknown_hdr.nonce = 44002;
        unknown_hdr.timestamp_ms = 1_763_900_000_000;
        let unknown_frame = sign_frame_ed25519(
            &WireFrame::new(unknown_hdr, AstNode::new(AgentAction::Query, "docs:a", "search")),
            &researcher_priv,
        )
        .unwrap();
        assert_eq!(
            verify_and_decode_ed25519(&unknown_frame, &pubkeys).unwrap_err(),
            WireError::UnknownSigner("rogue_agent".to_string())
        );
    }

    #[test]
    fn detects_corrupted_crc32() {
        let header = FrameHeader::new("planner", "researcher", 1, 1);
        let body = AstNode::new(AgentAction::Query, "postgres.users", "fetch_delta")
            .with_arg("user_id", AstValue::Int(123));
        let frame = WireFrame::new(header, body);

        let mut encoded = encode_frame(&frame).unwrap();
        let mid = encoded.len() / 2;
        encoded[mid] ^= 0x01;

        let err = decode_frame(&encoded).unwrap_err();
        assert!(matches!(err, WireError::ChecksumMismatch { .. }));
    }

    #[test]
    fn rejects_invalid_magic_and_short_buffers() {
        assert_eq!(decode_frame(b"AW01").unwrap_err(), WireError::UnexpectedEof);
        assert_eq!(
            decode_frame(b"NOPE0123456789").unwrap_err(),
            WireError::InvalidMagic
        );
    }

    // --- Property-based & fuzz robustness tests via proptest ---

    fn arb_action() -> impl Strategy<Value = AgentAction> {
        prop_oneof![
            Just(AgentAction::Query),
            Just(AgentAction::Mutate),
            Just(AgentAction::Delegate),
            Just(AgentAction::Yield),
            Just(AgentAction::Assert),
        ]
    }

    fn arb_ast_value() -> impl Strategy<Value = AstValue> {
        let leaf = prop_oneof![
            Just(AstValue::Null),
            any::<bool>().prop_map(AstValue::Bool),
            any::<i64>().prop_map(AstValue::Int),
            // Avoid NaN since NaN != NaN under PartialEq
            (-1e12f64..1e12f64).prop_map(AstValue::Float),
            ".{0,48}".prop_map(AstValue::String),
            "[a-z]{2,8}://[a-z0-9/_-]{1,24}".prop_map(AstValue::Ref),
        ];
        leaf.prop_recursive(3, 16, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(AstValue::List),
                prop::collection::btree_map("[a-z_]{1,12}", inner, 0..4).prop_map(AstValue::Map),
            ]
        })
    }

    proptest! {
        #[test]
        fn prop_unsigned_and_signed_roundtrip(
            action in arb_action(),
            source in "[a-z_]{1,16}",
            target_agent in "[a-z_]{1,16}",
            res_target in "[a-z0-9:._-]{1,24}",
            intent in "[a-z_]{1,24}",
            trace_id in any::<u64>(),
            span_id in any::<u32>(),
            hop_depth in 0u16..32,
            nonce in 1u64..u64::MAX,
            timestamp_ms in 1u64..2_000_000_000_000u64,
            max_tokens in 1u32..100_000,
            max_micro_usd in 1u64..10_000_000,
            payload in prop::collection::btree_map("[a-z_]{1,12}", arb_ast_value(), 0..6),
            refs in prop::collection::vec("[a-z]{2,6}://[a-z0-9/]{1,16}", 0..4),
        ) {
            let mut header = FrameHeader::new(source, target_agent, trace_id, span_id);
            header.hop_depth = hop_depth;
            header.budget = BudgetCap { max_tokens, max_micro_usd };

            let body = AstNode {
                action,
                target: res_target,
                intent,
                payload,
                refs,
            };
            let unsigned_frame = WireFrame::new(header.clone(), body.clone());
            let encoded = encode_frame(&unsigned_frame).unwrap();
            let decoded = decode_frame(&encoded).unwrap();
            prop_assert_eq!(decoded, unsigned_frame);

            // Authenticated roundtrip
            let mut auth_header = header;
            auth_header.nonce = nonce;
            auth_header.timestamp_ms = timestamp_ms;
            let auth_frame = WireFrame::new(auth_header, body);
            let key = b"proptest-hmac-key-0123456789";
            let signed = sign_frame(&auth_frame, key).unwrap();
            let verified = verify_and_decode_frame(&signed, key).unwrap();
            prop_assert!(verified.header.mac_verified);
            prop_assert_eq!(verified.body, auth_frame.body);
            prop_assert_eq!(verified.header.nonce, nonce);
            prop_assert_eq!(verified.header.timestamp_ms, timestamp_ms);
        }

        #[test]
        fn prop_arbitrary_bytes_never_panic_decoder(raw in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode_frame(&raw);
            let _ = verify_and_decode_frame(&raw, b"fuzz-key");
        }
    }
}
