//! Binary wire frame codec for AgentWire (`AW01`).
//!
//! # Wire Layout
//!
//! ```text
//! +----------+---------+-------+-----------+---------+-----------+
//! | Magic(4) | Ver (1) | Flg(1)| trace_id  | span_id | hop_depth |
//! |  "AW01"  |   0x01  |  u8   |  varuint  | varuint |  varuint  |
//! +----------+---------+-------+-----------+---------+-----------+
//! | source_agent | target_agent | [budget: max_tok, max_uusd]    |
//! |  compact_str |  compact_str | (if FLAG_HAS_BUDGET)           |
//! +--------------+--------------+--------------------------------+
//! | action(1) | target (cstr) | intent (cstr) | [refs] | payload |
//! +-----------+---------------+---------------+--------+---------+
//! | CRC32 (4 bytes, little-endian, covering all preceding bytes) |
//! +--------------------------------------------------------------+
//! ```
//!
//! Common multi-agent keys, roles, and operations are indexed in [`STATIC_DICT`] and
//! encoded as a single byte (`0x80..=0xFE`), eliminating JSON punctuation and key repetition.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ast::{AgentAction, AstNode, AstValue};

/// 4-byte protocol magic header (`AW01`).
pub const MAGIC_BYTES: [u8; 4] = *b"AW01";

/// Current binary wire protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum AST nesting depth accepted by the decoder to prevent stack exhaustion attacks.
const MAX_NESTING_DEPTH: usize = 32;

/// Static 1-byte dictionary (up to 127 entries: indices `0..=126` encoded as `0x80 | idx`).
///
/// Entries are chosen from high-frequency multi-agent RPC terms (roles, actions, payload keys,
/// tool namespaces, and verification attributes).
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
    /// Frame has passed deterministic `agentwire-validator` policy checks.
    pub const GUARD_VERIFIED: u8 = 0b0000_0100;
    /// Explicit token/cost budget cap is serialized in the header.
    pub const HAS_BUDGET: u8 = 0b0000_1000;
    /// AST body includes one or more external context references.
    pub const HAS_REFS: u8 = 0b0001_0000;
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

/// Wire frame routing, tracing, and budget header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameHeader {
    pub version: u8,
    pub flags: u8,
    pub trace_id: u64,
    pub span_id: u32,
    pub hop_depth: u16,
    pub source_agent: String,
    pub target_agent: String,
    pub budget: BudgetCap,
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
            source_agent: source_agent.into(),
            target_agent: target_agent.into(),
            budget: BudgetCap::default(),
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

/// Errors produced during binary wire encoding or decoding.
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
}

/// Encode a [`WireFrame`] into its compact binary representation with a trailing CRC32 checksum.
pub fn encode_frame(frame: &WireFrame) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::with_capacity(128);

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

    // 1. Fixed prefix: Magic + Version + Flags
    buf.extend_from_slice(&MAGIC_BYTES);
    buf.push(frame.header.version);
    buf.push(flags);

    // 2. Varint trace/span/hop identifiers
    write_varuint(&mut buf, frame.header.trace_id);
    write_varuint(&mut buf, frame.header.span_id as u64);
    write_varuint(&mut buf, frame.header.hop_depth as u64);

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

    // 6. Trailing CRC32 integrity checksum (IEEE / Castagnoli-compatible crc32fast)
    let crc = crc32fast::hash(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());

    Ok(buf)
}

/// Decode and integrity-check a binary AgentWire frame.
pub fn decode_frame(bytes: &[u8]) -> Result<WireFrame, WireError> {
    // Minimum frame: 4 magic + 1 version + 1 flags + 4 crc32 = 10 bytes.
    if bytes.len() < 10 {
        return Err(WireError::UnexpectedEof);
    }

    // Verify magic bytes first.
    if bytes[0..4] != MAGIC_BYTES {
        return Err(WireError::InvalidMagic);
    }

    // Verify trailing CRC32 over all preceding bytes before parsing payload.
    let body_end = bytes.len() - 4;
    let expected_crc = u32::from_le_bytes([
        bytes[body_end],
        bytes[body_end + 1],
        bytes[body_end + 2],
        bytes[body_end + 3],
    ]);
    let actual_crc = crc32fast::hash(&bytes[..body_end]);
    if expected_crc != actual_crc {
        return Err(WireError::ChecksumMismatch {
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    let mut cursor = Cursor::new(&bytes[4..body_end]);

    let version = cursor.read_u8()?;
    if version != PROTOCOL_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }

    let flags = cursor.read_u8()?;
    let use_dict = (flags & FrameFlags::DICT_COMPRESSED) != 0;

    let trace_id = cursor.read_varuint()?;
    let span_id = u32::try_from(cursor.read_varuint()?).map_err(|_| WireError::InvalidVarint)?;
    let hop_depth = u16::try_from(cursor.read_varuint()?).map_err(|_| WireError::InvalidVarint)?;

    let source_agent = cursor.read_compact_str(use_dict)?;
    let target_agent = cursor.read_compact_str(use_dict)?;

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
        let ref_count = cursor.read_varuint()? as usize;
        refs.reserve(ref_count.min(64));
        for _ in 0..ref_count {
            refs.push(cursor.read_compact_str(use_dict)?);
        }
    }

    let payload_len = cursor.read_varuint()? as usize;
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
            source_agent,
            target_agent,
            budget,
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

/// Lookup an index in [`STATIC_DICT`] (max 127 entries: `0..=126`).
#[inline]
fn dict_lookup(s: &str) -> Option<u8> {
    STATIC_DICT
        .iter()
        .position(|&entry| entry == s)
        .and_then(|idx| if idx < 127 { Some(idx as u8) } else { None })
}

/// Write an unsigned LEB128 varint.
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

/// Write a signed ZigZag LEB128 varint.
#[inline]
fn write_varsint(buf: &mut Vec<u8>, value: i64) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    write_varuint(buf, zigzag);
}

/// Write a prefix-free compact string:
/// - `0x80..=0xFE`: 1-byte static dictionary token (`index = byte & 0x7F`)
/// - `0x00..=0x7F`: short literal string of length `0..=127` followed by raw UTF-8 bytes
/// - `0xFF`: long literal string followed by `varuint(len)` and raw UTF-8 bytes
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

/// Zero-copy slice reader for decoding binary frames safely.
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
                let len = self.read_varuint()? as usize;
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
                let len = self.read_varuint()? as usize;
                let mut items = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    items.push(self.read_ast_value(use_dict, depth + 1)?);
                }
                Ok(AstValue::List(items))
            }
            TAG_MAP => {
                let len = self.read_varuint()? as usize;
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

    #[test]
    fn static_dict_fits_in_7bit_index_space() {
        assert!(STATIC_DICT.len() <= 127);
        // Ensure no duplicate keys in STATIC_DICT.
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
        nested.insert("ref_doc".to_string(), AstValue::Ref("ctx://session/42".to_string()));

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
    }

    #[test]
    fn detects_corrupted_crc32() {
        let header = FrameHeader::new("planner", "researcher", 1, 1);
        let body = AstNode::new(AgentAction::Query, "postgres.users", "fetch_delta")
            .with_arg("user_id", AstValue::Int(123));
        let frame = WireFrame::new(header, body);

        let mut encoded = encode_frame(&frame).unwrap();
        // Flip a bit in the payload region
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
}
