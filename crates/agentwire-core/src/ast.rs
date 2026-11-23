//! Typed Semantic AST definitions for AgentWire.
//!
//! Instead of transmitting verbose natural-language boilerplate or unvalidated JSON blobs
//! between LLM agents, every inter-agent message is represented as a strictly typed
//! [`AstNode`] built around five canonical [`AgentAction`] primitives.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::frame::WireError;

/// Canonical action primitives supported by the AgentWire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum AgentAction {
    /// Read-only retrieval against a database, tool, index, or agent memory.
    Query = 0x01,
    /// State-changing operation (DB write, file patch, API mutation, external side-effect).
    Mutate = 0x02,
    /// Handoff of a scoped sub-task to another agent with an explicit budget cap.
    Delegate = 0x03,
    /// Structured result emission returning outputs/artifacts to the caller.
    Yield = 0x04,
    /// Deterministic invariant or verification claim checked before committing work.
    Assert = 0x05,
}

impl AgentAction {
    /// Encode action primitive into its 1-byte wire opcode.
    #[inline]
    pub const fn as_code(self) -> u8 {
        self as u8
    }

    /// Decode a 1-byte wire opcode into an [`AgentAction`].
    pub fn from_code(code: u8) -> Result<Self, WireError> {
        match code {
            0x01 => Ok(Self::Query),
            0x02 => Ok(Self::Mutate),
            0x03 => Ok(Self::Delegate),
            0x04 => Ok(Self::Yield),
            0x05 => Ok(Self::Assert),
            other => Err(WireError::InvalidAction(other)),
        }
    }

    /// Canonical uppercase wire name.
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "QUERY",
            Self::Mutate => "MUTATE",
            Self::Delegate => "DELEGATE",
            Self::Yield => "YIELD",
            Self::Assert => "ASSERT",
        }
    }

    /// Parse from case-insensitive string representation.
    pub fn parse_name(name: &str) -> Result<Self, WireError> {
        match name.trim().to_ascii_uppercase().as_str() {
            "QUERY" => Ok(Self::Query),
            "MUTATE" => Ok(Self::Mutate),
            "DELEGATE" => Ok(Self::Delegate),
            "YIELD" => Ok(Self::Yield),
            "ASSERT" => Ok(Self::Assert),
            _ => Err(WireError::InvalidActionName(name.to_string())),
        }
    }

    /// Returns `true` if this action can perform side-effects or state mutation.
    #[inline]
    pub const fn is_mutating(self) -> bool {
        matches!(self, Self::Mutate)
    }
}

impl fmt::Display for AgentAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Strictly typed AST value nodes carried inside an [`AstNode`] payload.
///
/// Using [`BTreeMap`] for [`AstValue::Map`] guarantees canonical key ordering,
/// deterministic binary encoding, and reproducible CRC32 checksums across platforms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum AstValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<AstValue>),
    Map(BTreeMap<String, AstValue>),
    /// Opaque context/artifact pointer (e.g. `ref://ctx/42`, `mem:user_123`) used to avoid
    /// re-transmitting large conversation histories over the wire.
    Ref(String),
}

impl AstValue {
    /// Convert a standard [`serde_json::Value`] into a typed [`AstValue`].
    ///
    /// Convention: an object of exact shape `{"$ref": "<uri>"}` is promoted to
    /// [`AstValue::Ref`], allowing natural interop with JSON/Python callers.
    pub fn from_json(value: &JsonValue) -> Self {
        match value {
            JsonValue::Null => Self::Null,
            JsonValue::Bool(b) => Self::Bool(*b),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::Int(i)
                } else if let Some(u) = n.as_u64() {
                    if u <= i64::MAX as u64 {
                        Self::Int(u as i64)
                    } else {
                        Self::Float(u as f64)
                    }
                } else {
                    Self::Float(n.as_f64().unwrap_or(0.0))
                }
            }
            JsonValue::String(s) => Self::String(s.clone()),
            JsonValue::Array(items) => {
                Self::List(items.iter().map(Self::from_json).collect())
            }
            JsonValue::Object(map) => {
                if map.len() == 1 {
                    if let Some(JsonValue::String(uri)) = map.get("$ref") {
                        return Self::Ref(uri.clone());
                    }
                }
                let mut out = BTreeMap::new();
                for (k, v) in map {
                    out.insert(k.clone(), Self::from_json(v));
                }
                Self::Map(out)
            }
        }
    }

    /// Convert back to a [`serde_json::Value`] for interop with JSON/Python SDKs.
    pub fn to_json(&self) -> JsonValue {
        match self {
            Self::Null => JsonValue::Null,
            Self::Bool(b) => JsonValue::Bool(*b),
            Self::Int(i) => JsonValue::Number((*i).into()),
            Self::Float(f) => serde_json::Number::from_f64(*f)
                .map(JsonValue::Number)
                .unwrap_or(JsonValue::Null),
            Self::String(s) => JsonValue::String(s.clone()),
            Self::List(items) => {
                JsonValue::Array(items.iter().map(Self::to_json).collect())
            }
            Self::Map(map) => {
                let mut obj = serde_json::Map::new();
                for (k, v) in map {
                    obj.insert(k.clone(), v.to_json());
                }
                JsonValue::Object(obj)
            }
            Self::Ref(uri) => {
                let mut obj = serde_json::Map::new();
                obj.insert("$ref".to_string(), JsonValue::String(uri.clone()));
                JsonValue::Object(obj)
            }
        }
    }
}

/// Canonical Semantic AST node describing an inter-agent operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AstNode {
    /// Action primitive (`QUERY`, `MUTATE`, `DELEGATE`, `YIELD`, `ASSERT`).
    pub action: AgentAction,
    /// Structured target resource or capability (e.g., `postgres.users`, `repo:src/auth.rs`).
    pub target: String,
    /// Compact canonical intent identifier (e.g., `fetch_delta`, `apply_patch`, `verify_tests`).
    pub intent: String,
    /// Strictly typed structured arguments.
    pub payload: BTreeMap<String, AstValue>,
    /// Context/memory reference pointers replacing verbose prompt history.
    pub refs: Vec<String>,
}

impl AstNode {
    /// Construct a new [`AstNode`] with empty payload and refs.
    pub fn new(
        action: AgentAction,
        target: impl Into<String>,
        intent: impl Into<String>,
    ) -> Self {
        Self {
            action,
            target: target.into(),
            intent: intent.into(),
            payload: BTreeMap::new(),
            refs: Vec::new(),
        }
    }

    /// Builder method to attach a typed payload field.
    pub fn with_arg(mut self, key: impl Into<String>, value: AstValue) -> Self {
        self.payload.insert(key.into(), value);
        self
    }

    /// Builder method to attach a context reference pointer.
    pub fn with_ref(mut self, reference: impl Into<String>) -> Self {
        self.refs.push(reference.into());
        self
    }
}
