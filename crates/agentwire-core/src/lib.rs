//! Core protocol specification, typed AST, binary wire codec, and lossless decompiler
//! for **AgentWire**.

pub mod ast;
pub mod decompiler;
pub mod frame;

pub use ast::{AgentAction, AstNode, AstValue};
pub use decompiler::{decompile_ast, decompile_frame, TraceSummary};
pub use frame::{
    decode_frame, encode_frame, BudgetCap, FrameFlags, FrameHeader, WireError, WireFrame,
    MAGIC_BYTES, PROTOCOL_VERSION, STATIC_DICT,
};
