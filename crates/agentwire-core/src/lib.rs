//! Core protocol specification, typed AST, binary wire codec, HMAC-SHA256 frame
//! authentication, and lossless decompiler for **AgentWire**.

pub mod ast;
pub mod decompiler;
pub mod frame;

pub use ast::{AgentAction, AstNode, AstValue};
pub use decompiler::{decompile_ast, decompile_frame, TraceSummary};
pub use frame::{
    decode_frame, encode_frame, sign_frame, verify_and_decode_frame, BudgetCap, FrameFlags,
    FrameHeader, WireError, WireFrame, HMAC_TAG_LEN, MAGIC_BYTES, PROTOCOL_VERSION, STATIC_DICT,
};
