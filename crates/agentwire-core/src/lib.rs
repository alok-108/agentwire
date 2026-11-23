//! Core protocol specification, typed AST, binary wire codec, Ed25519 per-agent asymmetric
//! signatures, HMAC-SHA256 frame authentication, and lossless decompiler for **AgentWire**.

pub mod ast;
pub mod decompiler;
pub mod frame;

pub use ast::{AgentAction, AstNode, AstValue};
pub use decompiler::{decompile_ast, decompile_frame, TraceSummary};
pub use frame::{
    decode_frame, encode_frame, generate_ed25519_keypair, sign_frame, sign_frame_ed25519,
    verify_and_decode_ed25519, verify_and_decode_frame, BudgetCap, FrameFlags, FrameHeader,
    WireError, WireFrame, ED25519_KEY_LEN, ED25519_SIG_LEN, HMAC_TAG_LEN, MAGIC_BYTES,
    PROTOCOL_VERSION, STATIC_DICT,
};
