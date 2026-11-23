//! Deterministic policy validator and safety guard-gate engine for **AgentWire**.

pub mod policy;

pub use policy::{
    AgentCapability, PolicyEngine, PolicyError, PolicySpec, RejectionCode, ValidationResult,
};
