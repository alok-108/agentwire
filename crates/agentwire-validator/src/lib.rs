//! Deterministic policy validator, replay protection, and two-phase budget accounting
//! for **AgentWire**.

pub mod policy;

pub use policy::{
    AgentCapability, BudgetLedger, BudgetReservation, PolicyEngine, PolicyError, PolicySpec,
    RejectionCode, SettlementReceipt, ValidationResult,
};
