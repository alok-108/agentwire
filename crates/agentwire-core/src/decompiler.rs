//! Lossless 1:1 AST-to-human-readable decompiler & telemetry formatter.
//!
//! Every binary AgentWire frame can be deterministically projected back into a concise,
//! readable natural-language trace **and** a lossless canonical AST representation with
//! zero semantic drift.

use serde::{Deserialize, Serialize};

use crate::ast::{AstNode, AstValue};
use crate::frame::{FrameFlags, WireFrame};

/// Structured human-readable projection of a decoded [`WireFrame`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceSummary {
    pub trace_id: u64,
    pub span_id: u32,
    pub hop_depth: u16,
    pub source_agent: String,
    pub target_agent: String,
    pub action: String,
    pub target: String,
    pub intent: String,
    pub budget_tokens: u32,
    pub budget_usd: f64,
    pub guard_verified: bool,
    /// Single-line natural-language summary suitable for live UI timelines & logs.
    pub human_readable: String,
    /// Lossless canonical AST string produced by [`decompile_ast`].
    pub canonical_ast: String,
    /// Multi-line formatted trace breakdown for terminal/UI inspection panes.
    pub structured_lines: Vec<String>,
}

/// Format an [`AstValue`] losslessly into deterministic human-readable notation.
pub fn format_ast_value(value: &AstValue) -> String {
    match value {
        AstValue::Null => "null".to_string(),
        AstValue::Bool(b) => b.to_string(),
        AstValue::Int(i) => i.to_string(),
        AstValue::Float(f) => {
            if f.fract() == 0.0 {
                format!("{f:.1}")
            } else {
                format!("{f}")
            }
        }
        AstValue::String(s) => format!("{s:?}"),
        AstValue::Ref(uri) => format!("@{uri}"),
        AstValue::List(items) => {
            let rendered: Vec<String> = items.iter().map(format_ast_value).collect();
            format!("[{}]", rendered.join(", "))
        }
        AstValue::Map(map) => {
            let rendered: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{k}={}", format_ast_value(v)))
                .collect();
            format!("{{{}}}", rendered.join(", "))
        }
    }
}

/// Losslessly project an [`AstNode`] into a deterministic canonical human-readable string.
///
/// Format:
/// `<ACTION> <target>::<intent>(<k1>=<v1>, <k2>=<v2>) refs=[@<r1>, @<r2>]`
pub fn decompile_ast(node: &AstNode) -> String {
    let args = node
        .payload
        .iter()
        .map(|(k, v)| format!("{k}={}", format_ast_value(v)))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = format!("{} {}::{}({})", node.action.as_str(), node.target, node.intent, args);
    if !node.refs.is_empty() {
        let refs = node
            .refs
            .iter()
            .map(|r| format!("@{r}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(" refs=[{refs}]"));
    }
    out
}

/// Decompile a complete [`WireFrame`] into a [`TraceSummary`] for observability UIs and target agent context.
pub fn decompile_frame(frame: &WireFrame) -> TraceSummary {
    let h = &frame.header;
    let b = &frame.body;
    let budget_usd = (h.budget.max_micro_usd as f64) / 1_000_000.0;
    let guard_verified = (h.flags & FrameFlags::GUARD_VERIFIED) != 0;
    let canonical_ast = decompile_ast(b);

    let verb = match b.action {
        crate::ast::AgentAction::Query => "queried",
        crate::ast::AgentAction::Mutate => "mutated",
        crate::ast::AgentAction::Delegate => "delegated",
        crate::ast::AgentAction::Yield => "yielded",
        crate::ast::AgentAction::Assert => "asserted",
    };

    let arg_summary = if b.payload.is_empty() {
        String::new()
    } else {
        let pairs = b
            .payload
            .iter()
            .map(|(k, v)| format!("{k}={}", format_ast_value(v)))
            .collect::<Vec<_>>()
            .join(", ");
        format!(" with {{{pairs}}}")
    };

    let ref_summary = if b.refs.is_empty() {
        String::new()
    } else {
        let refs = b
            .refs
            .iter()
            .map(|r| format!("@{r}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(" [refs: {refs}]")
    };

    let human_readable = format!(
        "[hop {}] {} -> {} {} \"{}\" on {}{}{} (cap: {} tok / ${:.4})",
        h.hop_depth,
        h.source_agent,
        h.target_agent,
        verb,
        b.intent,
        b.target,
        arg_summary,
        ref_summary,
        h.budget.max_tokens,
        budget_usd
    );

    let mut structured_lines = vec![
        format!(
            "FRAME AW01 v{} | trace={} span={} hop={} | guard={}",
            h.version,
            h.trace_id,
            h.span_id,
            h.hop_depth,
            if guard_verified { "VERIFIED" } else { "UNVERIFIED" }
        ),
        format!("ROUTE {} -> {}", h.source_agent, h.target_agent),
        format!(
            "BUDGET max_tokens={} max_usd=${:.4}",
            h.budget.max_tokens, budget_usd
        ),
        format!("AST   {}", canonical_ast),
    ];

    if !b.refs.is_empty() {
        structured_lines.push(format!("REFS  {}", b.refs.join(", ")));
    }

    TraceSummary {
        trace_id: h.trace_id,
        span_id: h.span_id,
        hop_depth: h.hop_depth,
        source_agent: h.source_agent.clone(),
        target_agent: h.target_agent.clone(),
        action: b.action.as_str().to_string(),
        target: b.target.clone(),
        intent: b.intent.clone(),
        budget_tokens: h.budget.max_tokens,
        budget_usd,
        guard_verified,
        human_readable,
        canonical_ast,
        structured_lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::AgentAction;
    use crate::frame::{BudgetCap, FrameHeader};

    #[test]
    fn decompile_ast_is_deterministic_and_lossless() {
        let node = AstNode::new(AgentAction::Query, "postgres.users", "fetch_delta")
            .with_arg("user_id", AstValue::Int(123))
            .with_arg("strict", AstValue::Bool(true))
            .with_ref("ctx://session/9");

        let rendered = decompile_ast(&node);
        assert_eq!(
            rendered,
            "QUERY postgres.users::fetch_delta(strict=true, user_id=123) refs=[@ctx://session/9]"
        );
    }

    #[test]
    fn decompile_frame_contains_route_and_budget() {
        let mut header = FrameHeader::new("planner", "researcher", 42, 3);
        header.hop_depth = 1;
        header.budget = BudgetCap {
            max_tokens: 1024,
            max_micro_usd: 15_000,
        };
        let node = AstNode::new(AgentAction::Delegate, "repo:payments", "analyze_schema")
            .with_arg("depth", AstValue::Int(2));
        let frame = WireFrame::new(header, node);

        let summary = decompile_frame(&frame);
        assert!(summary.human_readable.contains("planner -> researcher"));
        assert!(summary.human_readable.contains("analyze_schema"));
        assert!(summary.human_readable.contains("1024 tok"));
        assert_eq!(summary.action, "DELEGATE");
    }
}
