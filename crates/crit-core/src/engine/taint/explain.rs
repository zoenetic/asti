//! Structured explanation of one file's taint analysis, backing `crit
//! explain`. Built by a read-only recompute pass (`engine::explain`) that
//! rebuilds the same Structure/bindings/solved rules a scan would and queries
//! them — the hot scan path carries no instrumentation.

use serde::Serialize;

/// A named scope (function) in the file.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeInfo {
    pub name: String,
    pub start_line: u32,
    pub end_line: u32,
}

/// A resolved call and how its callee was resolved.
#[derive(Debug, Clone, Serialize)]
pub struct CallInfo {
    pub line: u32,
    pub callee: String,
    pub resolution: String,
}

/// A source/sink location.
#[derive(Debug, Clone, Serialize)]
pub struct Loc {
    pub line: u32,
    pub column: u32,
    pub label: String,
    pub snippet: String,
}

/// Whether a sink is reported, and why (or why not).
#[derive(Debug, Clone, Serialize)]
pub struct SinkVerdict {
    pub line: u32,
    pub column: u32,
    pub snippet: String,
    pub reported: bool,
    pub reason: String,
}

/// Per-rule explanation: what it matched and how each sink was decided.
#[derive(Debug, Clone, Serialize)]
pub struct RuleExplain {
    pub rule_id: String,
    pub sources: Vec<Loc>,
    pub sinks: Vec<SinkVerdict>,
    /// Cross-file callee summaries consulted while evaluating this rule.
    pub linked: Vec<String>,
}

/// The full explanation for one file.
#[derive(Debug, Clone, Serialize)]
pub struct Explanation {
    pub file: String,
    pub language: String,
    pub scopes: Vec<ScopeInfo>,
    pub calls: Vec<CallInfo>,
    pub rules: Vec<RuleExplain>,
}
