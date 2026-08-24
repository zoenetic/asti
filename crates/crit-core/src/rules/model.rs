//! Serde model for YAML rule files.
//!
//! A rules file looks like:
//!
//! ```yaml
//! rules:
//!   - id: js.no-eval
//!     severity: high
//!     category: security
//!     languages: [javascript, typescript]
//!     message: "`eval` executes arbitrary code"
//!     metadata:
//!       cwe: [CWE-95]
//!       owasp: [A03:2021]
//!       nist: [SI-10]
//!     query: |
//!       (call_expression
//!         function: (identifier) @callee
//!         (#eq? @callee "eval")) @finding
//! ```
//!
//! Taint rules replace `query` with `sources`/`sinks` (and optional
//! `sanitizers`), each a list of queries whose `@source`/`@sink`/
//! `@sanitizer` captures mark the relevant nodes.

use crate::findings::{Category, Severity};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    #[default]
    Pattern,
    Taint,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// CWE identifiers, e.g. `CWE-89`.
    #[serde(default)]
    pub cwe: Vec<String>,
    /// OWASP Top 10 identifiers, e.g. `A03:2021`.
    #[serde(default)]
    pub owasp: Vec<String>,
    /// NIST SP 800-53 control identifiers, e.g. `SI-10`.
    #[serde(default)]
    pub nist: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Post-match filter applied to the text of a named capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFilter {
    pub capture: String,
    /// Regex the capture text must match (RE2-style, `regex` crate).
    #[serde(default)]
    pub pattern: Option<String>,
    /// Exact string the capture text must equal.
    #[serde(default)]
    pub equals: Option<String>,
    /// The capture text must equal one of these.
    #[serde(default)]
    pub any_of: Option<Vec<String>>,
    /// Invert the filter.
    #[serde(default)]
    pub negate: bool,
}

/// A taint source/sink/sanitizer declaration. Exactly one of `query` (a
/// tree-sitter query, the 0.1 form) or `resolved` (an identity matcher
/// against binder-resolved calls/reads, 0.2) must be present.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintPattern {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Identity matcher resolved through the binder (imports, aliases,
    /// method receivers). Alternative to `query`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<ResolvedMatcher>,
    /// Human-readable label used in flow traces, e.g. `HTTP request data`.
    #[serde(default)]
    pub label: Option<String>,
}

/// Identity-based matcher. Interpretation depends on the role:
/// * **sink**: match a resolved call whose identity is `module::name` (or just
///   terminal `name`); `arg_index` selects which argument is the sink (default
///   all). Set `match_unresolved` to also match a bare/text callee named
///   `name` (default false, so identity rules never silently degrade to text).
/// * **source**: match a resolved member read whose base resolves to `module`
///   (an import) or whose base identifier is `member_of`, with field chain
///   `path`.
/// * **sanitizer**: match a resolved call `module::name` (or terminal `name`);
///   the whole call cleanses.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResolvedMatcher {
    #[serde(default)]
    pub module: Option<String>,
    #[serde(default)]
    pub member_of: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub arg_index: Option<usize>,
    #[serde(default)]
    pub match_unresolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub kind: RuleKind,
    pub severity: Severity,
    #[serde(default)]
    pub category: Category,
    /// Language ids this rule applies to.
    pub languages: Vec<String>,
    /// Finding message. `${capture}` placeholders are substituted with the
    /// text of the corresponding query capture.
    pub message: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,

    /// Pattern rule: the tree-sitter query. The reported node is the
    /// `@finding` capture if present, otherwise the first capture.
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub filters: Vec<CaptureFilter>,

    /// Taint rule parts.
    #[serde(default)]
    pub sources: Vec<TaintPattern>,
    #[serde(default)]
    pub sinks: Vec<TaintPattern>,
    #[serde(default)]
    pub sanitizers: Vec<TaintPattern>,

    /// Where this rule was loaded from (set by the loader, not YAML).
    #[serde(skip, default)]
    pub origin: String,

    /// SARIF precision tier derived from verified fixture evidence
    /// (`rules/evidence.yaml`). Populated by the loader — not authorable in
    /// rule YAML — and serialized so it participates in the rules hash.
    #[serde(skip_deserializing, default, skip_serializing_if = "Option::is_none")]
    pub precision: Option<String>,
}

impl RuleSpec {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            bail!("rule id must not be empty");
        }
        if self.languages.is_empty() {
            bail!("rule must list at least one language");
        }
        match self.kind {
            RuleKind::Pattern => {
                if self.query.is_none() {
                    bail!("pattern rule requires `query`");
                }
                if !self.sources.is_empty() || !self.sinks.is_empty() {
                    bail!("pattern rule must not declare sources/sinks (use kind: taint)");
                }
            }
            RuleKind::Taint => {
                if self.sources.is_empty() || self.sinks.is_empty() {
                    bail!("taint rule requires at least one source and one sink");
                }
                if self.query.is_some() {
                    bail!("taint rule must not declare `query`");
                }
                for (role, pats) in [
                    ("source", &self.sources),
                    ("sink", &self.sinks),
                    ("sanitizer", &self.sanitizers),
                ] {
                    for p in pats {
                        match (&p.query, &p.resolved) {
                            (Some(_), Some(_)) => {
                                bail!("{role} declares both `query` and `resolved`; use one")
                            }
                            (None, None) => {
                                bail!("{role} needs one of `query` or `resolved`")
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        for f in &self.filters {
            if f.pattern.is_none() && f.equals.is_none() && f.any_of.is_none() {
                bail!(
                    "filter on `{}` needs one of pattern/equals/any_of",
                    f.capture
                );
            }
            if let Some(p) = &f.pattern {
                regex::Regex::new(p).map_err(|e| {
                    anyhow::anyhow!("invalid filter regex for `{}`: {e}", f.capture)
                })?;
            }
        }
        Ok(())
    }

    /// Short display name.
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}
