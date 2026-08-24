//! Core finding data model shared by the engine, cache, and all output
//! renderers. Findings are self-contained (message, snippet, metadata tags)
//! so cached entries can be rendered without re-parsing files.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity of a finding, ordered from least to most severe.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// SARIF `level` for this severity.
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Info => "note",
            Severity::Low | Severity::Medium => "warning",
            Severity::High | Severity::Critical => "error",
        }
    }

    /// SARIF `security-severity` score (GitHub uses this for display buckets).
    pub fn security_severity(&self) -> &'static str {
        match self {
            Severity::Info => "0.0",
            Severity::Low => "3.0",
            Severity::Medium => "5.5",
            Severity::High => "8.0",
            Severity::Critical => "9.5",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "note" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "warning" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "error" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rule category: what kind of problem the rule detects.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    #[default]
    Security,
    Quality,
    Correctness,
    Performance,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Security => "security",
            Category::Quality => "quality",
            Category::Correctness => "correctness",
            Category::Performance => "performance",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A position in a file. Lines and columns are 1-based (as displayed to
/// humans and required by SARIF).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pos {
    pub line: u32,
    pub column: u32,
}

/// A source span with both point and byte coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: Pos,
    pub end: Pos,
    pub start_byte: u32,
    pub end_byte: u32,
}

impl Span {
    pub fn from_node(node: &tree_sitter::Node) -> Self {
        let r = node.range();
        Span {
            start: Pos {
                line: r.start_point.row as u32 + 1,
                column: r.start_point.column as u32 + 1,
            },
            end: Pos {
                line: r.end_point.row as u32 + 1,
                column: r.end_point.column as u32 + 1,
            },
            start_byte: r.start_byte as u32,
            end_byte: r.end_byte as u32,
        }
    }

    /// Whether this span fully contains `other` (byte-based).
    pub fn contains(&self, other: &Span) -> bool {
        self.start_byte <= other.start_byte && other.end_byte <= self.end_byte
    }
}

/// One step in a taint flow trace, from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    /// Human label, e.g. `source: HTTP request parameter` or
    /// `propagates via assignment to \`query\``.
    pub label: String,
    pub span: Span,
    /// The source line(s) at this step, trimmed.
    pub snippet: String,
    /// File this step is in, when it differs from the finding's file (a
    /// cross-file flow step). `None` means the finding's own file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

/// A single scan finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub category: Category,
    /// Rendered message (capture placeholders already substituted).
    pub message: String,
    /// Path relative to the scan root, always with forward slashes.
    pub file: String,
    pub language: String,
    pub span: Span,
    /// Trimmed text of the first matched line, used for display and
    /// fingerprinting.
    pub snippet: String,
    /// Taint flow steps (empty for plain pattern findings).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<TraceStep>,
    /// Stable fingerprint used for baselines; independent of line numbers so
    /// unrelated edits don't churn baselines.
    pub fingerprint: String,
    /// Denormalised framework tags for self-contained rendering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nist: Vec<String>,
}

impl Finding {
    /// Sort key: most severe first, then by file and position for stable
    /// output.
    pub fn sort_key(&self) -> (std::cmp::Reverse<Severity>, &str, u32, u32, &str) {
        (
            std::cmp::Reverse(self.severity),
            self.file.as_str(),
            self.span.start.line,
            self.span.start.column,
            self.rule_id.as_str(),
        )
    }
}

/// Compute the stable fingerprint for a finding. `occurrence` disambiguates
/// several identical matches (same rule, file and snippet), numbered in
/// document order.
pub fn fingerprint(rule_id: &str, file: &str, snippet: &str, occurrence: u32) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crit-fp-v1\0");
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(file.as_bytes());
    hasher.update(b"\0");
    hasher.update(snippet.trim().as_bytes());
    hasher.update(b"\0");
    hasher.update(&occurrence.to_le_bytes());
    hasher.finalize().to_hex()[..32].to_string()
}
