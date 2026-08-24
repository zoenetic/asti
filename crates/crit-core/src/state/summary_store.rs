//! Content-addressed store of per-file function summaries, the persisted
//! inputs to cross-file taint linking.
//!
//! A summary captures, per taint rule, how each named function moves taint:
//! whether its return value is a source, which parameters flow to its return,
//! and which parameters reach a sink inside it. These are *intra-file* facts,
//! so a file's artifact depends only on its own contents — it is keyed by
//! `blake3(content_hash ‖ rules_hash ‖ SUMMARY_SCHEMA)` and is valid as long
//! as the file on disk exists, with no invalidation logic.

use crate::findings::Span;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Bump when the artifact layout changes (invalidates every stored summary).
pub const SUMMARY_SCHEMA: u32 = 1;

const SUMMARY_DIR: &str = "summaries";

/// One provenance step, portable across files (file-tagged, snippet baked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableStep {
    pub label: String,
    pub span: Span,
    pub file: String,
    pub snippet: String,
}

/// How one named function moves taint, for a single rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortableFunctionSummary {
    pub name: String,
    /// Non-empty when the return value carries a source (with provenance).
    pub returns_source: Vec<PortableStep>,
    /// Parameter indices whose taint flows to the return value.
    pub returns_params: Vec<(usize, Vec<PortableStep>)>,
    /// Parameters that reach a sink inside the function.
    pub param_to_sink: Vec<ParamSink>,
}

/// A parameter that reaches a sink within the function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamSink {
    pub index: usize,
    pub sink_label: String,
    pub sink_step: PortableStep,
    /// Steps from the parameter to the sink, inside the function.
    pub steps: Vec<PortableStep>,
}

/// Import/export facts needed to resolve the module graph.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortableBindings {
    pub module_decl: Option<String>,
    /// (local name, module, imported name)
    pub imports: Vec<(String, String, String)>,
    pub exports: Vec<String>,
}

/// A file's complete summary artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSummaryArtifact {
    pub schema: u32,
    pub file: String,
    pub content_hash: String,
    pub bindings: PortableBindings,
    /// rule id -> function summaries.
    pub rules: BTreeMap<String, Vec<PortableFunctionSummary>>,
    /// blake3 over the artifact's semantic content; identifies this summary
    /// for link fingerprints.
    pub summary_hash: String,
}

impl FileSummaryArtifact {
    /// Compute and set `summary_hash` from the current content.
    pub fn finalize(mut self) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"crit-summary-v1\0");
        h.update(self.content_hash.as_bytes());
        h.update(&serde_json::to_vec(&self.bindings).unwrap_or_default());
        h.update(&serde_json::to_vec(&self.rules).unwrap_or_default());
        self.summary_hash = h.finalize().to_hex().to_string();
        self
    }
}

fn dir(root: &Path) -> PathBuf {
    super::state_dir(root).join(SUMMARY_DIR)
}

/// Storage key for a file's summary under the current rule set.
pub fn key(content_hash: &str, rules_hash: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(content_hash.as_bytes());
    h.update(b"\0");
    h.update(rules_hash.as_bytes());
    h.update(b"\0");
    h.update(&SUMMARY_SCHEMA.to_le_bytes());
    h.finalize().to_hex().to_string()
}

fn artifact_path(root: &Path, key: &str) -> PathBuf {
    dir(root).join(&key[..2]).join(format!("{key}.json"))
}

/// Load a stored artifact by key, if present and well-formed.
pub fn load(root: &Path, key: &str) -> Option<FileSummaryArtifact> {
    let bytes = std::fs::read(artifact_path(root, key)).ok()?;
    let art: FileSummaryArtifact = serde_json::from_slice(&bytes).ok()?;
    (art.schema == SUMMARY_SCHEMA).then_some(art)
}

/// Persist an artifact under its key.
pub fn store(root: &Path, key: &str, artifact: &FileSummaryArtifact) -> Result<()> {
    let path = artifact_path(root, key);
    let bytes = serde_json::to_vec(artifact).context("serialize summary")?;
    super::write_atomic(&path, &bytes)
}

/// Remove all stored summaries (part of `crit cache clear`).
pub fn clear(root: &Path) -> Result<bool> {
    let d = dir(root);
    if d.exists() {
        std::fs::remove_dir_all(&d).with_context(|| format!("failed to remove {}", d.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}
