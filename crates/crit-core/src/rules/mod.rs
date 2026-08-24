//! Rule model, YAML loading, and compilation into per-language tree-sitter
//! queries.

pub mod compiled;
pub mod model;

pub use compiled::{CompiledRuleSet, LanguageRules};
pub use model::{CaptureFilter, Metadata, RuleKind, RuleSpec, TaintPattern};

use anyhow::{bail, Context, Result};
use include_dir::{include_dir, Dir};
use std::collections::BTreeMap;
use std::path::Path;

static BUILTIN_RULES: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../rules");

/// A loaded, but not yet compiled, set of rules.
#[derive(Debug, Default)]
pub struct LoadedRules {
    /// Rules keyed by id, sorted for deterministic hashing.
    pub rules: BTreeMap<String, RuleSpec>,
    /// Non-fatal problems encountered while loading (shown as warnings).
    pub warnings: Vec<String>,
}

impl LoadedRules {
    /// Load the built-in rule packs embedded in the binary, including the
    /// generated fixture evidence (which drives SARIF precision).
    pub fn builtin() -> Result<Self> {
        let mut out = LoadedRules::default();
        let mut stack = vec![&BUILTIN_RULES];
        while let Some(dir) = stack.pop() {
            for sub in dir.dirs() {
                stack.push(sub);
            }
            for file in dir.files() {
                let path = file.path();
                if !is_rule_file(path) {
                    continue;
                }
                let text = file
                    .contents_utf8()
                    .with_context(|| format!("embedded rules {} not UTF-8", path.display()))?;
                out.add_document(text, &format!("builtin:{}", path.display()))?;
            }
        }
        if let Some(f) = BUILTIN_RULES.get_file(crate::evidence::EVIDENCE_FILE) {
            let text = f
                .contents_utf8()
                .context("embedded evidence.yaml not UTF-8")?;
            out.apply_evidence(&crate::evidence::EvidenceFile::parse(text)?);
        }
        Ok(out)
    }

    /// Load rules from a directory (recursively) or a single YAML file.
    pub fn load_path(&mut self, path: &Path) -> Result<()> {
        if path.is_file() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read rules file {}", path.display()))?;
            return self.add_document(&text, &path.display().to_string());
        }
        if !path.is_dir() {
            bail!("rules path {} does not exist", path.display());
        }
        let mut entries: Vec<_> = walkdir(path)?;
        entries.sort();
        for file in entries {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("failed to read rules file {}", file.display()))?;
            self.add_document(&text, &file.display().to_string())?;
        }
        Ok(())
    }

    /// Parse a YAML rules document and merge it in. Duplicate ids override
    /// earlier definitions (user rules can replace builtins) with a warning.
    pub fn add_document(&mut self, text: &str, origin: &str) -> Result<()> {
        let doc: model::RuleFile = serde_yaml::from_str(text)
            .with_context(|| format!("invalid rules YAML in {origin}"))?;
        for mut rule in doc.rules {
            rule.origin = origin.to_string();
            if let Err(e) = rule.validate() {
                self.warnings
                    .push(format!("{origin}: rule `{}` skipped: {e}", rule.id));
                continue;
            }
            if self.rules.contains_key(&rule.id) && !origin.starts_with("builtin:") {
                self.warnings.push(format!(
                    "{origin}: rule `{}` overrides a previously loaded rule",
                    rule.id
                ));
            }
            self.rules.insert(rule.id.clone(), rule);
        }
        Ok(())
    }

    /// Remove disabled rules by id.
    pub fn disable(&mut self, ids: &[String]) {
        for id in ids {
            self.rules.remove(id);
        }
    }

    /// Set each rule's SARIF precision tier from verified fixture evidence.
    pub fn apply_evidence(&mut self, evidence: &crate::evidence::EvidenceFile) {
        for (id, entry) in &evidence.evidence {
            if let Some(rule) = self.rules.get_mut(id) {
                rule.precision = Some(crate::evidence::derive_precision(entry).to_string());
            }
        }
    }
}

/// Rule documents are `.yaml`/`.yml`, excluding the generated
/// `evidence.yaml` and anything under a pack's `tests/` fixture directory.
fn is_rule_file(path: &Path) -> bool {
    let yaml = matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml") | Some("yml")
    );
    yaml && path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n != crate::evidence::EVIDENCE_FILE)
        && !path
            .components()
            .any(|c| c.as_os_str() == crate::evidence::TESTS_DIR)
}

fn walkdir(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("failed to list {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if is_rule_file(&path) {
                out.push(path);
            }
        }
    }
    Ok(out)
}
