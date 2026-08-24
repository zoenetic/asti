//! Project configuration: `crit.toml` at the scan root (or passed via
//! `--config`). Everything is optional; CLI flags take precedence.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    /// Externally loaded tree-sitter grammars.
    #[serde(default)]
    pub grammars: Vec<GrammarConfig>,
    /// Extension → language id overrides, e.g. `inc = "pascal"`.
    #[serde(default)]
    pub extensions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Additional rule directories (relative to the config file).
    #[serde(default)]
    pub rules: Vec<String>,
    /// Disable the built-in rule packs entirely.
    #[serde(default)]
    pub no_default_rules: bool,
    /// Glob patterns to exclude, in addition to .gitignore/.critignore.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// If non-empty, only paths matching one of these globs are scanned.
    #[serde(default)]
    pub include: Vec<String>,
    /// Severity threshold for a non-zero exit code ("never" to disable).
    #[serde(default)]
    pub fail_on: Option<String>,
    /// Maximum file size in bytes (larger files are skipped). Default 2 MiB.
    #[serde(default)]
    pub max_file_size: Option<u64>,
    /// Rule ids to disable.
    #[serde(default)]
    pub disable_rules: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrammarConfig {
    /// Language id, also used to resolve the default symbol name
    /// `tree_sitter_<name>`.
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Path to the compiled grammar shared library (.so/.dylib/.dll),
    /// relative to the config file unless absolute.
    pub library: String,
    /// Exported symbol; defaults to `tree_sitter_<name>`.
    #[serde(default)]
    pub symbol: Option<String>,
    /// File extensions handled by this grammar.
    pub extensions: Vec<String>,
    /// Optional taint profile YAML path enabling taint rules for this
    /// language.
    #[serde(default)]
    pub profile: Option<String>,
}

impl Config {
    /// Load `crit.toml` from `root` if present; explicit path wins.
    pub fn load(root: &Path, explicit: Option<&Path>) -> Result<(Self, PathBuf)> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => {
                let candidate = root.join("crit.toml");
                if !candidate.exists() {
                    return Ok((Config::default(), root.to_path_buf()));
                }
                candidate
            }
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
        let base = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| root.to_path_buf());
        Ok((cfg, base))
    }
}
