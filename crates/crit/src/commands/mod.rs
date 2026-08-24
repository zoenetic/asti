//! CLI command implementations and the shared setup context.

pub mod baseline;
pub mod cache;
pub mod coverage;
pub mod explain;
pub mod languages;
pub mod parse;
pub mod rules;
pub mod scan;

use anyhow::{Context as _, Result};
use crit_core::config::Config;
use crit_core::languages::Registry;
use crit_core::rules::{CompiledRuleSet, LoadedRules};
use std::path::{Path, PathBuf};

/// Shared, lazily assembled state: scan root, config, language registry.
pub struct Context {
    pub root: PathBuf,
    pub config: Config,
    /// Directory config-relative paths resolve against.
    pub config_base: PathBuf,
    pub registry: Registry,
}

impl Context {
    pub fn new(root: Option<&Path>, config_path: Option<&Path>) -> Result<Self> {
        let cwd = std::env::current_dir().context("cannot determine current directory")?;
        let root = match root {
            Some(r) => r
                .canonicalize()
                .with_context(|| format!("invalid --root {}", r.display()))?,
            None => crit_core::diff::repo_root(&cwd).unwrap_or(cwd),
        };
        let (config, config_base) = Config::load(&root, config_path)?;

        let mut registry = Registry::with_builtins()?;
        for grammar in &config.grammars {
            registry
                .add_dynamic(grammar, &config_base)
                .with_context(|| format!("failed to load external grammar `{}`", grammar.name))?;
        }
        for (ext, lang) in &config.extensions {
            registry.override_extension(ext, lang)?;
        }

        Ok(Context {
            root,
            config,
            config_base,
            registry,
        })
    }

    /// Load and compile rules: builtins (unless disabled), config rule dirs,
    /// then extra dirs from the CLI (highest precedence).
    pub fn compile_rules(
        &self,
        extra_rule_paths: &[PathBuf],
        no_default_rules: bool,
    ) -> Result<CompiledRuleSet> {
        let mut loaded = if no_default_rules || self.config.scan.no_default_rules {
            LoadedRules::default()
        } else {
            LoadedRules::builtin()?
        };
        for dir in &self.config.scan.rules {
            let path = self.config_base.join(dir);
            loaded.load_path(&path)?;
        }
        for path in extra_rule_paths {
            loaded.load_path(path)?;
        }
        loaded.disable(&self.config.scan.disable_rules);
        CompiledRuleSet::compile(loaded, &self.registry)
    }

    /// Resolve CLI path arguments against the current directory and confine
    /// them to the scan root.
    pub fn resolve_paths(&self, paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for p in paths {
            let abs = if p.is_absolute() {
                p.clone()
            } else {
                std::env::current_dir()?.join(p)
            };
            let abs = abs
                .canonicalize()
                .with_context(|| format!("path {} does not exist", p.display()))?;
            if !abs.starts_with(&self.root) {
                anyhow::bail!(
                    "path {} is outside the scan root {}",
                    abs.display(),
                    self.root.display()
                );
            }
            out.push(abs);
        }
        Ok(out)
    }
}

/// Print compilation warnings to stderr (once, deduplicated).
pub fn print_warnings(warnings: &[String], verbose: bool) {
    let mut seen = std::collections::HashSet::new();
    let mut shown = 0;
    for w in warnings {
        if !seen.insert(w) {
            continue;
        }
        if !verbose && shown >= 8 {
            eprintln!(
                "warning: …and {} more (run `crit rules --verbose` for all)",
                warnings.len() - shown
            );
            break;
        }
        eprintln!("warning: {w}");
        shown += 1;
    }
}
