//! Taint profiles: per-language mappings from grammar node kinds to the
//! syntax concepts the taint engine needs (assignments, functions,
//! parameters, calls, returns, identifiers).
//!
//! Profiles are plain YAML so that externally loaded grammars can supply one
//! without recompiling crit. Built-in profiles are embedded from the
//! `profiles/` directory at the repository root.

use anyhow::{Context, Result};
use include_dir::{include_dir, Dir};
use serde::{Deserialize, Serialize};

static BUILTIN_PROFILES: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../profiles");

/// A tree-sitter query with expected captures, uncompiled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileQuery {
    pub query: String,
}

/// Uncompiled taint profile as authored in YAML.
///
/// Capture conventions:
/// * `assignments`: `@lhs` (assignment target; the first identifier
///   descendant is used if the node itself is not an identifier) and `@rhs`
///   (assigned expression).
/// * `functions`: `@function` (the scope node) and optionally `@name`.
/// * `params`: `@param` (a parameter name node; the innermost enclosing
///   `@function` scope owns it).
/// * `calls`: `@call` (whole call node), `@callee` (callee name node) and
///   `@args` (argument list node).
/// * `returns`: `@value` (returned expression).
///
/// Optional binding sections (crit 0.2), all safe to omit — a profile without
/// them behaves exactly as 0.1 (text-based resolution):
/// * `member_access`: `@access` (the whole field-read), `@object` (the
///   receiver), `@field` (the accessed field name).
/// * `method_calls`: `@call` (whole call), `@receiver` (object the method is
///   called on), `@method` (method name), `@args` (argument list).
/// * `imports`: `@module` (module path/string), `@name` (imported symbol),
///   optional `@alias` (local binding name).
/// * `exports`: `@name` (exported symbol; extraction only in 0.2, consumed by
///   cross-file linking later).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaintProfileSpec {
    /// Node kinds that represent variable references.
    #[serde(default)]
    pub identifiers: Vec<String>,
    #[serde(default)]
    pub assignments: Vec<ProfileQuery>,
    #[serde(default)]
    pub functions: Vec<ProfileQuery>,
    #[serde(default)]
    pub params: Vec<ProfileQuery>,
    #[serde(default)]
    pub calls: Vec<ProfileQuery>,
    #[serde(default)]
    pub returns: Vec<ProfileQuery>,

    // --- optional binding layer (0.2) ---
    #[serde(default)]
    pub member_access: Vec<ProfileQuery>,
    #[serde(default)]
    pub method_calls: Vec<ProfileQuery>,
    #[serde(default)]
    pub imports: Vec<ProfileQuery>,
    #[serde(default)]
    pub exports: Vec<ProfileQuery>,
    #[serde(default)]
    pub module_resolution: Option<ModuleResolution>,
}

/// How a module reference (import path) maps to files on disk. Declared per
/// language; consumed by cross-file linking. `path` resolves relative file
/// paths (JS/TS); `symbol` matches a declared module/namespace name
/// (Go/C#/Rust).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleResolution {
    #[serde(default = "default_strategy")]
    pub strategy: String,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub index_files: Vec<String>,
}

fn default_strategy() -> String {
    "path".to_string()
}

impl TaintProfileSpec {
    /// Stable content hash contribution, for cache invalidation.
    pub fn hash_into(&self, hasher: &mut blake3::Hasher) {
        let json = serde_json::to_vec(self).expect("profile serializes");
        hasher.update(&json);
    }
}

/// Parse a profile YAML document.
pub fn parse_profile(text: &str) -> Result<TaintProfileSpec> {
    serde_yaml::from_str(text).context("invalid taint profile YAML")
}

/// Load the embedded profile for a built-in language, if one exists.
pub fn builtin_profile(lang_id: &str) -> Result<Option<TaintProfileSpec>> {
    let file = BUILTIN_PROFILES.get_file(format!("{lang_id}.yaml"));
    match file {
        Some(f) => {
            let text = f
                .contents_utf8()
                .with_context(|| format!("profile {lang_id}.yaml is not UTF-8"))?;
            let spec =
                parse_profile(text).with_context(|| format!("embedded profile {lang_id}.yaml"))?;
            Ok(Some(spec))
        }
        None => Ok(None),
    }
}
