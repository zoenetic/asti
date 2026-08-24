//! Cross-file linking: resolve each file's imports to the summaries of the
//! files they name, producing the per-file `FileLinked` the evaluator applies
//! and a per-file *link fingerprint* over the summaries it may consult (the
//! second half of the two-layer cache key).

use crate::engine::taint::FileLinked;
use crate::languages::profile::ModuleResolution;
use crate::state::summary_store::{PortableBindings, PortableFunctionSummary};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Maximum re-export hops followed when resolving an import to a summary.
const MAX_LINK_DEPTH: usize = 4;

/// A file's extracted facts, as fed to the linker.
pub struct FileArtifact {
    pub file: String,
    pub summary_hash: String,
    pub bindings: PortableBindings,
    pub rules: HashMap<String, Vec<PortableFunctionSummary>>,
    pub resolution: Option<ModuleResolution>,
}

#[derive(Default)]
pub struct LinkResult {
    /// file -> (rule -> (local callee name -> summary)).
    pub linked: HashMap<String, FileLinked>,
    /// file -> fingerprint of the summaries it may consult (empty if none).
    pub link_fp: HashMap<String, String>,
}

/// Link every file's imports against the corpus of summaries.
pub fn link(artifacts: &[FileArtifact]) -> LinkResult {
    let by_file: HashMap<&str, &FileArtifact> =
        artifacts.iter().map(|a| (a.file.as_str(), a)).collect();
    let files: HashSet<&str> = by_file.keys().copied().collect();

    // symbol-strategy index: module_decl -> files declaring it.
    let mut by_module: HashMap<&str, Vec<&str>> = HashMap::new();
    for a in artifacts {
        if let Some(m) = &a.bindings.module_decl {
            by_module.entry(m.as_str()).or_default().push(&a.file);
        }
    }

    let mut result = LinkResult::default();
    for a in artifacts {
        let mut file_linked: FileLinked = HashMap::new();
        let mut deps: BTreeSet<(String, String)> = BTreeSet::new();

        for (local, module, name) in &a.bindings.imports {
            // Resolve this import to a target function summary, for every rule
            // that names a function there.
            resolve_all_rules(
                &a.file,
                local,
                module,
                name,
                &by_file,
                &files,
                &by_module,
                0,
                &mut file_linked,
                &mut deps,
            );
        }

        if !deps.is_empty() {
            let mut h = blake3::Hasher::new();
            h.update(b"crit-linkfp-v1\0");
            for (f, sh) in &deps {
                h.update(f.as_bytes());
                h.update(b"\0");
                h.update(sh.as_bytes());
                h.update(b"\0");
            }
            result
                .link_fp
                .insert(a.file.clone(), h.finalize().to_hex().to_string());
        }
        if !file_linked.is_empty() {
            result.linked.insert(a.file.clone(), file_linked);
        }
    }
    result
}

/// Resolve `module` (imported into `importer`) to a target file.
fn resolve_module<'a>(
    importer: &str,
    module: &str,
    resolution: Option<&ModuleResolution>,
    files: &HashSet<&'a str>,
    by_module: &HashMap<&'a str, Vec<&'a str>>,
) -> Vec<String> {
    let strategy = resolution.map(|r| r.strategy.as_str()).unwrap_or("path");
    if strategy == "symbol" {
        // Match a declared module/namespace by exact name or last segment.
        let last = module.rsplit(['/', ':', '.']).next().unwrap_or(module);
        let mut out = Vec::new();
        for key in [module, last] {
            if let Some(fs) = by_module.get(key) {
                out.extend(fs.iter().map(|s| s.to_string()));
            }
        }
        out.sort();
        out.dedup();
        return out;
    }
    // path strategy: only relative specifiers resolve to local files.
    if !module.starts_with('.') {
        return Vec::new();
    }
    let empty = ModuleResolution {
        strategy: "path".into(),
        extensions: Vec::new(),
        index_files: Vec::new(),
    };
    let mr = resolution.unwrap_or(&empty);
    let base = parent_dir(importer);
    let joined = normalize_join(&base, module);
    let mut cands = vec![joined.clone()];
    for ext in &mr.extensions {
        cands.push(format!("{joined}{ext}"));
    }
    for idx in &mr.index_files {
        cands.push(format!("{joined}/{idx}"));
    }
    cands
        .into_iter()
        .filter(|c| files.contains(c.as_str()))
        .take(1)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn resolve_all_rules(
    importer: &str,
    local: &str,
    module: &str,
    name: &str,
    by_file: &HashMap<&str, &FileArtifact>,
    files: &HashSet<&str>,
    by_module: &HashMap<&str, Vec<&str>>,
    depth: usize,
    out: &mut FileLinked,
    deps: &mut BTreeSet<(String, String)>,
) {
    if depth >= MAX_LINK_DEPTH {
        return;
    }
    let resolution = by_file.get(importer).and_then(|a| a.resolution.clone());
    for target in resolve_module(importer, module, resolution.as_ref(), files, by_module) {
        let Some(ta) = by_file.get(target.as_str()) else {
            continue;
        };
        let mut linked_here = false;
        for (rule, summaries) in &ta.rules {
            if let Some(sum) = summaries.iter().find(|s| s.name == name) {
                out.entry(rule.clone())
                    .or_default()
                    .insert(local.to_string(), sum.clone());
                linked_here = true;
            }
        }
        if linked_here {
            deps.insert((ta.file.clone(), ta.summary_hash.clone()));
        }
        // Re-export: the target imports `name` from elsewhere.
        for (l2, m2, n2) in &ta.bindings.imports {
            if l2 == name {
                deps.insert((ta.file.clone(), ta.summary_hash.clone()));
                resolve_all_rules(
                    &target,
                    local,
                    m2,
                    n2,
                    by_file,
                    files,
                    by_module,
                    depth + 1,
                    out,
                    deps,
                );
            }
        }
    }
}

/// Parent directory of a forward-slash relative path (`""` for a top-level file).
fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

/// Join `base` with a relative `spec` and collapse `.`/`..` segments.
fn normalize_join(base: &str, spec: &str) -> String {
    let mut parts: Vec<&str> = if base.is_empty() {
        Vec::new()
    } else {
        base.split('/').collect()
    };
    for seg in spec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_join_normalizes() {
        assert_eq!(normalize_join("web", "./db"), "web/db");
        assert_eq!(normalize_join("web/api", "../db"), "web/db");
        assert_eq!(normalize_join("", "./util"), "util");
    }
}
