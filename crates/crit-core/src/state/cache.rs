//! Incremental scan cache: per-file findings keyed by content hash, valid
//! only while the compiled rule set (rules + profiles + engine revision +
//! languages) is unchanged.

use crate::findings::Finding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const CACHE_FILE: &str = "cache.json";

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Cache {
    /// crit version that wrote the cache (informational).
    pub engine: String,
    /// Validity key: must equal the current compiled rule set hash.
    pub rules_hash: String,
    /// Root-relative path (forward slashes) -> entry.
    pub files: HashMap<String, CacheEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CacheEntry {
    /// blake3 of the file contents.
    pub hash: String,
    /// Fingerprint of the cross-file summaries this file's findings depend on
    /// (empty when the file has no resolved imports). Part of the validity
    /// key so a changed dependency invalidates dependents.
    #[serde(default)]
    pub link_fp: String,
    pub findings: Vec<Finding>,
}

impl Cache {
    fn path(root: &Path) -> PathBuf {
        super::state_dir(root).join(CACHE_FILE)
    }

    /// Load the cache; a missing/corrupt/stale cache yields a fresh one.
    pub fn load(root: &Path, rules_hash: &str) -> Cache {
        let path = Self::path(root);
        let fresh = || Cache {
            engine: crate::ENGINE_VERSION.to_string(),
            rules_hash: rules_hash.to_string(),
            files: HashMap::new(),
        };
        let Ok(bytes) = std::fs::read(&path) else {
            return fresh();
        };
        match serde_json::from_slice::<Cache>(&bytes) {
            Ok(cache) if cache.rules_hash == rules_hash => cache,
            _ => fresh(),
        }
    }

    /// A cache entry is valid only when both the file content and the
    /// cross-file link fingerprint match.
    pub fn lookup(&self, rel_path: &str, content_hash: &str, link_fp: &str) -> Option<&CacheEntry> {
        self.files
            .get(rel_path)
            .filter(|e| e.hash == content_hash && e.link_fp == link_fp)
    }

    pub fn insert(&mut self, rel_path: String, entry: CacheEntry) {
        self.files.insert(rel_path, entry);
    }

    pub fn remove(&mut self, rel_path: &str) {
        self.files.remove(rel_path);
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(self).context("failed to serialize cache")?;
        super::write_atomic(&Self::path(root), &bytes)
    }

    /// Delete the cache file.
    pub fn clear(root: &Path) -> Result<bool> {
        let path = Self::path(root);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn stats(root: &Path) -> Option<(usize, u64)> {
        let path = Self::path(root);
        let meta = std::fs::metadata(&path).ok()?;
        let bytes = std::fs::read(&path).ok()?;
        let cache: Cache = serde_json::from_slice(&bytes).ok()?;
        Some((cache.files.len(), meta.len()))
    }
}
