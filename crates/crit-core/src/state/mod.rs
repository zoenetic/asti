//! Persistent scan state under `.crit/` at the scan root: the incremental
//! result cache and finding baselines.

pub mod baseline;
pub mod cache;
pub mod summary_store;

use std::path::{Path, PathBuf};

pub const STATE_DIR: &str = ".crit";

pub fn state_dir(root: &Path) -> PathBuf {
    root.join(STATE_DIR)
}

/// Write a file atomically (temp file + rename) so interrupted scans never
/// corrupt state.
pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("state"),
        std::process::id()
    ));
    std::fs::write(&tmp, contents).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to move {} into place", tmp.display()))?;
    Ok(())
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
