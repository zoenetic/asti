//! Git integration for differential scans: resolve the repository root and
//! the set of files changed relative to a base ref (committed, staged and
//! unstaged changes, plus untracked files).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .context("failed to run git (is git installed?)")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

fn parse_z(bytes: &[u8]) -> Vec<PathBuf> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| PathBuf::from(String::from_utf8_lossy(s).into_owned()))
        .collect()
}

/// The git repository root containing `path`, if any.
pub fn repo_root(path: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

/// Files changed in the working tree relative to `base` (a ref, commit, or
/// anything `git rev-parse` accepts), plus untracked files. Paths are
/// repo-root-relative. Deleted files are excluded.
pub fn changed_files(root: &Path, base: &str) -> Result<Vec<PathBuf>> {
    // Validate the base ref up front for a clear error message.
    git(
        root,
        &["rev-parse", "--verify", &format!("{base}^{{commit}}")],
    )
    .with_context(|| format!("cannot resolve diff base `{base}`"))?;

    // Use the merge-base so `--diff-base origin/main` reports what this
    // branch changed, not what main changed since the branch point.
    let merge_base_out = git(root, &["merge-base", base, "HEAD"])
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_else(|_| base.to_string());

    let mut files = parse_z(&git(
        root,
        &[
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACMRT",
            &merge_base_out,
        ],
    )?);
    files.extend(parse_z(&git(
        root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?));
    files.sort();
    files.dedup();
    Ok(files)
}
