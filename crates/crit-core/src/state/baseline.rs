//! Finding baselines: a stored set of fingerprints representing accepted
//! pre-existing findings. `crit scan --baseline` reports only findings not
//! in the baseline, so CI can gate on newly introduced issues.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const BASELINE_FILE: &str = "baseline.json";

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Baseline {
    pub engine: String,
    /// Informational: when the baseline was written (RFC3339).
    #[serde(default)]
    pub created: String,
    pub fingerprints: BTreeSet<String>,
}

impl Baseline {
    fn path(root: &Path) -> PathBuf {
        super::state_dir(root).join(BASELINE_FILE)
    }

    pub fn exists(root: &Path) -> bool {
        Self::path(root).exists()
    }

    pub fn load(root: &Path) -> Result<Baseline> {
        let path = Self::path(root);
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "no baseline at {} (create one with `crit baseline update`)",
                path.display()
            )
        })?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("corrupt baseline {}", path.display()))
    }

    pub fn from_findings<'a>(
        findings: impl Iterator<Item = &'a crate::findings::Finding>,
    ) -> Baseline {
        Baseline {
            engine: crate::ENGINE_VERSION.to_string(),
            created: now_rfc3339(),
            fingerprints: findings.map(|f| f.fingerprint.clone()).collect(),
        }
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).context("failed to serialize baseline")?;
        super::write_atomic(&Self::path(root), &bytes)
    }
}

fn now_rfc3339() -> String {
    // Avoid a chrono dependency for one timestamp: seconds since epoch is
    // formatted manually into UTC date/time.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    // Civil-from-days algorithm (Howard Hinnant).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamp_shape() {
        let ts = super::now_rfc3339();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z'));
    }
}
