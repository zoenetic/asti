//! Plain JSON output: findings plus scan statistics, stable and easy to
//! post-process with jq.

use crate::findings::Finding;
use crate::scanner::ScanStats;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct JsonReport<'a> {
    schema: &'static str,
    version: &'static str,
    findings: &'a [Finding],
    stats: &'a ScanStats,
    errors: &'a [String],
}

pub fn render(findings: &[Finding], stats: &ScanStats, errors: &[String]) -> Result<String> {
    let report = JsonReport {
        schema: "crit/v1",
        version: crate::ENGINE_VERSION,
        findings,
        stats,
        errors,
    };
    Ok(serde_json::to_string_pretty(&report)?)
}
