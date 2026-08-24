//! `crit coverage` — taxonomy coverage report.
//!
//! Turns rule *comprehensiveness* into an objective, tracked number by
//! mapping the CWE and OWASP tags every rule already carries against two
//! industry-standard checklists: the OWASP Top 10 (2021) and the MITRE
//! CWE Top 25 Most Dangerous Software Weaknesses (2023).
//!
//! This measures *taxonomy completeness* — whether at least one rule exists
//! for each weakness class — not recall against a labelled corpus (no such
//! corpus exists for ObjectScript or Delphi). It is the standard rubric to
//! use when an external oracle is unavailable.

use super::Context;
use anyhow::Result;
use clap::Args;
use std::collections::{BTreeMap, BTreeSet};

/// OWASP Top 10 (2021): id → name.
const OWASP_2021: [(&str, &str); 10] = [
    ("A01:2021", "Broken Access Control"),
    ("A02:2021", "Cryptographic Failures"),
    ("A03:2021", "Injection"),
    ("A04:2021", "Insecure Design"),
    ("A05:2021", "Security Misconfiguration"),
    ("A06:2021", "Vulnerable and Outdated Components"),
    ("A07:2021", "Identification and Authentication Failures"),
    ("A08:2021", "Software and Data Integrity Failures"),
    ("A09:2021", "Security Logging and Monitoring Failures"),
    ("A10:2021", "Server-Side Request Forgery (SSRF)"),
];

/// MITRE CWE Top 25 (2023): id → name. Source: cwe.mitre.org/top25.
const CWE_TOP25_2023: [(&str, &str); 25] = [
    ("CWE-787", "Out-of-bounds Write"),
    ("CWE-79", "Cross-site Scripting"),
    ("CWE-89", "SQL Injection"),
    ("CWE-416", "Use After Free"),
    ("CWE-78", "OS Command Injection"),
    ("CWE-20", "Improper Input Validation"),
    ("CWE-125", "Out-of-bounds Read"),
    ("CWE-22", "Path Traversal"),
    ("CWE-352", "Cross-Site Request Forgery"),
    ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
    ("CWE-862", "Missing Authorization"),
    ("CWE-476", "NULL Pointer Dereference"),
    ("CWE-287", "Improper Authentication"),
    ("CWE-190", "Integer Overflow or Wraparound"),
    ("CWE-502", "Deserialization of Untrusted Data"),
    ("CWE-77", "Command Injection"),
    (
        "CWE-119",
        "Improper Restriction of Operations within Memory Bounds",
    ),
    ("CWE-798", "Use of Hard-coded Credentials"),
    ("CWE-918", "Server-Side Request Forgery"),
    ("CWE-306", "Missing Authentication for Critical Function"),
    ("CWE-362", "Race Condition"),
    ("CWE-269", "Improper Privilege Management"),
    ("CWE-94", "Code Injection"),
    ("CWE-863", "Incorrect Authorization"),
    ("CWE-276", "Incorrect Default Permissions"),
];

#[derive(Args)]
pub struct CoverageArgs {
    /// Restrict the report to these language ids (repeatable).
    #[arg(long = "lang", value_name = "LANG")]
    pub languages: Vec<String>,

    /// Additional rule files/directories to include.
    #[arg(long = "rules", value_name = "PATH")]
    pub rule_paths: Vec<std::path::PathBuf>,

    /// Disable the built-in rule packs.
    #[arg(long)]
    pub no_default_rules: bool,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,

    /// Print all rule-compilation warnings.
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

/// What one language (or the whole set) covers.
#[derive(Default)]
struct Covered {
    cwe: BTreeSet<String>,
    owasp: BTreeSet<String>,
    rule_count: usize,
}

pub fn run(ctx: &Context, args: CoverageArgs) -> Result<i32> {
    let ruleset = ctx.compile_rules(&args.rule_paths, args.no_default_rules)?;
    super::print_warnings(&ruleset.warnings, args.verbose);

    // Accumulate coverage per language and overall.
    let mut per_lang: BTreeMap<String, Covered> = BTreeMap::new();
    let mut all = Covered::default();
    let filter: BTreeSet<&str> = args.languages.iter().map(|s| s.as_str()).collect();

    for rule in ruleset.rules.values() {
        let mut counted_all = false;
        for lang in &rule.languages {
            if !filter.is_empty() && !filter.contains(lang.as_str()) {
                continue;
            }
            let entry = per_lang.entry(lang.clone()).or_default();
            entry.rule_count += 1;
            for c in &rule.metadata.cwe {
                entry.cwe.insert(c.clone());
            }
            for o in &rule.metadata.owasp {
                entry.owasp.insert(o.clone());
            }
            counted_all = true;
        }
        if counted_all {
            all.rule_count += 1;
            all.cwe.extend(rule.metadata.cwe.iter().cloned());
            all.owasp.extend(rule.metadata.owasp.iter().cloned());
        }
    }

    if args.json {
        print_json(&per_lang, &all);
    } else {
        print_human(&per_lang, &all);
    }
    Ok(0)
}

fn owasp_hits(cov: &Covered) -> usize {
    OWASP_2021
        .iter()
        .filter(|(id, _)| cov.owasp.contains(*id))
        .count()
}

fn cwe_top25_hits(cov: &Covered) -> usize {
    CWE_TOP25_2023
        .iter()
        .filter(|(id, _)| cov.cwe.contains(*id))
        .count()
}

fn print_human(per_lang: &BTreeMap<String, Covered>, all: &Covered) {
    println!("crit taxonomy coverage");
    println!("  checklists: OWASP Top 10 (2021), MITRE CWE Top 25 (2023)\n");

    println!(
        "  {:<14} {:>5} {:>12} {:>13} {:>10}",
        "language", "rules", "OWASP 10", "CWE Top25", "CWEs"
    );
    println!("  {}", "-".repeat(60));
    for (lang, cov) in per_lang {
        println!(
            "  {:<14} {:>5} {:>9}/10 {:>10}/25 {:>10}",
            lang,
            cov.rule_count,
            owasp_hits(cov),
            cwe_top25_hits(cov),
            cov.cwe.len(),
        );
    }
    println!("  {}", "-".repeat(60));
    println!(
        "  {:<14} {:>5} {:>9}/10 {:>10}/25 {:>10}",
        "ALL",
        all.rule_count,
        owasp_hits(all),
        cwe_top25_hits(all),
        all.cwe.len(),
    );

    // Detail: which Top-25 / OWASP items are covered vs missing, overall.
    println!("\n  OWASP Top 10 (2021):");
    for (id, name) in OWASP_2021 {
        let mark = if all.owasp.contains(id) { "✓" } else { "·" };
        println!("    {mark} {id}  {name}");
    }
    println!("\n  CWE Top 25 (2023):");
    for (id, name) in CWE_TOP25_2023 {
        let mark = if all.cwe.contains(id) { "✓" } else { "·" };
        println!("    {mark} {id:<8} {name}");
    }
    println!(
        "\n  Note: taxonomy completeness (a rule exists per class), not recall. \
         Some CWE Top 25 entries (e.g. memory-safety) do not apply to every language."
    );
}

fn print_json(per_lang: &BTreeMap<String, Covered>, all: &Covered) {
    let langs: Vec<serde_json::Value> = per_lang
        .iter()
        .map(|(lang, cov)| cov_json(Some(lang), cov))
        .collect();
    let doc = serde_json::json!({
        "checklists": { "owasp": "Top 10 (2021)", "cwe": "Top 25 (2023)" },
        "languages": langs,
        "all": cov_json(None, all),
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}

fn cov_json(lang: Option<&str>, cov: &Covered) -> serde_json::Value {
    let owasp_missing: Vec<&str> = OWASP_2021
        .iter()
        .filter(|(id, _)| !cov.owasp.contains(*id))
        .map(|(id, _)| *id)
        .collect();
    let cwe_missing: Vec<&str> = CWE_TOP25_2023
        .iter()
        .filter(|(id, _)| !cov.cwe.contains(*id))
        .map(|(id, _)| *id)
        .collect();
    serde_json::json!({
        "language": lang,
        "rules": cov.rule_count,
        "owasp_top10_covered": owasp_hits(cov),
        "owasp_top10_missing": owasp_missing,
        "cwe_top25_covered": cwe_top25_hits(cov),
        "cwe_top25_missing": cwe_missing,
        "distinct_cwes": cov.cwe.len(),
    })
}
