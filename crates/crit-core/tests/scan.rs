//! Integration tests exercising the whole pipeline (registry → rules →
//! engine → scanner) against the committed fixtures, plus cache and baseline
//! behavior.

use crit_core::config::Config;
use crit_core::findings::Severity;
use crit_core::languages::Registry;
use crit_core::rules::{CompiledRuleSet, LoadedRules};
use crit_core::scanner::{self, ScanOptions};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn compiled() -> (Registry, CompiledRuleSet) {
    let registry = Registry::with_builtins().expect("registry");
    let loaded = LoadedRules::builtin().expect("builtin rules");
    let ruleset = CompiledRuleSet::compile(loaded, &registry).expect("compile");
    (registry, ruleset)
}

fn scan_dir(dir: &Path, opts: ScanOptions) -> scanner::ScanOutcome {
    let (registry, ruleset) = compiled();
    scanner::scan(dir, &registry, &ruleset, &Config::default(), &opts).expect("scan")
}

fn base_opts() -> ScanOptions {
    ScanOptions {
        use_cache: false,
        ..Default::default()
    }
}

#[test]
fn builtin_rules_all_compile() {
    let (_reg, ruleset) = compiled();
    // No rule should be silently dropped because it failed to compile for
    // every language.
    assert!(
        ruleset.rules.len() >= 40,
        "expected the full builtin rule set, got {}",
        ruleset.rules.len()
    );
    let query_errors: Vec<_> = ruleset
        .warnings
        .iter()
        .filter(|w| w.contains("does not compile") || w.contains("query invalid"))
        .collect();
    assert!(
        query_errors.is_empty(),
        "rule/profile compile errors: {query_errors:?}"
    );
}

fn has(outcome: &scanner::ScanOutcome, rule_id: &str) -> bool {
    outcome.findings.iter().any(|f| f.rule_id == rule_id)
}

#[test]
fn javascript_sql_injection_has_full_flow() {
    let out = scan_dir(&fixtures().join("javascript"), base_opts());
    let sqli = out
        .findings
        .iter()
        .find(|f| f.rule_id == "js.sql-injection")
        .expect("sql injection finding");
    assert_eq!(sqli.severity, Severity::Critical);
    assert_eq!(sqli.file, "app.js");
    // source → assign → use → assign → use → sink
    assert!(sqli.trace.len() >= 4, "trace too short: {:?}", sqli.trace);
    assert!(sqli.trace.first().unwrap().label.starts_with("source:"));
    assert!(sqli.trace.last().unwrap().label.starts_with("sink:"));
    assert!(sqli.cwe.iter().any(|c| c == "CWE-89"));
    assert!(sqli.owasp.iter().any(|o| o == "A03:2021"));
}

#[test]
fn javascript_cross_function_command_injection() {
    // host flows through buildCmd() before reaching exec().
    let out = scan_dir(&fixtures().join("javascript"), base_opts());
    assert!(
        has(&out, "js.command-injection"),
        "expected cross-function taint via buildCmd"
    );
}

#[test]
fn sanitizers_suppress_findings() {
    let mut opts = base_opts();
    opts.include = vec!["safe.js".into()];
    let out = scan_dir(&fixtures().join("javascript"), opts);
    assert!(
        !has(&out, "js.sql-injection"),
        "parseInt-sanitized value must not be a SQLi finding"
    );
    assert!(
        !has(&out, "js.path-traversal"),
        "path.basename-sanitized value must not be a traversal finding"
    );
}

#[test]
fn objectscript_sqli_and_xecute() {
    let out = scan_dir(&fixtures().join("objectscript"), base_opts());
    assert!(has(&out, "os.sql-injection"), "objectscript dynamic SQL");
    assert!(
        has(&out, "os.code-injection.xecute-taint"),
        "objectscript XECUTE taint"
    );
    assert!(has(&out, "os.cmd-injection.zf"), "objectscript $ZF taint");
}

#[test]
fn pascal_sqli_and_cmd() {
    let out = scan_dir(&fixtures().join("pascal"), base_opts());
    assert!(has(&out, "pas.sql-injection"), "pascal SQL text taint");
    assert!(has(&out, "pas.cmd-injection"), "pascal WinExec taint");
}

#[test]
fn csharp_go_sinks() {
    let cs = scan_dir(&fixtures().join("csharp"), base_opts());
    assert!(has(&cs, "cs.sql-injection"));
    assert!(has(&cs, "cs.cmd-injection"));
    assert!(has(&cs, "cs.weak-crypto"));

    let go = scan_dir(&fixtures().join("go"), base_opts());
    assert!(has(&go, "go.sql-injection"));
    assert!(has(&go, "go.cmd-injection"));
}

#[test]
fn fail_on_threshold() {
    let out = scan_dir(&fixtures().join("javascript"), base_opts());
    assert!(scanner::exceeds_threshold(
        &out.findings,
        Some(Severity::High)
    ));
    assert!(!scanner::exceeds_threshold(&out.findings, None));
}

#[test]
fn cache_reuse_is_transparent() {
    // Copy fixtures into a temp dir so the cache write doesn't touch the repo.
    let tmp = tempfile::tempdir().unwrap();
    let src = fixtures().join("javascript").join("app.js");
    std::fs::copy(&src, tmp.path().join("app.js")).unwrap();

    let mut opts = base_opts();
    opts.use_cache = true;
    let first = scan_dir(tmp.path(), opts.clone());
    assert_eq!(first.stats.files_scanned, 1);
    assert_eq!(first.stats.files_from_cache, 0);

    let second = scan_dir(tmp.path(), opts);
    assert_eq!(
        second.stats.files_scanned, 0,
        "second scan should hit cache"
    );
    assert_eq!(second.stats.files_from_cache, 1);
    // Findings identical across cached/uncached runs.
    assert_eq!(first.findings.len(), second.findings.len());
}

#[test]
fn baseline_suppresses_known_findings() {
    let tmp = tempfile::tempdir().unwrap();
    let src = fixtures().join("javascript").join("app.js");
    std::fs::copy(&src, tmp.path().join("app.js")).unwrap();

    let (registry, ruleset) = compiled();
    let opts = base_opts();
    let out = scanner::scan(tmp.path(), &registry, &ruleset, &Config::default(), &opts).unwrap();
    assert!(!out.findings.is_empty());

    let baseline = crit_core::state::baseline::Baseline::from_findings(out.findings.iter());
    baseline.save(tmp.path()).unwrap();

    let mut opts2 = base_opts();
    opts2.compare_baseline = true;
    let out2 = scanner::scan(tmp.path(), &registry, &ruleset, &Config::default(), &opts2).unwrap();
    assert!(
        out2.findings.is_empty(),
        "baseline should suppress all known findings"
    );
    assert_eq!(out2.stats.baseline_suppressed, out.findings.len());
}

#[test]
fn fingerprints_are_stable_and_unique() {
    let out = scan_dir(&fixtures().join("javascript"), base_opts());
    let mut fps: Vec<_> = out.findings.iter().map(|f| f.fingerprint.clone()).collect();
    let total = fps.len();
    fps.sort();
    fps.dedup();
    assert_eq!(fps.len(), total, "fingerprints must be unique per finding");
    assert!(fps.iter().all(|f| f.len() == 32));
}

#[test]
fn sarif_output_is_valid_shape() {
    let (_reg, ruleset) = compiled();
    let out = scan_dir(&fixtures().join("javascript"), base_opts());
    let sarif = crit_core::output::sarif::render(&out.findings, &ruleset).unwrap();
    let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert!(!v["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .is_empty());
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), out.findings.len());
    // At least one result carries a codeFlow (taint trace).
    assert!(results.iter().any(|r| r.get("codeFlows").is_some()));
    // Every result has a partial fingerprint.
    assert!(results
        .iter()
        .all(|r| r["partialFingerprints"]["crit/v1"].is_string()));
}

#[test]
fn language_detection() {
    let reg = Registry::with_builtins().unwrap();
    assert_eq!(reg.detect(Path::new("a/b.cls")).unwrap().id, "objectscript");
    assert_eq!(reg.detect(Path::new("x.pas")).unwrap().id, "pascal");
    assert_eq!(reg.detect(Path::new("x.tsx")).unwrap().id, "tsx");
    assert!(reg.detect(Path::new("x.unknownext")).is_none());
}
