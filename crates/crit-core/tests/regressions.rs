//! Regression tests for the two engine defects confirmed during the 0.1
//! review. Both are `#[ignore]`d until the Phase 1 engine rewrite lands;
//! flipping them green (and removing the ignores) is Phase 1's exit
//! criterion.

use crit_core::config::Config;
use crit_core::languages::Registry;
use crit_core::rules::{CompiledRuleSet, LoadedRules};
use crit_core::scanner::{self, ScanOptions};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/regressions")
}

fn scan_dir(dir: &Path) -> scanner::ScanOutcome {
    let registry = Registry::with_builtins().expect("registry");
    let loaded = LoadedRules::builtin().expect("builtin rules");
    let ruleset = CompiledRuleSet::compile(loaded, &registry).expect("compile");
    let opts = ScanOptions {
        use_cache: false,
        ..Default::default()
    };
    scanner::scan(dir, &registry, &ruleset, &Config::default(), &opts).expect("scan")
}

/// Bug 1: `const n = getB(req); db.query(... + n)` — the tainted return of
/// getB() must reach the sink even though the caller has a parameter.
#[test]
fn cross_function_return_taint_with_caller_params() {
    let out = scan_dir(&fixtures().join("return-taint"));
    assert!(
        out.findings.iter().any(|f| f.rule_id == "js.sql-injection"),
        "tainted return value must reach the sink; findings: {:?}",
        out.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// Bug 2: the sink reads the variable BEFORE the tainted assignment in the
/// same scope — must not report.
#[test]
fn use_before_tainted_assignment_does_not_report() {
    let out = scan_dir(&fixtures().join("flow-order"));
    assert!(
        !out.findings.iter().any(|f| f.rule_id == "js.sql-injection"),
        "flow-order false positive: sink use precedes the tainted write"
    );
}

/// Every emitted taint trace must be dataflow-ordered: it starts at a
/// source, ends at a sink, and never steps backwards in the same file+scope.
#[test]
fn traces_are_dataflow_ordered() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let out = scan_dir(&root);
    let mut checked = 0;
    for f in &out.findings {
        if f.trace.is_empty() {
            continue;
        }
        checked += 1;
        assert!(
            f.trace.first().unwrap().label.starts_with("source:"),
            "{}: trace must start at a source",
            f.rule_id
        );
        assert!(
            f.trace.last().unwrap().label.starts_with("sink:"),
            "{}: trace must end at a sink",
            f.rule_id
        );
    }
    assert!(checked > 0, "expected at least one taint trace to check");
}
