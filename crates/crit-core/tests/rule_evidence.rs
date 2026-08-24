//! Per-rule fixture evidence: every `rules/<lang>/tests/<rule-id>/` fixture
//! directory must verify, and the committed `rules/evidence.yaml` must be in
//! sync with what the harness measures.

use crit_core::evidence;
use crit_core::languages::Registry;
use crit_core::rules::{CompiledRuleSet, LoadedRules};
use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

fn report() -> evidence::EvidenceReport {
    let registry = Registry::with_builtins().expect("registry");
    let loaded = LoadedRules::builtin().expect("builtin rules");
    let ruleset = CompiledRuleSet::compile(loaded, &registry).expect("compile");
    evidence::run(&rules_root(), &registry, &ruleset).expect("harness")
}

#[test]
fn all_rule_fixtures_verify() {
    let report = report();
    assert!(
        !report.per_rule.is_empty(),
        "no fixture directories found — expected rules/<lang>/tests/<rule-id>/"
    );
    let failures: Vec<String> = report
        .failures()
        .map(|(id, f)| format!("{id}: {f}"))
        .collect();
    assert!(
        failures.is_empty(),
        "rule fixtures failed to verify:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn evidence_file_is_in_sync() {
    let path = rules_root().join(evidence::EVIDENCE_FILE);
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "{} missing — run `crit rules verify --write-evidence`",
            path.display()
        )
    });
    let committed = evidence::EvidenceFile::parse(&committed).expect("parse committed evidence");
    let fresh = report().to_evidence_file();
    assert_eq!(
        committed.evidence, fresh.evidence,
        "rules/evidence.yaml is stale — run `crit rules verify --write-evidence`"
    );
}

#[test]
fn evidence_drives_sarif_precision() {
    let loaded = LoadedRules::builtin().expect("builtin rules");
    // A rule with verified fixtures carries a measured precision...
    let with_fixtures = loaded
        .rules
        .get("js.sql-injection")
        .expect("js.sql-injection exists");
    assert!(
        with_fixtures.precision.is_some(),
        "js.sql-injection has fixtures; precision should be measured"
    );
    // ...and precision is never author-settable from YAML (skip_deserializing).
    let doc = "rules:\n  - id: t.x\n    severity: low\n    languages: [javascript]\n    message: m\n    precision: high\n    query: '(identifier) @finding'\n";
    let mut fresh = LoadedRules::default();
    assert!(
        fresh.add_document(doc, "test").is_err(),
        "setting precision in rule YAML must be rejected"
    );
}
