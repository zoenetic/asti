//! Phase 2 binder + `resolved:` identity matchers. These exercise detections
//! that text/regex sink rules cannot reach: an aliased import and a method
//! receiver resolved by identity.

use crit_core::config::Config;
use crit_core::languages::Registry;
use crit_core::rules::{CompiledRuleSet, LoadedRules};
use crit_core::scanner::{self, ScanOptions};
use std::path::Path;

/// Scan `files` (name → contents) written to a temp dir with the given rule
/// YAML (no builtins), returning the fired rule ids.
fn scan_with_rule(rule_yaml: &str, files: &[(&str, &str)]) -> Vec<(String, u32)> {
    let tmp = tempfile::tempdir().unwrap();
    for (name, contents) in files {
        std::fs::write(tmp.path().join(name), contents).unwrap();
    }
    let registry = Registry::with_builtins().expect("registry");
    let mut loaded = LoadedRules::default();
    loaded.add_document(rule_yaml, "test").expect("rule parses");
    let ruleset = CompiledRuleSet::compile(loaded, &registry).expect("compile");
    assert!(
        ruleset.warnings.iter().all(|w| !w.contains("invalid")),
        "rule/profile warnings: {:?}",
        ruleset.warnings
    );
    let opts = ScanOptions {
        use_cache: false,
        ..Default::default()
    };
    let out = scanner::scan(tmp.path(), &registry, &ruleset, &Config::default(), &opts).unwrap();
    out.findings
        .iter()
        .map(|f| (f.rule_id.clone(), f.span.start.line))
        .collect()
}

const RESOLVED_EXEC: &str = r#"
rules:
  - id: test.resolved-exec
    kind: taint
    severity: critical
    category: security
    languages: [javascript]
    message: "user data reaches child_process.exec"
    sources:
      - label: request query
        resolved: { member_of: req, path: [query] }
    sinks:
      - label: child_process.exec
        resolved: { module: child_process, name: exec }
"#;

#[test]
fn resolved_sink_matches_aliased_import() {
    // `run` is an alias of child_process.exec; a text rule keyed on "exec"
    // would never match it, but identity resolution does.
    let js = "import { exec as run } from 'child_process';\n\
              function handler(req) {\n\
              \x20 run(req.query.cmd);\n\
              }\n";
    let hits = scan_with_rule(RESOLVED_EXEC, &[("app.js", js)]);
    assert!(
        hits.iter()
            .any(|(id, line)| id == "test.resolved-exec" && *line == 3),
        "aliased import sink should fire on line 3; got {hits:?}"
    );
}

#[test]
fn resolved_sink_ignores_unrelated_import() {
    // Same local name `run`, but bound to a different module — must NOT fire.
    let js = "import { run } from './safe-runner';\n\
              function handler(req) {\n\
              \x20 run(req.query.cmd);\n\
              }\n";
    let hits = scan_with_rule(RESOLVED_EXEC, &[("app.js", js)]);
    assert!(
        !hits.iter().any(|(id, _)| id == "test.resolved-exec"),
        "run from ./safe-runner is not child_process.exec; got {hits:?}"
    );
}

const RESOLVED_QUERY: &str = r#"
rules:
  - id: test.resolved-query
    kind: taint
    severity: critical
    category: security
    languages: [javascript]
    message: "user data reaches a .query() sink"
    sources:
      - label: request query
        resolved: { member_of: req, path: [query] }
    sinks:
      - label: query method
        resolved: { name: query }
"#;

#[test]
fn resolved_sink_matches_method_receiver() {
    // `this.conn.query(...)` — a member call resolved by terminal method name.
    let js = "function handler(req) {\n\
              \x20 this.conn.query(\"SELECT \" + req.query.id);\n\
              }\n";
    let hits = scan_with_rule(RESOLVED_QUERY, &[("app.js", js)]);
    assert!(
        hits.iter()
            .any(|(id, line)| id == "test.resolved-query" && *line == 2),
        "method-receiver sink should fire on line 2; got {hits:?}"
    );
}

#[test]
fn resolved_source_field_is_precise() {
    // Source is req.query.*; a read of req.cookies must not be a source.
    let js = "function handler(req) {\n\
              \x20 this.conn.query(\"SELECT \" + req.cookies.id);\n\
              }\n";
    let hits = scan_with_rule(RESOLVED_QUERY, &[("app.js", js)]);
    assert!(
        !hits.iter().any(|(id, _)| id == "test.resolved-query"),
        "req.cookies is not req.query; got {hits:?}"
    );
}

#[test]
fn resolved_rules_do_not_disturb_builtins() {
    // A profile with binding sections must leave builtin (query-based) rules
    // producing identical findings.
    let registry = Registry::with_builtins().unwrap();
    let loaded = LoadedRules::builtin().unwrap();
    let ruleset = CompiledRuleSet::compile(loaded, &registry).unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/javascript");
    let opts = ScanOptions {
        use_cache: false,
        ..Default::default()
    };
    let out = scanner::scan(&fixtures, &registry, &ruleset, &Config::default(), &opts).unwrap();
    // The known builtin SQLi finding is still present.
    assert!(out.findings.iter().any(|f| f.rule_id == "js.sql-injection"));
}
