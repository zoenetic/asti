//! `crit explain` introspection and the trace-shape guarantee.

use crit_core::config::Config;
use crit_core::engine;
use crit_core::languages::Registry;
use crit_core::rules::{CompiledRuleSet, LoadedRules};
use crit_core::scanner::{self, ScanOptions};
use std::path::{Path, PathBuf};

fn compiled() -> (Registry, CompiledRuleSet) {
    let registry = Registry::with_builtins().expect("registry");
    let loaded = LoadedRules::builtin().expect("builtin rules");
    let ruleset = CompiledRuleSet::compile(loaded, &registry).expect("compile");
    (registry, ruleset)
}

#[test]
fn explain_reports_verdicts_and_resolution() {
    let (_reg, ruleset) = compiled();
    let lang_rules = ruleset.for_language("javascript").unwrap();
    let src = "import { exec as run } from 'child_process';\n\
               function handler(req) {\n\
               \x20 const id = req.query.id;\n\
               \x20 db.query(\"SELECT \" + id);\n\
               \x20 run(\"ping \" + req.query.host);\n\
               }\n\
               function safe(req) {\n\
               \x20 const n = parseInt(req.query.n);\n\
               \x20 db.query(\"SELECT \" + n);\n\
               }\n";
    let ex = engine::explain("app.js", src, &lang_rules, None).unwrap();

    // Call resolution names the alias hop.
    assert!(
        ex.calls
            .iter()
            .any(|c| c.callee == "exec" && c.resolution.contains("child_process")),
        "expected `run` resolved to child_process.exec: {:?}",
        ex.calls.iter().map(|c| &c.resolution).collect::<Vec<_>>()
    );

    // The SQLi rule: tainted sink REPORTED, sanitized sink not.
    let sqli = ex
        .rules
        .iter()
        .find(|r| r.rule_id == "js.sql-injection")
        .unwrap();
    assert!(sqli.sinks.iter().any(|s| s.reported && s.line == 4));
    let clean = sqli.sinks.iter().find(|s| s.line == 9).unwrap();
    assert!(!clean.reported, "parseInt-sanitized sink must not report");
    assert!(clean.reason.contains("no tainted data") || clean.reason.contains("sanitiz"));
}

#[test]
fn explain_rule_filter_limits_output() {
    let (_reg, ruleset) = compiled();
    let lang_rules = ruleset.for_language("javascript").unwrap();
    let src = "function h(req){ db.query(req.query.id); }\n";
    let ex = engine::explain("a.js", src, &lang_rules, Some("js.sql-injection")).unwrap();
    assert!(ex.rules.iter().all(|r| r.rule_id == "js.sql-injection"));
}

/// The trace-shape guarantee, asserted in release (where debug_assert is off):
/// every emitted trace starts at a source and ends at a sink — across the
/// whole fixture corpus and a cross-file pair.
#[test]
fn every_trace_starts_source_ends_sink() {
    let (registry, ruleset) = compiled();
    let opts = ScanOptions {
        use_cache: false,
        ..Default::default()
    };

    let mut dirs: Vec<PathBuf> = Vec::new();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    dirs.push(fixtures);

    // A cross-file pair, to exercise foreign trace steps too.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("util.js"),
        "function getInput(req){ return req.query.data; }\n",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("app.js"),
        "const { getInput } = require('./util');\n\
         function h(req){ const n = getInput(req); db.query(\"x\"+n); }\n",
    )
    .unwrap();
    dirs.push(tmp.path().to_path_buf());

    let mut traces = 0;
    for dir in &dirs {
        let out = scanner::scan(dir, &registry, &ruleset, &Config::default(), &opts).unwrap();
        for f in &out.findings {
            if f.trace.is_empty() {
                continue;
            }
            traces += 1;
            assert!(
                f.trace.first().unwrap().label.starts_with("source:"),
                "{} @ {}: trace must start at a source, got {:?}",
                f.rule_id,
                f.file,
                f.trace.first().unwrap().label
            );
            assert!(
                f.trace.last().unwrap().label.starts_with("sink:"),
                "{} @ {}: trace must end at a sink",
                f.rule_id,
                f.file
            );
        }
    }
    assert!(traces > 5, "expected several taint traces, saw {traces}");
}
