//! Phase 3: cross-file taint. Sources and sinks that span files, resolved
//! through imports, with two-file traces; plus cache-coherence under edits.

use crit_core::config::Config;
use crit_core::findings::Finding;
use crit_core::languages::Registry;
use crit_core::rules::{CompiledRuleSet, LoadedRules};
use crit_core::scanner::{self, ScanOptions};
use std::path::Path;

fn compiled() -> (Registry, CompiledRuleSet) {
    let registry = Registry::with_builtins().expect("registry");
    let loaded = LoadedRules::builtin().expect("builtin rules");
    let ruleset = CompiledRuleSet::compile(loaded, &registry).expect("compile");
    (registry, ruleset)
}

fn scan_files(dir: &Path, use_cache: bool) -> scanner::ScanOutcome {
    let (registry, ruleset) = compiled();
    let opts = ScanOptions {
        use_cache,
        ..Default::default()
    };
    scanner::scan(dir, &registry, &ruleset, &Config::default(), &opts).expect("scan")
}

fn write(dir: &Path, files: &[(&str, &str)]) {
    for (name, contents) in files {
        std::fs::write(dir.join(name), contents).unwrap();
    }
}

fn sqli(out: &scanner::ScanOutcome) -> Vec<&Finding> {
    out.findings
        .iter()
        .filter(|f| f.rule_id == "js.sql-injection")
        .collect()
}

/// A dependency exports a function returning request data; the caller sinks
/// it. Finding is in the caller, trace reaches into the dependency file.
#[test]
fn tainted_return_flows_across_files() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        &[
            ("util.js", "function getInput(req) {\n  return req.query.data;\n}\nmodule.exports = { getInput };\n"),
            (
                "app.js",
                "const db = require('./db');\n\
                 const { getInput } = require('./util');\n\
                 function handler(req) {\n\
                 \x20 const n = getInput(req);\n\
                 \x20 db.query(\"SELECT id = \" + n);\n\
                 }\n",
            ),
        ],
    );
    let out = scan_files(tmp.path(), false);
    let hits = sqli(&out);
    let f = hits.iter().find(|f| f.file == "app.js").unwrap_or_else(|| {
        panic!(
            "expected cross-file SQLi in app.js; got {:?}",
            out.findings
                .iter()
                .map(|f| (&f.file, &f.rule_id))
                .collect::<Vec<_>>()
        )
    });
    assert!(
        f.trace.iter().any(|s| s.file.as_deref() == Some("util.js")),
        "trace should reach into util.js: {:?}",
        f.trace
            .iter()
            .map(|s| (&s.label, &s.file))
            .collect::<Vec<_>>()
    );
}

/// A dependency exports a function that sinks its parameter; the caller passes
/// tainted data. Finding is at the call site in the caller.
#[test]
fn tainted_arg_reaches_cross_file_sink() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        &[
            (
                "dep.js",
                "const db = require('./db');\n\
                 function runQuery(fragment) {\n\
                 \x20 db.query(\"SELECT \" + fragment);\n\
                 }\n\
                 module.exports = { runQuery };\n",
            ),
            (
                "app.js",
                "const { runQuery } = require('./dep');\n\
                 function handler(req) {\n\
                 \x20 runQuery(req.query.x);\n\
                 }\n",
            ),
        ],
    );
    let out = scan_files(tmp.path(), false);
    let hits = sqli(&out);
    let f = hits.iter().find(|f| f.file == "app.js").unwrap_or_else(|| {
        panic!(
            "expected cross-file arg->sink finding in app.js; got {:?}",
            out.findings
                .iter()
                .map(|f| (&f.file, &f.rule_id))
                .collect::<Vec<_>>()
        )
    });
    assert!(
        f.trace.iter().any(|s| s.file.as_deref() == Some("dep.js")),
        "trace should reach into dep.js"
    );
}

/// A same-named function in an unrelated module must not link.
#[test]
fn unrelated_module_does_not_link() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        &[
            // getInput here is harmless (returns a constant).
            (
                "safe.js",
                "function getInput() {\n  return 42;\n}\nmodule.exports = { getInput };\n",
            ),
            (
                "app.js",
                "const db = require('./db');\n\
                 const { getInput } = require('./safe');\n\
                 function handler() {\n\
                 \x20 const n = getInput();\n\
                 \x20 db.query(\"SELECT id = \" + n);\n\
                 }\n",
            ),
        ],
    );
    let out = scan_files(tmp.path(), false);
    assert!(
        !sqli(&out).iter().any(|f| f.file == "app.js"),
        "getInput from ./safe returns a constant; no taint"
    );
}

/// Editing a dependency re-evaluates its dependents through the link
/// fingerprint: warm results equal cold results after a mutation.
#[test]
fn cache_coherent_across_dependency_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    write(
        dir,
        &[
            (
                "util.js",
                "function getInput(req) {\n  return req.query.data;\n}\n",
            ),
            (
                "app.js",
                "const db = require('./db');\n\
                 const { getInput } = require('./util');\n\
                 function handler(req) {\n\
                 \x20 const n = getInput(req);\n\
                 \x20 db.query(\"SELECT id = \" + n);\n\
                 }\n",
            ),
        ],
    );
    // Warm the cache, then scan again warm — the dependent finding persists.
    let first = scan_files(dir, true);
    assert!(sqli(&first).iter().any(|f| f.file == "app.js"));
    let warm = scan_files(dir, true);
    assert_eq!(
        sqli(&warm).iter().filter(|f| f.file == "app.js").count(),
        sqli(&first).iter().filter(|f| f.file == "app.js").count(),
        "warm scan must match cold scan"
    );

    // Now make the dependency safe. app.js is UNCHANGED, but its finding must
    // disappear — the link fingerprint invalidated its cache entry.
    std::fs::write(
        dir.join("util.js"),
        "function getInput(req) {\n  return \"constant\";\n}\n",
    )
    .unwrap();
    let after = scan_files(dir, true);
    assert!(
        !sqli(&after).iter().any(|f| f.file == "app.js"),
        "editing util.js to be safe must clear the finding in unchanged app.js"
    );

    // A cold (no-cache) scan of the same tree agrees.
    let cold = scan_files(dir, false);
    assert!(!sqli(&cold).iter().any(|f| f.file == "app.js"));
}
