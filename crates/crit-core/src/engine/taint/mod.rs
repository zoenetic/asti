//! Intra-file taint analysis (crit 0.2).
//!
//! The engine is language-agnostic: everything grammar-specific comes from
//! the language's compiled taint profile (scopes, assignments, parameters,
//! calls, returns, identifier kinds) and from each rule's
//! source/sink/sanitizer queries.
//!
//! Semantics, in one place:
//! * **Origin sets.** Each access path carries a *set* of taint origins, not a
//!   single flag, so a value can hold a real `Source` taint and a synthetic
//!   `Param` taint at once — neither masks the other.
//! * **Statement order.** A same-scope use is tainted only by assignments that
//!   textually precede it; cross-scope (closure) reads stay order-insensitive.
//!   See [`state::TaintState::visible`].
//! * **Field sensitivity.** Taint is tracked per access path with prefix /
//!   extension overlap: tainting `o` reaches `o.v`, and a tainted `o.v`
//!   reaches a read of `o`, but `o.a` and `o.b` stay disjoint.
//! * **Summaries.** Per-function summaries connect flows across functions in
//!   the same file, in both directions, and are structured to become
//!   cross-file artifacts in a later release.

pub mod paths;
mod resolved;
mod sinks;
mod solve;
mod state;
mod structure;

pub mod explain;

pub use structure::Structure;

use crate::binder::FileBindings;
use crate::findings::{Finding, Span};
use crate::rules::compiled::{CompiledProfile, CompiledTaint, CompiledTaintQuery};
use crate::rules::LanguageRules;
use crate::state::summary_store::{ParamSink, PortableFunctionSummary, PortableStep};
use solve::{LinkedForRule, RuleRun, SourceMatch};
use std::collections::{BTreeMap, HashMap};
use streaming_iterator::StreamingIterator;
use tree_sitter::{QueryCursor, Tree};

/// Cross-file summaries available to a file, keyed by rule id then callee name.
pub type FileLinked = HashMap<String, LinkedForRule>;

fn needs_binder(rules: &LanguageRules) -> bool {
    rules.taints.iter().any(|t| {
        !t.resolved_sources.is_empty()
            || !t.resolved_sinks.is_empty()
            || !t.resolved_sanitizers.is_empty()
    })
}

/// Collect a rule's source/sink/sanitizer spans (query + identity matchers).
fn rule_spans(
    tree: &Tree,
    bytes: &[u8],
    bindings: &FileBindings,
    taint_rule: &CompiledTaint,
) -> (Vec<SourceMatch>, Vec<(Span, String)>, Vec<Span>) {
    let mut source_spans = collect_taint_query(&taint_rule.sources, tree, bytes, "tainted data");
    source_spans.extend(resolved::source_spans(
        &taint_rule.resolved_sources,
        bindings,
    ));
    let sources = source_spans
        .into_iter()
        .map(|(span, label)| SourceMatch { span, label })
        .collect();
    let mut sinks = collect_taint_query(&taint_rule.sinks, tree, bytes, "dangerous sink");
    sinks.extend(resolved::sink_spans(&taint_rule.resolved_sinks, bindings));
    let mut sanitizers: Vec<Span> = collect_taint_query(&taint_rule.sanitizers, tree, bytes, "")
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    sanitizers.extend(resolved::sanitizer_spans(
        &taint_rule.resolved_sanitizers,
        bindings,
    ));
    (sources, sinks, sanitizers)
}

/// Run all taint rules over one parsed file, applying any cross-file summaries
/// reachable from it. `linked` is empty for a pure intra-file scan.
pub fn run_taint(
    rel_path: &str,
    source: &str,
    tree: &Tree,
    rules: &LanguageRules,
    profile: &CompiledProfile,
    linked: &FileLinked,
    out: &mut Vec<Finding>,
) {
    if rules.taints.is_empty() {
        return;
    }
    let bytes = source.as_bytes();
    let structure = Structure::build(tree, source, profile);
    let bindings = if needs_binder(rules) {
        FileBindings::build(tree, source, profile)
    } else {
        FileBindings::default()
    };

    for taint_rule in &rules.taints {
        let rule_linked = linked.get(&taint_rule.rule.id).cloned().unwrap_or_default();
        let (sources, sinks, sanitizers) = rule_spans(tree, bytes, &bindings, taint_rule);
        // Something to taint (a source, a param, or a cross-file return), and
        // somewhere for it to go (a local sink or a cross-file param→sink).
        let has_taint =
            !sources.is_empty() || !structure.params.is_empty() || !rule_linked.is_empty();
        let has_sink =
            !sinks.is_empty() || rule_linked.values().any(|s| !s.param_to_sink.is_empty());
        if !has_taint || !has_sink {
            continue;
        }
        let mut run = RuleRun::new(&structure, sources, sinks, sanitizers, rule_linked);
        run.solve();
        run.report(rel_path, source, rules, taint_rule, out);
    }
}

/// Extract this file's per-rule function summaries (intra-file facts) for
/// cross-file linking.
pub fn extract_summaries(
    source: &str,
    tree: &Tree,
    rules: &LanguageRules,
    profile: &CompiledProfile,
) -> BTreeMap<String, Vec<PortableFunctionSummary>> {
    let mut out = BTreeMap::new();
    if rules.taints.is_empty() {
        return out;
    }
    let bytes = source.as_bytes();
    let structure = Structure::build(tree, source, profile);
    let bindings = if needs_binder(rules) {
        FileBindings::build(tree, source, profile)
    } else {
        FileBindings::default()
    };

    for taint_rule in &rules.taints {
        let (sources, sinks, sanitizers) = rule_spans(tree, bytes, &bindings, taint_rule);
        if sinks.is_empty() && sources.is_empty() {
            continue;
        }
        let mut run = RuleRun::new(&structure, sources, sinks, sanitizers, LinkedForRule::new());
        run.solve();

        // Merge return-facts and param→sink facts per function name.
        let mut funcs: HashMap<String, PortableFunctionSummary> = HashMap::new();
        for (name, sum) in run.summaries() {
            let entry = funcs.entry(name.clone()).or_default();
            entry.name = name;
            if let Some((_, w)) = sum.returns_source.iter().next() {
                entry.returns_source = w.steps.iter().map(|s| portable(s, source)).collect();
            }
            entry.returns_params = sum
                .returns_params
                .into_iter()
                .map(|(i, steps)| (i, steps.iter().map(|s| portable(s, source)).collect()))
                .collect();
        }
        for ps in run.param_sinks() {
            let entry = funcs.entry(ps.func.clone()).or_default();
            entry.name = ps.func;
            entry.param_to_sink.push(ParamSink {
                index: ps.index,
                sink_label: ps.sink_label,
                sink_step: PortableStep {
                    label: "sink".to_string(),
                    span: ps.sink_span,
                    file: String::new(), // filled with the file path by the caller
                    snippet: crate::engine::snippet_at(source, &ps.sink_span),
                },
                steps: ps.steps.iter().map(|s| portable(s, source)).collect(),
            });
        }
        if !funcs.is_empty() {
            let mut v: Vec<_> = funcs.into_values().collect();
            v.sort_by(|a, b| a.name.cmp(&b.name));
            out.insert(taint_rule.rule.id.clone(), v);
        }
    }
    out
}

/// Build a structured explanation of one file's taint analysis (read-only;
/// rebuilds the same facts a scan would and queries them).
pub fn explain(
    source: &str,
    tree: &Tree,
    rules: &LanguageRules,
    profile: &CompiledProfile,
    rule_filter: Option<&str>,
    linked: &FileLinked,
) -> (
    Vec<explain::ScopeInfo>,
    Vec<explain::CallInfo>,
    Vec<explain::RuleExplain>,
) {
    let bytes = source.as_bytes();
    let structure = Structure::build(tree, source, profile);
    let bindings = FileBindings::build(tree, source, profile);

    let scopes = structure
        .scopes
        .iter()
        .filter_map(|s| {
            s.name.clone().map(|name| explain::ScopeInfo {
                name,
                start_line: s.span.start.line,
                end_line: s.span.end.line,
            })
        })
        .collect();

    let calls = bindings
        .calls
        .iter()
        .map(|c| explain::CallInfo {
            line: c.call_span.start.line,
            callee: c.callee.terminal().to_string(),
            resolution: c.callee.describe(),
        })
        .collect();

    let mut rule_explains = Vec::new();
    for taint_rule in &rules.taints {
        if let Some(want) = rule_filter {
            if taint_rule.rule.id != want {
                continue;
            }
        }
        let rule_linked = linked.get(&taint_rule.rule.id).cloned().unwrap_or_default();
        let (sources, sinks, sanitizers) = rule_spans(tree, bytes, &bindings, taint_rule);
        if sources.is_empty() && structure.params.is_empty() && rule_linked.is_empty() {
            continue;
        }
        let mut source_locs: Vec<explain::Loc> = sources
            .iter()
            .map(|s| explain::Loc {
                line: s.span.start.line,
                column: s.span.start.column,
                label: s.label.clone(),
                snippet: crate::engine::snippet_at(source, &s.span),
            })
            .collect();
        // Overlapping member reads (`req.query` and `req.query.id`) match the
        // same source at one position; collapse for a readable listing.
        source_locs.dedup_by(|a, b| a.line == b.line && a.column == b.column && a.label == b.label);
        let linked_names: Vec<String> = rule_linked.keys().cloned().collect();

        let mut run = RuleRun::new(&structure, sources, sinks, sanitizers, rule_linked);
        run.solve();
        let sink_verdicts = run
            .sinks
            .iter()
            .map(|(span, _)| {
                let (reported, reason) = run.explain_sink(span);
                explain::SinkVerdict {
                    line: span.start.line,
                    column: span.start.column,
                    snippet: crate::engine::snippet_at(source, span),
                    reported,
                    reason,
                }
            })
            .collect();

        rule_explains.push(explain::RuleExplain {
            rule_id: taint_rule.rule.id.clone(),
            sources: source_locs,
            sinks: sink_verdicts,
            linked: linked_names,
        });
    }
    (scopes, calls, rule_explains)
}

/// Convert an internal step to a portable one, baking the local snippet.
fn portable(s: &state::Step, source: &str) -> PortableStep {
    PortableStep {
        label: s.label.clone(),
        span: s.span,
        file: s.file.clone().unwrap_or_default(),
        snippet: s
            .snippet
            .clone()
            .unwrap_or_else(|| crate::engine::snippet_at(source, &s.span)),
    }
}

/// Collect the marker-captured spans of a set of source/sink/sanitizer
/// queries, with their labels.
fn collect_taint_query(
    set: &[CompiledTaintQuery],
    tree: &Tree,
    bytes: &[u8],
    default_label: &str,
) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    let mut cursor = QueryCursor::new();
    for tq in set {
        let mut matches = cursor.matches(&tq.query, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            for cap in m.captures {
                if cap.index == tq.capture_index {
                    out.push((
                        Span::from_node(&cap.node),
                        tq.label
                            .clone()
                            .unwrap_or_else(|| default_label.to_string()),
                    ));
                }
            }
        }
    }
    out.sort_by_key(|(s, _)| (s.start_byte, s.end_byte));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}
