//! Sink evaluation: for each sink, resolve the strongest available taint
//! (a real `Source` origin, else a `Param` origin stitched back to a source
//! through the owning function's call sites), then assemble a forward-ordered
//! trace and emit a finding.

use super::solve::RuleRun;
use super::state::{Origin, Step};
use crate::findings::{Finding, Span, TraceStep};
use crate::rules::compiled::CompiledTaint;
use crate::rules::LanguageRules;

/// Depth of call-site stitching for param-origin taint (f→g→h).
const MAX_STITCH_DEPTH: usize = 3;

impl<'a> RuleRun<'a> {
    /// Try to connect a param-origin taint at a sink back to a real source
    /// through call sites of the owning function.
    fn stitch(&self, scope: usize, index: usize, tail: &[Step], depth: usize) -> Option<Vec<Step>> {
        if depth >= MAX_STITCH_DEPTH {
            return None;
        }
        let fname = self.structure.scopes[scope].name.as_deref()?;
        for call in &self.structure.calls {
            if call.callee.as_deref() != Some(fname) {
                continue;
            }
            let Some(arg_span) = call.args.get(index) else {
                continue;
            };
            let arg_origins = self.expr_taint(arg_span, arg_span.start_byte);
            // Prefer a direct source-tainted argument.
            if let Some((_, w)) = arg_origins.iter().find(|(o, _)| o.is_source()) {
                let mut steps = w.steps.clone();
                steps.push(Step::local(format!("passed to `{fname}`"), call.span));
                steps.extend(tail.iter().cloned());
                return Some(steps);
            }
            // Else follow a param-tainted argument one level up.
            for (origin, w) in &arg_origins {
                if let Origin::Param {
                    scope: s2,
                    index: i2,
                } = origin
                {
                    let mut deeper_tail =
                        vec![Step::local(format!("passed to `{fname}`"), call.span)];
                    deeper_tail.extend(tail.iter().cloned());
                    let _ = w;
                    if let Some(steps) = self.stitch(*s2, *i2, &deeper_tail, depth + 1) {
                        return Some(steps);
                    }
                }
            }
        }
        None
    }

    /// Evaluate all sinks and push findings.
    pub fn report(
        &self,
        rel_path: &str,
        source: &str,
        rules: &LanguageRules,
        taint_rule: &CompiledTaint,
        out: &mut Vec<Finding>,
    ) {
        let mut reported: std::collections::HashSet<(u32, u32)> = std::collections::HashSet::new();
        for (sink_span, sink_label) in &self.sinks {
            let origins = self.expr_taint(sink_span, sink_span.start_byte);
            if origins.is_empty() {
                continue;
            }
            // Prefer a real (or cross-file) source origin; else stitch a param
            // origin back to a source through this file's call sites.
            let resolved: Option<Vec<Step>> =
                if let Some((_, w)) = origins.iter().find(|(o, _)| o.is_source()) {
                    Some(w.steps.clone())
                } else {
                    origins.iter().find_map(|(o, w)| match o {
                        Origin::Param { scope, index } => self.stitch(*scope, *index, &w.steps, 0),
                        Origin::Source(_) | Origin::External(_) => None,
                    })
                };
            let Some(steps) = resolved else { continue };
            if !reported.insert((sink_span.start_byte, sink_span.end_byte)) {
                continue;
            }

            let mut trace = build_trace(source, &steps, sink_span, sink_label);
            normalize_trace(&mut trace);

            let mut finding = crate::engine::base_finding(
                &taint_rule.rule,
                &rules.language.id,
                rel_path,
                source,
                *sink_span,
                taint_rule.rule.message.clone(),
            );
            finding.trace = trace;
            out.push(finding);
        }

        self.report_cross_file(rel_path, source, rules, taint_rule, &mut reported, out);
    }

    /// Read-only verdict for one sink span, for `crit explain`: whether it is
    /// reported and the reason.
    pub fn explain_sink(&self, sink_span: &Span) -> (bool, String) {
        let origins = self.expr_taint(sink_span, sink_span.start_byte);
        if origins.iter().any(|(o, _)| o.is_source()) {
            return (true, "a source reaches this sink".to_string());
        }
        for (o, w) in &origins {
            if let Origin::Param { scope, index } = o {
                if self.stitch(*scope, *index, &w.steps, 0).is_some() {
                    return (
                        true,
                        "a parameter stitched back to a source reaches this sink".to_string(),
                    );
                }
            }
        }
        if origins
            .iter()
            .any(|(o, _)| matches!(o, Origin::Param { .. }))
        {
            return (
                false,
                "reached only by an unstitched parameter (no source-tainted call site)".to_string(),
            );
        }
        if self.sanitized(sink_span) {
            return (false, "the sink is sanitized".to_string());
        }
        (false, "no tainted data reaches this sink".to_string())
    }

    /// Emit findings where a source-tainted argument in this file is passed to
    /// a linked callee that reaches a sink inside it. The finding is located
    /// at the call site here; its trace continues into the dependency file.
    fn report_cross_file(
        &self,
        rel_path: &str,
        source: &str,
        rules: &LanguageRules,
        taint_rule: &CompiledTaint,
        reported: &mut std::collections::HashSet<(u32, u32)>,
        out: &mut Vec<Finding>,
    ) {
        if self.linked.is_empty() {
            return;
        }
        for call in &self.structure.calls {
            let Some(callee) = &call.callee else { continue };
            let Some(sum) = self.linked.get(callee) else {
                continue;
            };
            for ps in &sum.param_to_sink {
                let Some(arg_span) = call.args.get(ps.index) else {
                    continue;
                };
                let origins = self.expr_taint(arg_span, arg_span.start_byte);
                let Some((_, w)) = origins.iter().find(|(o, _)| o.is_source()) else {
                    continue;
                };
                let loc = *arg_span;
                if !reported.insert((loc.start_byte, loc.end_byte)) {
                    continue;
                }
                // Trace: caller-side source → "passed to callee" → callee-side
                // steps → foreign sink.
                let mut steps = w.steps.clone();
                steps.push(Step::local(format!("passed to `{callee}`"), call.span));
                steps.extend(ps.steps.iter().map(super::solve::portable_to_step));
                let mut trace = build_trace(source, &steps, &ps.sink_step.span, &ps.sink_label);
                // The sink lives in the dependency; retag the appended sink step.
                if let Some(last) = trace.last_mut() {
                    last.file = Some(ps.sink_step.file.clone());
                    last.snippet = ps.sink_step.snippet.clone();
                }
                normalize_trace(&mut trace);

                let mut finding = crate::engine::base_finding(
                    &taint_rule.rule,
                    &rules.language.id,
                    rel_path,
                    source,
                    loc,
                    taint_rule.rule.message.clone(),
                );
                finding.trace = trace;
                out.push(finding);
            }
        }
    }
}

fn build_trace(source: &str, steps: &[Step], sink_span: &Span, sink_label: &str) -> Vec<TraceStep> {
    let mut trace: Vec<TraceStep> = steps
        .iter()
        .map(|s| TraceStep {
            label: s.label.clone(),
            span: s.span,
            // Foreign steps carry a baked snippet; local steps read the live
            // source.
            snippet: s
                .snippet
                .clone()
                .unwrap_or_else(|| crate::engine::snippet_at(source, &s.span)),
            file: s.file.clone(),
        })
        .collect();
    trace.push(TraceStep {
        label: format!("sink: {sink_label}"),
        span: *sink_span,
        snippet: crate::engine::snippet_at(source, sink_span),
        file: None,
    });
    trace
}

/// Collapse consecutive steps on the same line with the same label, keeping
/// traces tight without disturbing dataflow order, and enforce the trace
/// shape invariant: every emitted trace starts at a source and ends at a sink.
fn normalize_trace(trace: &mut Vec<TraceStep>) {
    trace.dedup_by(|b, a| a.span.start.line == b.span.start.line && a.label == b.label);
    debug_assert!(
        trace
            .first()
            .is_some_and(|s| s.label.starts_with("source:")),
        "trace must start with a source step: {:?}",
        trace.iter().map(|s| &s.label).collect::<Vec<_>>()
    );
    debug_assert!(
        trace.last().is_some_and(|s| s.label.starts_with("sink:")),
        "trace must end with a sink step"
    );
}
