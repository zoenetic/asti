//! Per-rule taint propagation: seed parameters, propagate through
//! assignments to a fixpoint over origin sets, compute function summaries,
//! and apply them at call sites — iterating so call chains f→g→h connect.
//!
//! Statement-order semantics (visibility) live in [`super::state`]: a
//! tainted binding in scope S written at byte W is visible to a use at byte U
//! iff S == use-scope and W < U, or S is a strict ancestor of use-scope
//! (position-insensitive, so closures still see later-assigned outer vars).
//! Consequences, all intentional: the hoisting/use-before-write false
//! positive is suppressed; loop-carried same-scope flows become false
//! negatives (there is no loop concept in profiles); inner-scope writes to
//! captured outer variables stay invisible, as in 0.1.

use super::state::{merge_origins, Origin, Origins, Step, TaintState, Witness};
use super::structure::Structure;
use crate::findings::Span;
use crate::state::summary_store::{PortableFunctionSummary, PortableStep};
use std::collections::HashMap;

/// Cross-file summaries reachable from this file+rule, keyed by the local name
/// each callee is invoked under.
pub type LinkedForRule = HashMap<String, PortableFunctionSummary>;

/// Convert a portable (cross-file) step back into an internal trace step.
pub(super) fn portable_to_step(p: &PortableStep) -> Step {
    Step::foreign(p.label.clone(), p.span, p.file.clone(), p.snippet.clone())
}

/// Fixpoint iterations for assignment propagation within one round.
const MAX_ASSIGN_ITERS: usize = 16;
/// Rounds of summary application (handles call chains f→g→h).
pub const MAX_SUMMARY_ROUNDS: usize = 3;

pub struct SourceMatch {
    pub span: Span,
    pub label: String,
}

/// A parameter-to-sink flow within one function, extracted for summaries.
pub struct ParamSinkRaw {
    pub func: String,
    pub index: usize,
    pub sink_span: Span,
    pub sink_label: String,
    pub steps: Vec<Step>,
}

/// How taint moves through a named function (per rule).
#[derive(Default, Clone)]
pub struct Summary {
    /// Return value carries these source origins (with provenance).
    pub returns_source: Origins,
    /// Return value carries taint from these parameter indices.
    pub returns_params: Vec<(usize, Vec<Step>)>,
}

pub struct RuleRun<'a> {
    pub structure: &'a Structure,
    pub sources: Vec<SourceMatch>,
    pub sinks: Vec<(Span, String)>,
    pub sanitizers: Vec<Span>,
    pub state: TaintState,
    /// Call-site spans that carry taint via summaries.
    pub call_taints: Vec<(Span, Origins)>,
    /// Cross-file summaries for callees invoked in this file (empty for the
    /// intra-file path).
    pub linked: LinkedForRule,
    /// Counter minting unique cross-file source origins.
    external_counter: usize,
}

impl<'a> RuleRun<'a> {
    pub fn new(
        structure: &'a Structure,
        sources: Vec<SourceMatch>,
        sinks: Vec<(Span, String)>,
        sanitizers: Vec<Span>,
        linked: LinkedForRule,
    ) -> Self {
        RuleRun {
            structure,
            sources,
            sinks,
            sanitizers,
            state: TaintState::default(),
            call_taints: Vec::new(),
            linked,
            external_counter: 0,
        }
    }

    pub fn sanitized(&self, span: &Span) -> bool {
        self.sanitizers.iter().any(|s| s.contains(span))
    }

    /// Origins visible to an expression occupying `span`, evaluated as if used
    /// at `use_byte`.
    pub fn expr_taint(&self, span: &Span, use_byte: u32) -> Origins {
        let mut out = Origins::new();

        // Direct source containment.
        for (i, src) in self.sources.iter().enumerate() {
            if span.contains(&src.span) && !self.sanitized(&src.span) {
                out.insert(
                    Origin::Source(i),
                    Witness {
                        write_byte: src.span.start_byte,
                        steps: vec![Step::local(format!("source: {}", src.label), src.span)],
                    },
                );
            }
        }

        // Tainted path uses, visible through the scope chain and statement
        // order.
        for u in self.structure.uses_within(span) {
            if self.sanitized(&u.span) {
                continue;
            }
            let chain = self.structure.chain(u.scope);
            let visible = self
                .state
                .visible(u.scope, &chain, &u.path, u.span.start_byte);
            if visible.is_empty() {
                continue;
            }
            let mut stepped = Origins::new();
            for (origin, w) in visible {
                let mut w = w;
                w.steps.push(Step::local(
                    format!("`{}` used here", render_path(u)),
                    u.span,
                ));
                stepped.insert(origin, w);
            }
            merge_origins(&mut out, &stepped);
        }

        // Taint flowing out of a summarised call.
        for (cspan, origins) in &self.call_taints {
            if span.contains(cspan) && !self.sanitized(cspan) {
                merge_origins(&mut out, origins);
            }
        }
        let _ = use_byte;
        out
    }

    /// Seed parameters with synthetic taint so summaries can be computed and
    /// caller taint can reach sinks inside callees.
    pub fn seed_params(&mut self) {
        for p in &self.structure.params {
            let mut origins = Origins::new();
            origins.insert(
                Origin::Param {
                    scope: p.scope,
                    index: p.index,
                },
                Witness {
                    write_byte: p.span.start_byte,
                    steps: vec![Step::local(format!("parameter `{}`", p.name), p.span)],
                },
            );
            let path = super::paths::AccessPath::base_only(p.name.clone());
            self.state.bind(p.scope, &path, &origins);
        }
    }

    /// Propagate through assignments until fixpoint.
    pub fn propagate(&mut self) {
        for _ in 0..MAX_ASSIGN_ITERS {
            let mut changed = false;
            for a in &self.structure.assigns {
                let origins = self.expr_taint(&a.rhs_span, a.rhs_span.start_byte);
                if origins.is_empty() {
                    continue;
                }
                // Rebind at the assignment's position, extending provenance.
                let mut bound = Origins::new();
                for (origin, w) in origins {
                    let mut w = w;
                    w.write_byte = a.write_byte;
                    w.steps.push(Step::local(
                        format!("assigned to `{}`", render_access(&a.path)),
                        a.lhs_span,
                    ));
                    bound.insert(origin, w);
                }
                if self.state.bind(a.scope, &a.path, &bound) {
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Compute per-function summaries from return statements.
    pub fn summaries(&self) -> std::collections::HashMap<String, Summary> {
        let mut out: std::collections::HashMap<String, Summary> = std::collections::HashMap::new();
        for r in &self.structure.returns {
            let Some(func_scope) = self
                .structure
                .chain(r.scope)
                .into_iter()
                .find(|&s| self.structure.scopes[s].name.is_some())
            else {
                continue;
            };
            let name = self.structure.scopes[func_scope].name.clone().unwrap();
            let origins = self.expr_taint(&r.value_span, r.value_span.start_byte);
            if origins.is_empty() {
                continue;
            }
            let entry = out.entry(name).or_default();
            for (origin, w) in origins {
                match origin {
                    // A real or cross-file source flowing to the return.
                    Origin::Source(_) | Origin::External(_) => {
                        entry.returns_source.entry(origin).or_insert(w);
                    }
                    Origin::Param { scope, index } if scope == func_scope => {
                        if !entry.returns_params.iter().any(|(i, _)| *i == index) {
                            entry.returns_params.push((index, w.steps));
                        }
                    }
                    Origin::Param { .. } => {}
                }
            }
        }
        out
    }

    /// Apply summaries at call sites, producing call-site taints. Returns true
    /// if any new call taint was added.
    pub fn apply_summaries(
        &mut self,
        summaries: &std::collections::HashMap<String, Summary>,
    ) -> bool {
        let mut changed = false;
        // Snapshot call sites to avoid borrowing self while mutating.
        let calls: Vec<(Span, Option<String>, Vec<Span>)> = self
            .structure
            .calls
            .iter()
            .map(|c| (c.span, c.callee.clone(), c.args.clone()))
            .collect();

        for (call_span, callee, args) in calls {
            let Some(callee) = callee else { continue };
            let Some(sum) = summaries.get(&callee) else {
                continue;
            };
            if self.call_taints.iter().any(|(s, _)| *s == call_span) {
                continue;
            }

            let mut new_origins = Origins::new();
            // Returned source taint.
            for (origin, w) in &sum.returns_source {
                let mut w = w.clone();
                w.steps
                    .push(Step::local(format!("returned by `{callee}`"), call_span));
                new_origins.insert(origin.clone(), w);
            }
            // Returned parameter taint, if the matching argument is
            // source-tainted.
            for (index, inner_steps) in &sum.returns_params {
                let Some(arg_span) = args.get(*index) else {
                    continue;
                };
                let arg_origins = self.expr_taint(arg_span, arg_span.start_byte);
                for (origin, w) in arg_origins {
                    if origin.is_source() {
                        let mut w = w;
                        w.steps.extend(inner_steps.iter().cloned());
                        w.steps
                            .push(Step::local(format!("returned by `{callee}`"), call_span));
                        new_origins.entry(origin).or_insert(w);
                    }
                }
            }

            if !new_origins.is_empty() {
                self.call_taints.push((call_span, new_origins));
                changed = true;
            }
        }
        changed
    }

    /// For summary extraction: which parameters reach a sink inside their
    /// owning function, with the provenance from parameter to sink.
    pub fn param_sinks(&self) -> Vec<ParamSinkRaw> {
        let mut out = Vec::new();
        for (sink_span, sink_label) in &self.sinks {
            let origins = self.expr_taint(sink_span, sink_span.start_byte);
            for (origin, w) in &origins {
                if let Origin::Param { scope, index } = origin {
                    if let Some(func) = self.structure.scopes[*scope].name.clone() {
                        out.push(ParamSinkRaw {
                            func,
                            index: *index,
                            sink_span: *sink_span,
                            sink_label: sink_label.clone(),
                            steps: w.steps.clone(),
                        });
                    }
                }
            }
        }
        out
    }

    fn next_external(&mut self) -> usize {
        let id = self.external_counter;
        self.external_counter += 1;
        id
    }

    /// Apply cross-file summaries at call sites: a callee that returns a source
    /// (or forwards a source-tainted argument to its return) taints its call
    /// site with an `External` origin carrying the dependency's provenance.
    pub fn apply_linked(&mut self) -> bool {
        if self.linked.is_empty() {
            return false;
        }
        let calls: Vec<(Span, Option<String>, Vec<Span>)> = self
            .structure
            .calls
            .iter()
            .map(|c| (c.span, c.callee.clone(), c.args.clone()))
            .collect();
        let mut changed = false;
        for (call_span, callee, args) in calls {
            let Some(callee) = callee else { continue };
            let Some(sum) = self.linked.get(&callee).cloned() else {
                continue;
            };
            if self.call_taints.iter().any(|(s, _)| *s == call_span) {
                continue;
            }
            let mut steps: Option<Vec<Step>> = None;
            if !sum.returns_source.is_empty() {
                let mut s: Vec<Step> = sum.returns_source.iter().map(portable_to_step).collect();
                s.push(Step::local(format!("returned by `{callee}`"), call_span));
                steps = Some(s);
            } else {
                for (index, inner) in &sum.returns_params {
                    let Some(arg_span) = args.get(*index) else {
                        continue;
                    };
                    let arg_origins = self.expr_taint(arg_span, arg_span.start_byte);
                    if let Some((_, w)) = arg_origins.iter().find(|(o, _)| o.is_source()) {
                        let mut s = w.steps.clone();
                        s.extend(inner.iter().map(portable_to_step));
                        s.push(Step::local(format!("returned by `{callee}`"), call_span));
                        steps = Some(s);
                        break;
                    }
                }
            }
            if let Some(steps) = steps {
                let id = self.next_external();
                let mut origins = Origins::new();
                origins.insert(
                    Origin::External(id),
                    Witness {
                        write_byte: call_span.start_byte,
                        steps,
                    },
                );
                self.call_taints.push((call_span, origins));
                changed = true;
            }
        }
        changed
    }

    /// Run seeding, propagation and summary application (intra- and cross-file)
    /// to fixpoint.
    pub fn solve(&mut self) {
        self.seed_params();
        for _ in 0..MAX_SUMMARY_ROUNDS {
            self.propagate();
            let summaries = self.summaries();
            let local_changed = self.apply_summaries(&summaries);
            let linked_changed = self.apply_linked();
            if !local_changed && !linked_changed {
                break;
            }
        }
    }
}

fn render_access(path: &super::paths::AccessPath) -> String {
    if path.fields.is_empty() {
        path.base.clone()
    } else {
        format!("{}.{}", path.base, path.fields.join("."))
    }
}

fn render_path(u: &super::structure::PathUse) -> String {
    render_access(&u.path)
}
