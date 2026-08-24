//! Bridge from identity (`resolved:`) matchers to the taint engine's span
//! lists. Each matcher is evaluated against the binder's resolved calls and
//! member reads, producing the same `(Span, label)` pairs the query-based
//! collector produces — so the solver downstream is unchanged.

use crate::binder::{CalleeId, FileBindings};
use crate::findings::Span;
use crate::rules::compiled::CompiledResolvedMatcher;

/// Does a call identity satisfy a matcher's name + module constraints?
fn call_matches(m: &CompiledResolvedMatcher, callee: &CalleeId) -> bool {
    // Name (required for call matchers) must equal the terminal name.
    match &m.name {
        Some(name) if callee.terminal() == name => {}
        _ => return false,
    }
    match (&m.module, callee) {
        // No module constraint: resolved forms always match; text (Unresolved)
        // only when explicitly opted in.
        (None, CalleeId::Unresolved(_)) => m.match_unresolved,
        (None, _) => true,
        // Module constraint against resolved identities.
        (Some(want), CalleeId::External { module, .. }) => module == want,
        (Some(want), CalleeId::Member { base, .. }) => base == want,
        (Some(_), _) => false,
    }
}

/// Sink spans: the matched call's argument at `arg_index` (or every argument).
pub fn sink_spans(
    matchers: &[CompiledResolvedMatcher],
    bindings: &FileBindings,
) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for m in matchers {
        for call in &bindings.calls {
            if !call_matches(m, &call.callee) {
                continue;
            }
            let label = m
                .label
                .clone()
                .unwrap_or_else(|| "dangerous sink".to_string());
            match m.arg_index {
                Some(i) => {
                    if let Some(span) = call.arg_spans.get(i) {
                        out.push((*span, label));
                    }
                }
                None => {
                    for span in &call.arg_spans {
                        out.push((*span, label.clone()));
                    }
                }
            }
        }
    }
    out
}

/// Sanitizer spans: the whole matched call cleanses its result.
pub fn sanitizer_spans(matchers: &[CompiledResolvedMatcher], bindings: &FileBindings) -> Vec<Span> {
    let mut out = Vec::new();
    for m in matchers {
        for call in &bindings.calls {
            if call_matches(m, &call.callee) {
                out.push(call.call_span);
            }
        }
    }
    out
}

/// Source spans: member reads whose base + field chain satisfy the matcher.
pub fn source_spans(
    matchers: &[CompiledResolvedMatcher],
    bindings: &FileBindings,
) -> Vec<(Span, String)> {
    let mut out = Vec::new();
    for m in matchers {
        for read in &bindings.reads {
            // Base constraint: an import module or a literal receiver name.
            let base_ok = match (&m.module, &m.member_of) {
                (Some(module), _) => read.base_module.as_deref() == Some(module.as_str()),
                (None, Some(base)) => &read.path.base == base,
                (None, None) => true,
            };
            if !base_ok {
                continue;
            }
            // Field chain: matcher path must be a prefix of the read's fields.
            if !read.path.fields.starts_with(m.path.as_slice()) {
                continue;
            }
            let label = m
                .label
                .clone()
                .unwrap_or_else(|| "tainted data".to_string());
            out.push((read.span, label));
        }
    }
    out
}
