//! Resolution: turn call and member-access syntax into identities.

use super::facts::{cap, run_matches, text};
use super::{CalleeId, FileBindings, LocalBinding, ResolvedCall, ResolvedRead};
use crate::engine::taint::paths::AccessPath;
use crate::findings::Span;
use tree_sitter::{Node, Tree};

fn arg_spans(args: Option<Node<'_>>) -> Vec<Span> {
    args.map(|node| {
        let mut c = node.walk();
        node.named_children(&mut c)
            .map(|n| Span::from_node(&n))
            .collect()
    })
    .unwrap_or_default()
}

/// Resolve a bare callee name through the local table.
fn resolve_bare(name: &str, b: &FileBindings) -> CalleeId {
    match b.resolve_local(name) {
        Some(LocalBinding::Imported { module, name: n }) if n != "*" => CalleeId::External {
            module: module.clone(),
            name: n.clone(),
        },
        Some(LocalBinding::LocalFunction) => CalleeId::LocalFn(name.to_string()),
        _ => CalleeId::Unresolved(name.to_string()),
    }
}

pub(super) fn resolve_calls(
    tree: &Tree,
    bytes: &[u8],
    profile: &crate::rules::compiled::CompiledProfile,
    b: &mut FileBindings,
) {
    let mut calls: Vec<ResolvedCall> = Vec::new();

    // Bare-identifier calls (profile `calls`).
    run_matches(&profile.calls, tree, bytes, |q, m| {
        let Some(call) = cap(q, m, "call") else {
            return;
        };
        let callee = match cap(q, m, "callee").and_then(|n| text(n, bytes)) {
            Some(c) => resolve_bare(c, b),
            None => return,
        };
        calls.push(ResolvedCall {
            callee,
            call_span: Span::from_node(&call),
            arg_spans: arg_spans(cap(q, m, "args")),
        });
    });

    // Method calls (profile `method_calls`): receiver.method(args).
    run_matches(&profile.method_calls, tree, bytes, |q, m| {
        let Some(call) = cap(q, m, "call") else {
            return;
        };
        let Some(method) = cap(q, m, "method").and_then(|n| text(n, bytes)) else {
            return;
        };
        let receiver = cap(q, m, "receiver")
            .and_then(|n| text(n, bytes))
            .unwrap_or("");
        let base = AccessPath::parse(receiver).map(|p| p.base);
        // A method on a whole-module import resolves to that module's symbol.
        let callee = match base.as_deref().and_then(|base| b.resolve_local(base)) {
            Some(LocalBinding::Imported { module, name }) if name == "*" => CalleeId::External {
                module: module.clone(),
                name: method.to_string(),
            },
            _ => CalleeId::Member {
                base: receiver.to_string(),
                method: method.to_string(),
            },
        };
        calls.push(ResolvedCall {
            callee,
            call_span: Span::from_node(&call),
            arg_spans: arg_spans(cap(q, m, "args")),
        });
    });

    calls.sort_by_key(|c| (c.call_span.start_byte, c.call_span.end_byte));
    calls.dedup_by(|a, b| a.call_span == b.call_span);
    b.calls = calls;
}

pub(super) fn resolve_reads(
    tree: &Tree,
    bytes: &[u8],
    profile: &crate::rules::compiled::CompiledProfile,
    b: &mut FileBindings,
) {
    // Collect maximal member-access chains, mirroring the taint engine's
    // path-use extraction (longest chain per start byte wins).
    let mut raw: Vec<(Span, AccessPath)> = Vec::new();
    run_matches(&profile.member_access, tree, bytes, |q, m| {
        if let Some(access) = cap(q, m, "access") {
            if let Some(p) = text(access, bytes).and_then(AccessPath::parse) {
                raw.push((Span::from_node(&access), p));
            }
        }
    });
    raw.sort_by_key(|(s, _)| (s.start_byte, std::cmp::Reverse(s.end_byte)));

    let mut reads: Vec<ResolvedRead> = Vec::new();
    let mut max_end = 0u32;
    for (span, path) in raw {
        if span.end_byte <= max_end {
            continue;
        }
        max_end = span.end_byte;
        let base_module = match b.resolve_local(&path.base) {
            Some(LocalBinding::Imported { module, .. }) => Some(module.clone()),
            _ => None,
        };
        reads.push(ResolvedRead {
            path,
            span,
            base_module,
        });
    }
    b.reads = reads;
}
