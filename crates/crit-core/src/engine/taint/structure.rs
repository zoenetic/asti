//! Structural facts extracted once per (file, profile): scopes, path uses,
//! assignments, parameters, calls, and returns. Everything grammar-specific
//! comes from the compiled taint profile.

use super::paths::AccessPath;
use crate::findings::Span;
use crate::rules::compiled::CompiledProfile;
use std::collections::HashMap;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Query, Tree};

pub struct Scope {
    pub span: Span,
    pub parent: Option<usize>,
    pub name: Option<String>,
}

/// An occurrence of an access path being read.
pub struct PathUse {
    pub path: AccessPath,
    pub span: Span,
    pub scope: usize,
}

pub struct Assign {
    pub path: AccessPath,
    pub lhs_span: Span,
    pub rhs_span: Span,
    pub scope: usize,
    /// Byte at which the write becomes visible to later same-scope uses.
    pub write_byte: u32,
}

pub struct Param {
    pub name: String,
    pub span: Span,
    pub scope: usize,
    pub index: usize,
}

pub struct CallSite {
    pub span: Span,
    pub callee: Option<String>,
    pub args: Vec<Span>,
}

pub struct Return {
    pub value_span: Span,
    pub scope: usize,
}

pub struct Structure {
    pub scopes: Vec<Scope>,
    pub path_uses: Vec<PathUse>, // sorted by start byte
    pub assigns: Vec<Assign>,
    pub params: Vec<Param>,
    pub calls: Vec<CallSite>,
    pub returns: Vec<Return>,
}

fn capture_named<'t>(
    query: &Query,
    m: &tree_sitter::QueryMatch<'_, 't>,
    name: &str,
) -> Option<Node<'t>> {
    let idx = query.capture_names().iter().position(|n| *n == name)?;
    m.captures
        .iter()
        .find(|c| c.index as usize == idx)
        .map(|c| c.node)
}

fn run_query_matches<'t, F: FnMut(&Query, &tree_sitter::QueryMatch<'_, 't>)>(
    queries: &[Query],
    tree: &'t Tree,
    bytes: &[u8],
    mut f: F,
) {
    let mut cursor = tree_sitter::QueryCursor::new();
    for q in queries {
        let mut matches = cursor.matches(q, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            f(q, m);
        }
    }
}

/// First identifier-kind descendant of a node (document order), or the node
/// itself if it is an identifier kind. Used for complex LHS that is not a
/// pure dotted chain.
fn first_identifier_text(
    node: Node<'_>,
    bytes: &[u8],
    ident_kinds: &std::collections::HashSet<String>,
) -> Option<String> {
    if ident_kinds.contains(node.kind()) {
        return node.utf8_text(bytes).ok().map(|s| s.to_string());
    }
    let mut cursor = node.walk();
    let mut stack: Vec<Node> = node.named_children(&mut cursor).collect();
    stack.reverse();
    while let Some(n) = stack.pop() {
        if ident_kinds.contains(n.kind()) {
            return n.utf8_text(bytes).ok().map(|s| s.to_string());
        }
        let mut c = n.walk();
        let mut children: Vec<Node> = n.named_children(&mut c).collect();
        children.reverse();
        stack.extend(children);
    }
    None
}

/// Given an identifier node, climb to the outermost ancestor that begins at
/// the same byte and whose text is still a pure `ident(.ident)*` chain (a
/// member-access spine), returning that node and its parsed path. Falls back
/// to the identifier itself.
fn maximal_chain<'t>(ident: Node<'t>, bytes: &[u8]) -> (Node<'t>, AccessPath) {
    let start = ident.start_byte();
    let mut best = ident;
    let mut best_path = ident
        .utf8_text(bytes)
        .ok()
        .and_then(AccessPath::parse)
        .unwrap_or_else(|| AccessPath::base_only(""));
    let mut cur = ident;
    while let Some(parent) = cur.parent() {
        if parent.start_byte() != start {
            break;
        }
        match parent.utf8_text(bytes).ok().and_then(AccessPath::parse) {
            Some(p) => {
                best = parent;
                best_path = p;
                cur = parent;
            }
            None => break,
        }
    }
    (best, best_path)
}

/// Build an access path from an LHS/expression node: prefer a pure dotted
/// chain, else fall back to a base-only path on the first identifier.
fn path_of_node(
    node: Node<'_>,
    bytes: &[u8],
    ident_kinds: &std::collections::HashSet<String>,
) -> Option<AccessPath> {
    if let Ok(text) = node.utf8_text(bytes) {
        if let Some(p) = AccessPath::parse(text) {
            return Some(p);
        }
    }
    first_identifier_text(node, bytes, ident_kinds).map(AccessPath::base_only)
}

impl Structure {
    pub fn build(tree: &Tree, source: &str, profile: &CompiledProfile) -> Structure {
        let bytes = source.as_bytes();
        let root_span = Span::from_node(&tree.root_node());

        // ---- scopes ----
        let mut scopes = vec![Scope {
            span: root_span,
            parent: None,
            name: None,
        }];
        run_query_matches(&profile.functions, tree, bytes, |q, m| {
            if let Some(func) = capture_named(q, m, "function") {
                let name = capture_named(q, m, "name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    .map(|s| s.to_string());
                scopes.push(Scope {
                    span: Span::from_node(&func),
                    parent: None,
                    name,
                });
            }
        });
        scopes.sort_by_key(|s| (s.span.start_byte, std::cmp::Reverse(s.span.end_byte)));
        scopes.dedup_by(|a, b| {
            a.span == b.span && {
                if b.name.is_none() {
                    b.name = a.name.take();
                }
                true
            }
        });
        for i in 1..scopes.len() {
            let mut parent = 0;
            for j in (0..i).rev() {
                if scopes[j].span.contains(&scopes[i].span) {
                    parent = j;
                    break;
                }
            }
            scopes[i].parent = Some(parent);
        }

        let innermost = |span: &Span| -> usize {
            let mut best = 0;
            for (i, s) in scopes.iter().enumerate() {
                if s.span.contains(span)
                    && (s.span.end_byte - s.span.start_byte)
                        <= (scopes[best].span.end_byte - scopes[best].span.start_byte)
                {
                    best = i;
                }
            }
            best
        };

        // ---- path uses: maximal dotted chains rooted at real identifiers ----
        // Start only from identifier-kind nodes (never string contents or
        // other tokens that merely look like identifiers), then climb to the
        // maximal enclosing `ident(.ident)*` chain that begins at the same
        // byte (so `req` grows into `req.query.id`).
        let mut raw: Vec<(Span, AccessPath)> = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(n) = stack.pop() {
            if profile.identifiers.contains(n.kind()) {
                let (node, path) = maximal_chain(n, bytes);
                raw.push((Span::from_node(&node), path));
            }
            let mut c = n.walk();
            for child in n.children(&mut c) {
                stack.push(child);
            }
        }
        // Keep maximal spans only: sorting by (start asc, end desc) and
        // dropping any span contained in an earlier-kept one removes the field
        // sub-identifiers (`query`, `id`) that a chain already covers.
        raw.sort_by_key(|(s, _)| (s.start_byte, std::cmp::Reverse(s.end_byte)));
        let mut path_uses: Vec<PathUse> = Vec::new();
        let mut max_end = 0u32;
        for (span, path) in raw {
            if span.end_byte <= max_end {
                continue; // contained in an already-kept chain
            }
            max_end = span.end_byte;
            let scope = innermost(&span);
            path_uses.push(PathUse { path, span, scope });
        }
        path_uses.sort_by_key(|u| u.span.start_byte);

        // ---- assignments ----
        let mut assigns = Vec::new();
        run_query_matches(&profile.assignments, tree, bytes, |q, m| {
            let (Some(lhs), Some(rhs)) = (capture_named(q, m, "lhs"), capture_named(q, m, "rhs"))
            else {
                return;
            };
            let Some(path) = path_of_node(lhs, bytes, &profile.identifiers) else {
                return;
            };
            let lhs_span = Span::from_node(&lhs);
            assigns.push(Assign {
                path,
                lhs_span,
                rhs_span: Span::from_node(&rhs),
                scope: innermost(&lhs_span),
                write_byte: lhs_span.start_byte,
            });
        });
        assigns.sort_by_key(|a| a.lhs_span.start_byte);

        // ---- params ----
        let mut params = Vec::new();
        run_query_matches(&profile.params, tree, bytes, |q, m| {
            if let Some(p) = capture_named(q, m, "param") {
                if let Ok(text) = p.utf8_text(bytes) {
                    let span = Span::from_node(&p);
                    params.push(Param {
                        name: text.to_string(),
                        span,
                        scope: innermost(&span),
                        index: 0,
                    });
                }
            }
        });
        params.sort_by_key(|p| p.span.start_byte);
        params.dedup_by(|a, b| a.span == b.span);
        let mut per_scope: HashMap<usize, usize> = HashMap::new();
        for p in &mut params {
            let n = per_scope.entry(p.scope).or_insert(0);
            p.index = *n;
            *n += 1;
        }

        // ---- calls ----
        let mut calls = Vec::new();
        run_query_matches(&profile.calls, tree, bytes, |q, m| {
            let Some(call) = capture_named(q, m, "call") else {
                return;
            };
            let callee = capture_named(q, m, "callee")
                .and_then(|n| n.utf8_text(bytes).ok())
                .map(|s| s.to_string());
            let args = capture_named(q, m, "args")
                .map(|args_node| {
                    let mut c = args_node.walk();
                    args_node
                        .named_children(&mut c)
                        .map(|n| Span::from_node(&n))
                        .collect()
                })
                .unwrap_or_default();
            calls.push(CallSite {
                span: Span::from_node(&call),
                callee,
                args,
            });
        });
        calls.sort_by_key(|c| c.span.start_byte);
        calls.dedup_by(|a, b| a.span == b.span);

        // ---- returns ----
        let mut returns = Vec::new();
        run_query_matches(&profile.returns, tree, bytes, |q, m| {
            if let Some(v) = capture_named(q, m, "value") {
                let value_span = Span::from_node(&v);
                returns.push(Return {
                    scope: innermost(&value_span),
                    value_span,
                });
            }
        });

        Structure {
            scopes,
            path_uses,
            assigns,
            params,
            calls,
            returns,
        }
    }

    /// Scope chain from `scope` to the root, innermost first.
    pub fn chain(&self, scope: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut s = Some(scope);
        while let Some(cur) = s {
            out.push(cur);
            s = self.scopes[cur].parent;
        }
        out
    }

    /// Path uses whose span lies within `span`.
    pub fn uses_within<'a>(&'a self, span: &'a Span) -> impl Iterator<Item = &'a PathUse> {
        let start = self
            .path_uses
            .partition_point(|u| u.span.start_byte < span.start_byte);
        self.path_uses[start..]
            .iter()
            .take_while(move |u| u.span.end_byte <= span.end_byte)
    }
}
