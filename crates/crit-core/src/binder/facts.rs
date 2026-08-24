//! Fact extraction: imports, exports, and local function names.

use super::{FileBindings, ImportFact, LocalBinding};
use crate::findings::Span;
use crate::rules::compiled::CompiledProfile;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Query, Tree};

/// Run each query and hand every match to `f`.
pub(super) fn run_matches<'t, F: FnMut(&Query, &tree_sitter::QueryMatch<'_, 't>)>(
    queries: &[Query],
    tree: &'t Tree,
    bytes: &[u8],
    mut f: F,
) {
    let mut cursor = tree_sitter::QueryCursor::new();
    for q in queries {
        let mut m = cursor.matches(q, tree.root_node(), bytes);
        while let Some(mat) = m.next() {
            f(q, mat);
        }
    }
}

pub(super) fn cap<'t>(
    q: &Query,
    m: &tree_sitter::QueryMatch<'_, 't>,
    name: &str,
) -> Option<Node<'t>> {
    let idx = q.capture_names().iter().position(|n| *n == name)?;
    m.captures
        .iter()
        .find(|c| c.index as usize == idx)
        .map(|c| c.node)
}

pub(super) fn text<'a>(node: Node<'_>, bytes: &'a [u8]) -> Option<&'a str> {
    node.utf8_text(bytes).ok()
}

/// Strip surrounding quotes/backticks from a module string literal.
pub(super) fn unquote(s: &str) -> String {
    s.trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .to_string()
}

pub(super) fn collect_module_decl(
    _tree: &Tree,
    _bytes: &[u8],
    _profile: &CompiledProfile,
    _b: &mut FileBindings,
) {
    // Module/namespace declarations feed symbol-strategy cross-file linking,
    // which lands with the linker; no consumer in this phase.
}

pub(super) fn collect_imports(
    tree: &Tree,
    bytes: &[u8],
    profile: &CompiledProfile,
    b: &mut FileBindings,
) {
    run_matches(&profile.imports, tree, bytes, |q, m| {
        let Some(module_node) = cap(q, m, "module") else {
            return;
        };
        let Some(module) = text(module_node, bytes).map(unquote) else {
            return;
        };
        let name = cap(q, m, "name")
            .and_then(|n| text(n, bytes))
            .map(str::to_string);
        let alias = cap(q, m, "alias")
            .and_then(|n| text(n, bytes))
            .map(str::to_string);
        // local binding name: alias, else the imported name, else the last
        // path segment (whole-module import).
        let local = alias
            .clone()
            .or_else(|| name.clone())
            .unwrap_or_else(|| module.rsplit('/').next().unwrap_or(&module).to_string());
        let imported = name.clone().unwrap_or_else(|| "*".to_string());
        b.imports.push(ImportFact {
            module: module.clone(),
            name: imported.clone(),
            local: local.clone(),
            span: Span::from_node(&module_node),
        });
        b.locals.insert(
            local,
            LocalBinding::Imported {
                module,
                name: imported,
            },
        );
    });
}

pub(super) fn collect_exports(
    tree: &Tree,
    bytes: &[u8],
    profile: &CompiledProfile,
    b: &mut FileBindings,
) {
    run_matches(&profile.exports, tree, bytes, |q, m| {
        if let Some(n) = cap(q, m, "name").and_then(|n| text(n, bytes)) {
            b.exports.push(n.to_string());
        }
    });
}

pub(super) fn collect_local_functions(
    tree: &Tree,
    bytes: &[u8],
    profile: &CompiledProfile,
    b: &mut FileBindings,
) {
    run_matches(&profile.functions, tree, bytes, |q, m| {
        if let Some(n) = cap(q, m, "name").and_then(|n| text(n, bytes)) {
            // Imports take precedence over same-named local decls.
            b.locals
                .entry(n.to_string())
                .or_insert(LocalBinding::LocalFunction);
        }
    });
}
