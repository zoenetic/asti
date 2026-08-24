//! Declarative name binding (crit 0.2).
//!
//! From a file's parsed tree and its language taint profile, the binder
//! extracts import/export facts and a local symbol table, then resolves each
//! call and member read to a stable *identity* — so rules can match sinks and
//! sources by what a name actually refers to (an imported `child_process.exec`
//! reached through `import {exec as run}`) rather than by its spelling.
//!
//! Everything is driven by the profile's optional `imports` / `exports` /
//! `member_access` / `method_calls` query sections. A profile that omits them
//! yields empty bindings and every callee resolves to
//! [`CalleeId::Unresolved`], which reproduces exact 0.1 text behavior — the
//! backward-compatible degradation path.

mod facts;
mod resolve;

use crate::engine::taint::paths::AccessPath;
use crate::findings::Span;
use crate::rules::compiled::CompiledProfile;
use std::collections::HashMap;
use tree_sitter::Tree;

/// What a local name refers to within a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalBinding {
    /// A named import: `local` refers to `name` from `module`. A whole-module
    /// import (`import * as m`, `const m = require(...)`) uses name `"*"`.
    Imported { module: String, name: String },
    /// A function declared in this file.
    LocalFunction,
    /// A one-hop alias to another local name (`const q = db.query`).
    AliasOf(String),
}

/// A resolved call identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalleeId {
    /// A function defined in this file.
    LocalFn(String),
    /// A function/symbol imported from `module`.
    External { module: String, name: String },
    /// A method `method` invoked on receiver expression `base`.
    Member { base: String, method: String },
    /// Unresolved: the raw callee text (reproduces 0.1 matching).
    Unresolved(String),
}

impl CalleeId {
    /// The terminal name a `resolved:` matcher's `name` compares against.
    pub fn terminal(&self) -> &str {
        match self {
            CalleeId::LocalFn(n) => n,
            CalleeId::External { name, .. } => name,
            CalleeId::Member { method, .. } => method,
            CalleeId::Unresolved(t) => t.rsplit('.').next().unwrap_or(t),
        }
    }

    /// A human-readable account of how this callee resolved, for `explain`.
    pub fn describe(&self) -> String {
        match self {
            CalleeId::LocalFn(n) => format!("local function `{n}`"),
            CalleeId::External { module, name } => {
                format!("`{name}` imported from `{module}`")
            }
            CalleeId::Member { base, method } => format!("method `{method}` on `{base}`"),
            CalleeId::Unresolved(t) => {
                format!("unresolved: no import or local function binds `{t}`")
            }
        }
    }
}

/// A call with its resolved identity and argument spans.
#[derive(Debug, Clone)]
pub struct ResolvedCall {
    pub callee: CalleeId,
    pub call_span: Span,
    pub arg_spans: Vec<Span>,
}

/// A member (field) read, e.g. `req.query.id`.
#[derive(Debug, Clone)]
pub struct ResolvedRead {
    pub path: AccessPath,
    pub span: Span,
    /// Module the base identifier resolves to, if it is an import.
    pub base_module: Option<String>,
}

/// An import fact (kept for cross-file linking in a later phase).
#[derive(Debug, Clone)]
pub struct ImportFact {
    pub module: String,
    pub name: String,
    pub local: String,
    pub span: Span,
}

/// All binding facts for one file.
#[derive(Debug, Default)]
pub struct FileBindings {
    pub module_decl: Option<String>,
    pub imports: Vec<ImportFact>,
    pub exports: Vec<String>,
    pub locals: HashMap<String, LocalBinding>,
    pub calls: Vec<ResolvedCall>,
    pub reads: Vec<ResolvedRead>,
}

impl FileBindings {
    /// Build bindings for a file. Cheap and side-effect free; returns empty
    /// bindings when the profile declares no binding sections.
    pub fn build(tree: &Tree, source: &str, profile: &CompiledProfile) -> FileBindings {
        let bytes = source.as_bytes();
        let mut b = FileBindings::default();

        facts::collect_module_decl(tree, bytes, profile, &mut b);
        facts::collect_imports(tree, bytes, profile, &mut b);
        facts::collect_exports(tree, bytes, profile, &mut b);
        facts::collect_local_functions(tree, bytes, profile, &mut b);

        // Resolution needs the local table fully populated first.
        resolve::resolve_calls(tree, bytes, profile, &mut b);
        resolve::resolve_reads(tree, bytes, profile, &mut b);
        b
    }

    /// Resolve a base identifier through one alias hop into a binding.
    pub fn resolve_local(&self, name: &str) -> Option<&LocalBinding> {
        match self.locals.get(name) {
            Some(LocalBinding::AliasOf(target)) => self.locals.get(target),
            other => other,
        }
    }
}
