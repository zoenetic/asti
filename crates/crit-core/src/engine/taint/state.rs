//! The taint lattice: origins, provenance witnesses, and the per-file taint
//! state store keyed by (scope, access-path).
//!
//! Taint is a SET of origins per path, not a single flag. This is what lets a
//! variable simultaneously carry a real `Source` taint (from a summarised
//! call) and a synthetic `Param` taint (from a caller argument) without one
//! masking the other — the return-taint masking bug of 0.1.

use super::paths::AccessPath;
use crate::findings::Span;
use std::collections::BTreeMap;
use std::collections::HashMap;

/// Where a tainted value ultimately came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// Index into the rule's matched source list — a real, reportable flow.
    Source(usize),
    /// A source reached through a cross-file summary (its provenance lives in
    /// the carrying witness). Reportable, like `Source`.
    External(usize),
    /// Synthetic: the value of parameter `index` of function scope `scope`.
    /// Used to build summaries and to carry caller taint into callees; never
    /// reported directly (must be stitched back to a `Source` first).
    Param { scope: usize, index: usize },
}

impl Origin {
    pub fn is_source(&self) -> bool {
        matches!(self, Origin::Source(_) | Origin::External(_))
    }
}

/// One step in a provenance trace. `file`/`snippet` are `None` for steps in
/// the file being analysed (the snippet is read from the live source at
/// trace-build time) and `Some(..)` for steps imported from a cross-file
/// summary, whose source line is baked in.
#[derive(Debug, Clone)]
pub struct Step {
    pub label: String,
    pub span: Span,
    pub file: Option<String>,
    pub snippet: Option<String>,
}

impl Step {
    /// A step in the file currently being analysed.
    pub fn local(label: String, span: Span) -> Self {
        Step {
            label,
            span,
            file: None,
            snippet: None,
        }
    }

    /// A step imported from a cross-file summary (file-tagged, baked snippet).
    pub fn foreign(label: String, span: Span, file: String, snippet: String) -> Self {
        Step {
            label,
            span,
            file: Some(file),
            snippet: Some(snippet),
        }
    }
}

/// How a particular origin reached a particular path.
#[derive(Debug, Clone)]
pub struct Witness {
    /// Byte at which this taint became bound in its scope. A same-scope use
    /// is only tainted if its position is strictly greater (statement-order
    /// sensitivity).
    pub write_byte: u32,
    pub steps: Vec<Step>,
}

/// A set of origins with their witnesses. Merging keeps the earliest
/// (smallest `write_byte`) witness per origin, so the map only grows —
/// guaranteeing the propagation fixpoint terminates.
pub type Origins = BTreeMap<Origin, Witness>;

/// Merge `src` into `dst`, keeping the earliest witness per origin. Returns
/// true if `dst` gained a new origin (drives the fixpoint's change flag).
pub fn merge_origins(dst: &mut Origins, src: &Origins) -> bool {
    let mut changed = false;
    for (origin, w) in src {
        match dst.get_mut(origin) {
            Some(existing) => {
                if w.write_byte < existing.write_byte {
                    *existing = w.clone();
                }
            }
            None => {
                dst.insert(origin.clone(), w.clone());
                changed = true;
            }
        }
    }
    changed
}

struct Cell {
    path: AccessPath,
    origins: Origins,
}

/// Per-rule taint state: for each (scope, base identifier) a small bucket of
/// (access-path, origins) cells. Buckets are tiny, so lookup is a linear scan.
#[derive(Default)]
pub struct TaintState {
    buckets: HashMap<(usize, String), Vec<Cell>>,
}

impl TaintState {
    /// Union `origins` into the cell for `(scope, path)`. Returns true if any
    /// new origin was added.
    pub fn bind(&mut self, scope: usize, path: &AccessPath, origins: &Origins) -> bool {
        let bucket = self.buckets.entry((scope, path.base.clone())).or_default();
        for cell in bucket.iter_mut() {
            if cell.path == *path {
                return merge_origins(&mut cell.origins, origins);
            }
        }
        bucket.push(Cell {
            path: path.clone(),
            origins: origins.clone(),
        });
        true
    }

    /// Collect origins visible to a use of `path` at byte `use_byte` in
    /// `use_scope`, given that scope's ancestor chain (innermost first).
    ///
    /// Visibility rule: a binding in scope `S` written at byte `W` is visible
    /// iff `S == use_scope && W < use_byte` (same-scope, textually earlier),
    /// or `S` is a strict ancestor of `use_scope` (position-insensitive —
    /// closures see outer bindings regardless of order).
    pub fn visible(
        &self,
        use_scope: usize,
        chain: &[usize],
        path: &AccessPath,
        use_byte: u32,
    ) -> Origins {
        let mut out = Origins::new();
        for &s in chain {
            let Some(bucket) = self.buckets.get(&(s, path.base.clone())) else {
                continue;
            };
            let same_scope = s == use_scope;
            for cell in bucket {
                if !cell.path.overlaps(path) {
                    continue;
                }
                for (origin, w) in &cell.origins {
                    if same_scope && w.write_byte >= use_byte {
                        continue;
                    }
                    match out.get_mut(origin) {
                        Some(existing) if existing.write_byte <= w.write_byte => {}
                        _ => {
                            out.insert(origin.clone(), w.clone());
                        }
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(byte: u32) -> Witness {
        Witness {
            write_byte: byte,
            steps: vec![],
        }
    }
    fn origins(entries: &[(Origin, u32)]) -> Origins {
        entries.iter().map(|(o, b)| (o.clone(), w(*b))).collect()
    }

    #[test]
    fn same_scope_respects_write_order() {
        let mut st = TaintState::default();
        let p = AccessPath::base_only("v");
        st.bind(0, &p, &origins(&[(Origin::Source(0), 100)]));
        // use before the write: not visible.
        assert!(st.visible(0, &[0], &p, 50).is_empty());
        // use after the write: visible.
        assert_eq!(st.visible(0, &[0], &p, 150).len(), 1);
    }

    #[test]
    fn ancestor_scope_ignores_order() {
        let mut st = TaintState::default();
        let p = AccessPath::base_only("x");
        st.bind(0, &p, &origins(&[(Origin::Source(0), 200)]));
        // child scope 1 whose chain is [1, 0]; parent taint visible regardless
        // of the earlier use byte.
        assert_eq!(st.visible(1, &[1, 0], &p, 50).len(), 1);
    }

    #[test]
    fn origin_sets_coexist() {
        let mut st = TaintState::default();
        let p = AccessPath::base_only("n");
        st.bind(
            0,
            &p,
            &origins(&[(Origin::Param { scope: 0, index: 0 }, 10)]),
        );
        let added = st.bind(0, &p, &origins(&[(Origin::Source(0), 20)]));
        assert!(added, "adding a distinct origin is a change");
        let vis = st.visible(0, &[0], &p, 100);
        assert_eq!(vis.len(), 2, "Param and Source coexist");
    }

    #[test]
    fn field_sensitive_disjoint() {
        let mut st = TaintState::default();
        let oa = AccessPath::parse("o.a").unwrap();
        st.bind(0, &oa, &origins(&[(Origin::Source(0), 10)]));
        // reading o.b is not tainted...
        assert!(st
            .visible(0, &[0], &AccessPath::parse("o.b").unwrap(), 100)
            .is_empty());
        // ...but reading the whole object o is (extension rule).
        assert_eq!(
            st.visible(0, &[0], &AccessPath::base_only("o"), 100).len(),
            1
        );
    }
}
