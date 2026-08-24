//! Access paths: a base identifier plus a bounded chain of field accesses
//! (`req.query.id` → base `req`, fields `[query, id]`).
//!
//! Phase 1 extraction is text-shape based: a node whose text is a pure
//! `ident(.ident)*` chain becomes a path; anything else falls back to a
//! base-only path (equivalent to the 0.1 single-name behavior). Phase 2
//! replaces the heuristic with grammar-precise `member_access` queries.

/// Maximum tracked field depth; deeper accesses widen to the prefix.
pub const MAX_PATH_DEPTH: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPath {
    pub base: String,
    pub fields: Vec<String>,
    /// True if the original access was deeper than `MAX_PATH_DEPTH`.
    pub truncated: bool,
}

impl AccessPath {
    pub fn base_only(base: impl Into<String>) -> Self {
        AccessPath {
            base: base.into(),
            fields: Vec::new(),
            truncated: false,
        }
    }

    /// Parse `ident(.ident)*`; returns `None` for anything else.
    pub fn parse(text: &str) -> Option<AccessPath> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let mut segs = text.split('.');
        let base = segs.next()?;
        if !is_ident(base) {
            return None;
        }
        let mut fields = Vec::new();
        for s in segs {
            if !is_ident(s) {
                return None;
            }
            fields.push(s.to_string());
        }
        let truncated = fields.len() > MAX_PATH_DEPTH;
        fields.truncate(MAX_PATH_DEPTH);
        Some(AccessPath {
            base: base.to_string(),
            fields,
            truncated,
        })
    }

    /// Whether taint on `self` should reach a use of `other`, or vice versa:
    /// true when either path is a prefix of the other. Tainting `o` reaches
    /// `o.v` (prefix); a tainted `o.v` reaches a read of `o` (extension).
    pub fn overlaps(&self, other: &AccessPath) -> bool {
        if self.base != other.base {
            return false;
        }
        let (short, long) = if self.fields.len() <= other.fields.len() {
            (&self.fields, &other.fields)
        } else {
            (&other.fields, &self.fields)
        };
        long.starts_with(short.as_slice())
    }
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chains_and_rejects_complex() {
        assert_eq!(AccessPath::parse("req").unwrap().base, "req");
        let p = AccessPath::parse("req.query.id").unwrap();
        assert_eq!(p.base, "req");
        assert_eq!(p.fields, vec!["query", "id"]);
        assert!(AccessPath::parse("o[i]").is_none());
        assert!(AccessPath::parse("a + b").is_none());
        assert!(AccessPath::parse("").is_none());
    }

    #[test]
    fn depth_is_capped() {
        let p = AccessPath::parse("a.b.c.d.e").unwrap();
        assert_eq!(p.fields.len(), MAX_PATH_DEPTH);
        assert!(p.truncated);
    }

    #[test]
    fn prefix_and_extension_overlap() {
        let o = AccessPath::base_only("o");
        let ov = AccessPath::parse("o.v").unwrap();
        let ow = AccessPath::parse("o.w").unwrap();
        assert!(o.overlaps(&ov), "o taints o.v (prefix)");
        assert!(ov.overlaps(&o), "o.v reaches read of o (extension)");
        assert!(!ov.overlaps(&ow), "o.v and o.w are disjoint");
        let other = AccessPath::base_only("p");
        assert!(!o.overlaps(&other));
    }
}
