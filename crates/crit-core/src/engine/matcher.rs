//! Pattern rule execution: run compiled queries over a tree, apply capture
//! filters, and materialise findings.
//!
//! Text predicates in queries (`#eq?`, `#match?`, `#any-of?` and their
//! negations) are evaluated by the tree-sitter Rust binding itself during
//! match iteration; `filters` in the rule YAML add regex/equality checks on
//! top of that.

use crate::findings::{Finding, Span};
use crate::rules::compiled::CompiledPattern;
use crate::rules::LanguageRules;
use streaming_iterator::StreamingIterator;
use tree_sitter::{QueryCursor, Tree};

pub fn run_patterns(
    rel_path: &str,
    source: &str,
    tree: &Tree,
    rules: &LanguageRules,
    out: &mut Vec<Finding>,
) {
    let bytes = source.as_bytes();
    let mut cursor = QueryCursor::new();
    for pat in &rules.patterns {
        let names = pat.query.capture_names();
        let mut matches = cursor.matches(&pat.query, tree.root_node(), bytes);
        // Several query patterns can match the same node; dedupe on the
        // reported span per rule.
        let mut seen: std::collections::HashSet<(u32, u32)> = std::collections::HashSet::new();
        while let Some(m) = matches.next() {
            if m.captures.is_empty() {
                continue;
            }
            // Capture name -> text, for filters and message templating. The
            // first captured node under each name wins.
            let mut texts: Vec<Option<&str>> = vec![None; names.len()];
            for cap in m.captures {
                let idx = cap.index as usize;
                if texts[idx].is_none() {
                    texts[idx] = cap.node.utf8_text(bytes).ok();
                }
            }

            if !apply_filters(pat, names, &texts) {
                continue;
            }

            let report_node = m
                .captures
                .iter()
                .find(|c| names[c.index as usize] == "finding")
                .map(|c| c.node)
                .unwrap_or(m.captures[0].node);
            let span = Span::from_node(&report_node);
            if !seen.insert((span.start_byte, span.end_byte)) {
                continue;
            }

            let message = render_message(&pat.rule.message, names, &texts);
            out.push(crate::engine::base_finding(
                &pat.rule,
                &rules.language.id,
                rel_path,
                source,
                span,
                message,
            ));
        }
    }
}

fn apply_filters(pat: &CompiledPattern, names: &[&str], texts: &[Option<&str>]) -> bool {
    for filter in &pat.filters {
        let idx = names.iter().position(|n| *n == filter.capture);
        let text = idx.and_then(|i| texts[i]);
        let ok = match text {
            Some(t) => filter.accept(t),
            // A missing capture fails a positive filter and passes a negated
            // one.
            None => filter.negate,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Substitute `${capture}` placeholders in rule messages.
pub(crate) fn render_message(template: &str, names: &[&str], texts: &[Option<&str>]) -> String {
    if !template.contains("${") {
        return template.to_string();
    }
    let mut msg = template.to_string();
    for (i, name) in names.iter().enumerate() {
        let placeholder = format!("${{{name}}}");
        if msg.contains(&placeholder) {
            let value: String = texts[i].unwrap_or("?").chars().take(120).collect();
            msg = msg.replace(&placeholder, &value);
        }
    }
    msg
}
