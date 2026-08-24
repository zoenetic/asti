//! Per-file analysis: parse once, run pattern rules and taint rules, and
//! assemble findings with stable fingerprints.

pub mod matcher;
pub mod taint;

use crate::findings::{fingerprint, Finding, Span};
use crate::rules::LanguageRules;
use anyhow::{Context, Result};
use std::collections::HashMap;

/// Extract the trimmed text of the (1-based) line containing `span`'s start.
pub fn snippet_at(source: &str, span: &Span) -> String {
    let line = span.start.line as usize;
    source
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .trim()
        .chars()
        .take(400)
        .collect()
}

fn parse(rel_path: &str, source: &str, rules: &LanguageRules) -> Result<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&rules.language.language)
        .with_context(|| format!("failed to load grammar for {}", rules.language.id))?;
    parser
        .parse(source, None)
        .with_context(|| format!("parser returned no tree for {rel_path}"))
}

/// Analyze one file with no cross-file summaries (intra-file only). Kept for
/// callers and tests that don't run the cross-file pipeline.
pub fn analyze_file(rel_path: &str, source: &str, rules: &LanguageRules) -> Result<Vec<Finding>> {
    evaluate(rel_path, source, rules, &taint::FileLinked::new())
}

/// Analyze one file, applying cross-file summaries reachable from it.
pub fn evaluate(
    rel_path: &str,
    source: &str,
    rules: &LanguageRules,
    linked: &taint::FileLinked,
) -> Result<Vec<Finding>> {
    let tree = parse(rel_path, source, rules)?;

    let mut findings = Vec::new();
    matcher::run_patterns(rel_path, source, &tree, rules, &mut findings);
    if let Some(profile) = &rules.profile {
        taint::run_taint(
            rel_path,
            source,
            &tree,
            rules,
            profile,
            linked,
            &mut findings,
        );
    }

    // Stable order, then occurrence-indexed fingerprints so that several
    // identical matches don't collide in baselines.
    findings.sort_by(|a, b| {
        (a.span.start_byte, a.span.end_byte, &a.rule_id).cmp(&(
            b.span.start_byte,
            b.span.end_byte,
            &b.rule_id,
        ))
    });
    let mut occurrence: HashMap<(String, String), u32> = HashMap::new();
    for f in &mut findings {
        let key = (f.rule_id.clone(), f.snippet.clone());
        let n = occurrence.entry(key).or_insert(0);
        f.fingerprint = fingerprint(&f.rule_id, rel_path, &f.snippet, *n);
        *n += 1;
    }
    Ok(findings)
}

/// Build a structured [`taint::explain::Explanation`] for one file (read-only
/// diagnostic backing `crit explain`). `linked` is typically empty — explain
/// runs on a single file.
pub fn explain(
    rel_path: &str,
    source: &str,
    rules: &LanguageRules,
    rule_filter: Option<&str>,
) -> Result<taint::explain::Explanation> {
    let tree = parse(rel_path, source, rules)?;
    let (scopes, calls, rule_explains) = match &rules.profile {
        Some(profile) => taint::explain(
            source,
            &tree,
            rules,
            profile,
            rule_filter,
            &taint::FileLinked::new(),
        ),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };
    Ok(taint::explain::Explanation {
        file: rel_path.to_string(),
        language: rules.language.id.clone(),
        scopes,
        calls,
        rules: rule_explains,
    })
}

/// Extract a file's binding facts and per-rule function summaries (intra-file)
/// for cross-file linking. Cheap relative to a full evaluate.
pub fn extract(
    rel_path: &str,
    source: &str,
    rules: &LanguageRules,
) -> Result<(
    crate::state::summary_store::PortableBindings,
    std::collections::BTreeMap<String, Vec<crate::state::summary_store::PortableFunctionSummary>>,
)> {
    use crate::state::summary_store::PortableBindings;
    let tree = parse(rel_path, source, rules)?;

    let Some(profile) = &rules.profile else {
        return Ok((PortableBindings::default(), Default::default()));
    };

    // Binder facts (imports/exports) for module resolution.
    let fb = crate::binder::FileBindings::build(&tree, source, profile);
    let bindings = PortableBindings {
        module_decl: fb.module_decl.clone(),
        imports: fb
            .imports
            .iter()
            .map(|i| (i.local.clone(), i.module.clone(), i.name.clone()))
            .collect(),
        exports: fb.exports.clone(),
    };

    let mut rules_map = taint::extract_summaries(source, &tree, rules, profile);
    // Tag each summary's sink step + provenance with this file's path.
    for summaries in rules_map.values_mut() {
        for f in summaries {
            for s in &mut f.returns_source {
                if s.file.is_empty() {
                    s.file = rel_path.to_string();
                }
            }
            for (_, steps) in &mut f.returns_params {
                for s in steps {
                    if s.file.is_empty() {
                        s.file = rel_path.to_string();
                    }
                }
            }
            for ps in &mut f.param_to_sink {
                if ps.sink_step.file.is_empty() {
                    ps.sink_step.file = rel_path.to_string();
                }
                for s in &mut ps.steps {
                    if s.file.is_empty() {
                        s.file = rel_path.to_string();
                    }
                }
            }
        }
    }
    Ok((bindings, rules_map))
}

/// Build a finding skeleton from a rule and a matched node span.
pub(crate) fn base_finding(
    rule: &crate::rules::RuleSpec,
    lang_id: &str,
    rel_path: &str,
    source: &str,
    span: Span,
    message: String,
) -> Finding {
    Finding {
        rule_id: rule.id.clone(),
        severity: rule.severity,
        category: rule.category,
        message,
        file: rel_path.to_string(),
        language: lang_id.to_string(),
        span,
        snippet: snippet_at(source, &span),
        trace: Vec::new(),
        fingerprint: String::new(),
        cwe: rule.metadata.cwe.clone(),
        owasp: rule.metadata.owasp.clone(),
        nist: rule.metadata.nist.clone(),
    }
}
