//! Compilation of loaded rules into per-language tree-sitter queries.
//!
//! Compilation happens once at startup; scanning threads share the compiled
//! set immutably (`Query` is `Send + Sync`).

use crate::findings::Severity;
use crate::languages::{profile::TaintProfileSpec, LanguageDef, Registry};
use crate::rules::model::{CaptureFilter, RuleKind, RuleSpec};
use crate::rules::LoadedRules;
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::Query;

/// A compiled capture filter.
pub struct CompiledFilter {
    pub capture: String,
    pub regex: Option<Regex>,
    pub equals: Option<String>,
    pub any_of: Option<Vec<String>>,
    pub negate: bool,
}

impl CompiledFilter {
    fn compile(f: &CaptureFilter) -> Self {
        CompiledFilter {
            capture: f.capture.clone(),
            regex: f
                .pattern
                .as_ref()
                .map(|p| Regex::new(p).expect("validated")),
            equals: f.equals.clone(),
            any_of: f.any_of.clone(),
            negate: f.negate,
        }
    }

    /// Test a capture's text (before negation).
    fn matches(&self, text: &str) -> bool {
        if let Some(re) = &self.regex {
            if !re.is_match(text) {
                return false;
            }
        }
        if let Some(eq) = &self.equals {
            if text != eq {
                return false;
            }
        }
        if let Some(set) = &self.any_of {
            if !set.iter().any(|s| s == text) {
                return false;
            }
        }
        true
    }

    pub fn accept(&self, text: &str) -> bool {
        self.matches(text) != self.negate
    }
}

pub struct CompiledPattern {
    pub rule: Arc<RuleSpec>,
    pub query: Query,
    pub filters: Vec<CompiledFilter>,
}

/// One compiled source/sink/sanitizer query.
pub struct CompiledTaintQuery {
    pub query: Query,
    /// Index of the marker capture (`source`/`sink`/`sanitizer`); falls back
    /// to capture 0.
    pub capture_index: u32,
    pub label: Option<String>,
}

/// One compiled identity matcher (the `resolved:` form). Matched against
/// binder-resolved calls and member reads instead of a tree-sitter query.
#[derive(Clone)]
pub struct CompiledResolvedMatcher {
    pub module: Option<String>,
    pub member_of: Option<String>,
    pub name: Option<String>,
    pub path: Vec<String>,
    pub arg_index: Option<usize>,
    pub match_unresolved: bool,
    pub label: Option<String>,
}

pub struct CompiledTaint {
    pub rule: Arc<RuleSpec>,
    pub sources: Vec<CompiledTaintQuery>,
    pub sinks: Vec<CompiledTaintQuery>,
    pub sanitizers: Vec<CompiledTaintQuery>,
    // Identity matchers (0.2); empty for rules that only use `query:`.
    pub resolved_sources: Vec<CompiledResolvedMatcher>,
    pub resolved_sinks: Vec<CompiledResolvedMatcher>,
    pub resolved_sanitizers: Vec<CompiledResolvedMatcher>,
}

/// Compiled taint profile for one language.
pub struct CompiledProfile {
    pub identifiers: std::collections::HashSet<String>,
    pub assignments: Vec<Query>,
    pub functions: Vec<Query>,
    pub params: Vec<Query>,
    pub calls: Vec<Query>,
    pub returns: Vec<Query>,
    // --- optional binding layer (0.2); empty when the profile omits them ---
    pub member_access: Vec<Query>,
    pub method_calls: Vec<Query>,
    pub imports: Vec<Query>,
    pub exports: Vec<Query>,
    pub module_resolution: Option<crate::languages::profile::ModuleResolution>,
}

impl CompiledProfile {
    /// Compile a profile, skipping (and reporting) individual queries that
    /// don't fit this grammar so one typo doesn't disable taint analysis for
    /// the whole language.
    fn compile(spec: &TaintProfileSpec, def: &LanguageDef, warnings: &mut Vec<String>) -> Self {
        let mut compile_set =
            |queries: &[crate::languages::profile::ProfileQuery], what: &str| -> Vec<Query> {
                queries
                    .iter()
                    .filter_map(|q| match Query::new(&def.language, &q.query) {
                        Ok(query) => Some(query),
                        Err(e) => {
                            warnings.push(format!(
                                "profile {what} query invalid for `{}`: {e}",
                                def.id
                            ));
                            None
                        }
                    })
                    .collect()
            };
        CompiledProfile {
            identifiers: spec.identifiers.iter().cloned().collect(),
            assignments: compile_set(&spec.assignments, "assignments"),
            functions: compile_set(&spec.functions, "functions"),
            params: compile_set(&spec.params, "params"),
            calls: compile_set(&spec.calls, "calls"),
            returns: compile_set(&spec.returns, "returns"),
            member_access: compile_set(&spec.member_access, "member_access"),
            method_calls: compile_set(&spec.method_calls, "method_calls"),
            imports: compile_set(&spec.imports, "imports"),
            exports: compile_set(&spec.exports, "exports"),
            module_resolution: spec.module_resolution.clone(),
        }
    }
}

/// Everything compiled for a single language.
pub struct LanguageRules {
    pub language: Arc<LanguageDef>,
    pub patterns: Vec<CompiledPattern>,
    pub taints: Vec<CompiledTaint>,
    pub profile: Option<CompiledProfile>,
}

/// The complete compiled rule set shared across scan threads.
pub struct CompiledRuleSet {
    /// All rules that compiled for at least one language, keyed by id
    /// (used for listings and SARIF rule descriptors).
    pub rules: HashMap<String, Arc<RuleSpec>>,
    pub by_language: HashMap<String, Arc<LanguageRules>>,
    /// Hash covering rule content, profiles, engine revision and language
    /// set; used as the cache validity key.
    pub rules_hash: String,
    /// Warnings from loading + compilation (rendered by the CLI).
    pub warnings: Vec<String>,
}

impl CompiledRuleSet {
    pub fn compile(loaded: LoadedRules, registry: &Registry) -> Result<Self> {
        let mut warnings = loaded.warnings.clone();
        let mut rules: HashMap<String, Arc<RuleSpec>> = HashMap::new();
        let mut by_language: HashMap<String, Arc<LanguageRules>> = HashMap::new();

        // Hash rule content deterministically (BTreeMap iterates sorted).
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crit-rules-v1\0");
        hasher.update(&crate::ANALYSIS_REVISION.to_le_bytes());
        for (id, rule) in &loaded.rules {
            hasher.update(id.as_bytes());
            hasher.update(&serde_json::to_vec(rule).expect("rule serializes"));
        }

        for def in registry.all() {
            hasher.update(def.id.as_bytes());
            if let Some(p) = &def.taint_profile {
                p.hash_into(&mut hasher);
            }

            let profile = def
                .taint_profile
                .as_ref()
                .map(|spec| CompiledProfile::compile(spec, def, &mut warnings));

            let mut patterns = Vec::new();
            let mut taints = Vec::new();

            for rule in loaded.rules.values() {
                if !rule.languages.iter().any(|l| l == &def.id) {
                    continue;
                }
                let arc = rules
                    .entry(rule.id.clone())
                    .or_insert_with(|| Arc::new(rule.clone()))
                    .clone();
                match rule.kind {
                    RuleKind::Pattern => {
                        let text = rule.query.as_deref().expect("validated");
                        match Query::new(&def.language, text) {
                            Ok(query) => patterns.push(CompiledPattern {
                                rule: arc,
                                query,
                                filters: rule.filters.iter().map(CompiledFilter::compile).collect(),
                            }),
                            Err(e) => warnings.push(format!(
                                "rule `{}` query does not compile for `{}`: {e}",
                                rule.id, def.id
                            )),
                        }
                    }
                    RuleKind::Taint => {
                        if profile.is_none() {
                            warnings.push(format!(
                                "taint rule `{}` skipped for `{}`: language has no taint profile",
                                rule.id, def.id
                            ));
                            continue;
                        }
                        match compile_taint(rule, arc.clone(), def) {
                            Ok(t) => taints.push(t),
                            Err(e) => warnings.push(format!(
                                "taint rule `{}` skipped for `{}`: {e}",
                                rule.id, def.id
                            )),
                        }
                    }
                }
            }

            by_language.insert(
                def.id.clone(),
                Arc::new(LanguageRules {
                    language: def.clone(),
                    patterns,
                    taints,
                    profile,
                }),
            );
        }

        // Drop rules that failed to compile everywhere so listings reflect
        // what actually runs.
        let live: std::collections::HashSet<&str> = by_language
            .values()
            .flat_map(|lr| {
                lr.patterns
                    .iter()
                    .map(|p| p.rule.id.as_str())
                    .chain(lr.taints.iter().map(|t| t.rule.id.as_str()))
            })
            .collect();
        rules.retain(|id, _| live.contains(id.as_str()));

        Ok(CompiledRuleSet {
            rules,
            by_language,
            rules_hash: hasher.finalize().to_hex().to_string(),
            warnings,
        })
    }

    pub fn for_language(&self, id: &str) -> Option<Arc<LanguageRules>> {
        self.by_language.get(id).cloned()
    }

    /// All rules sorted by id, for stable listings.
    pub fn sorted_rules(&self) -> Vec<Arc<RuleSpec>> {
        let mut v: Vec<_> = self.rules.values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Highest severity among rules (used for CLI hints).
    pub fn max_severity(&self) -> Option<Severity> {
        self.rules.values().map(|r| r.severity).max()
    }
}

fn compile_taint(
    rule: &RuleSpec,
    arc: Arc<RuleSpec>,
    def: &LanguageDef,
) -> Result<CompiledTaint, String> {
    // Compile the tree-sitter-query patterns of one role.
    let compile_queries = |patterns: &[crate::rules::model::TaintPattern],
                           marker: &str|
     -> Result<Vec<CompiledTaintQuery>, String> {
        patterns
            .iter()
            .filter_map(|p| p.query.as_ref().map(|q| (p, q)))
            .map(|(p, q)| {
                let query = Query::new(&def.language, q)
                    .map_err(|e| format!("{marker} query invalid: {e}"))?;
                let capture_index = query
                    .capture_names()
                    .iter()
                    .position(|n| *n == marker)
                    .unwrap_or(0) as u32;
                Ok(CompiledTaintQuery {
                    query,
                    capture_index,
                    label: p.label.clone(),
                })
            })
            .collect()
    };
    // Collect the identity matchers of one role.
    let compile_resolved =
        |patterns: &[crate::rules::model::TaintPattern]| -> Vec<CompiledResolvedMatcher> {
            patterns
                .iter()
                .filter_map(|p| {
                    p.resolved.as_ref().map(|r| CompiledResolvedMatcher {
                        module: r.module.clone(),
                        member_of: r.member_of.clone(),
                        name: r.name.clone(),
                        path: r.path.clone(),
                        arg_index: r.arg_index,
                        match_unresolved: r.match_unresolved,
                        label: p.label.clone(),
                    })
                })
                .collect()
        };
    Ok(CompiledTaint {
        rule: arc,
        sources: compile_queries(&rule.sources, "source")?,
        sinks: compile_queries(&rule.sinks, "sink")?,
        sanitizers: compile_queries(&rule.sanitizers, "sanitizer")?,
        resolved_sources: compile_resolved(&rule.sources),
        resolved_sinks: compile_resolved(&rule.sinks),
        resolved_sanitizers: compile_resolved(&rule.sanitizers),
    })
}
