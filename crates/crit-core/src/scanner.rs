//! Scan orchestration: file discovery (full walk, explicit paths, or git
//! diff scope), language detection, cache reuse, parallel per-file analysis,
//! and baseline filtering.

use crate::config::Config;
use crate::engine;
use crate::findings::{Finding, Severity};
use crate::languages::Registry;
use crate::rules::CompiledRuleSet;
use crate::state::baseline::Baseline;
use crate::state::cache::{Cache, CacheEntry};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Paths to scan (files or directories), relative to cwd or absolute.
    /// Empty means the whole root.
    pub paths: Vec<PathBuf>,
    /// Scan only files changed since this git ref.
    pub diff_base: Option<String>,
    /// Restrict to these language ids (empty = all).
    pub languages: Vec<String>,
    /// Restrict to these rule ids (empty = all).
    pub rule_filter: Vec<String>,
    /// Extra include globs (root-relative); if non-empty, only matches scan.
    pub include: Vec<String>,
    /// Extra exclude globs (root-relative).
    pub exclude: Vec<String>,
    pub use_cache: bool,
    /// Filter findings against the stored baseline.
    pub compare_baseline: bool,
    pub max_file_size: Option<u64>,
    /// Rayon thread count (None = rayon default).
    pub jobs: Option<usize>,
    /// Do not respect ignore files (scan everything).
    pub no_ignore: bool,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ScanStats {
    pub files_considered: usize,
    pub files_scanned: usize,
    pub files_from_cache: usize,
    pub files_skipped_size: usize,
    pub files_with_parse_errors: usize,
    /// Files whose summaries were freshly extracted this scan.
    pub files_summarized: usize,
    /// Files whose summaries were reused from the summary store.
    pub summaries_from_cache: usize,
    /// Findings suppressed by the baseline.
    pub baseline_suppressed: usize,
    pub duration_ms: u128,
}

pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
    /// Non-fatal per-file errors (unreadable files etc).
    pub errors: Vec<String>,
}

/// Convert a root-relative path to the canonical forward-slash string form
/// used in findings, caches and SARIF.
fn rel_str(path: &Path) -> String {
    let s = path.to_string_lossy();
    if std::path::MAIN_SEPARATOR == '/' {
        s.into_owned()
    } else {
        s.replace(std::path::MAIN_SEPARATOR, "/")
    }
}

/// Discover candidate files under `root` honoring ignore files.
fn walk_files(root: &Path, paths: &[PathBuf], no_ignore: bool) -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = if paths.is_empty() {
        vec![root.to_path_buf()]
    } else {
        paths.to_vec()
    };
    // Deduplicate nested targets.
    targets.sort();
    targets.dedup();

    let mut builder = ignore::WalkBuilder::new(&targets[0]);
    for t in &targets[1..] {
        builder.add(t);
    }
    builder
        .hidden(true)
        .git_ignore(!no_ignore)
        .git_global(!no_ignore)
        .git_exclude(!no_ignore)
        .ignore(!no_ignore)
        .add_custom_ignore_filename(".critignore")
        .follow_links(false);

    let mut files = Vec::new();
    for entry in builder.build().flatten() {
        if entry.file_type().is_some_and(|t| t.is_file()) {
            files.push(entry.into_path());
        }
    }
    files.sort();
    files.dedup();
    files
}

fn build_globset(patterns: &[String]) -> Result<Option<globset::GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut b = globset::GlobSetBuilder::new();
    for p in patterns {
        b.add(
            globset::GlobBuilder::new(p)
                .literal_separator(false)
                .build()
                .with_context(|| format!("invalid glob `{p}`"))?,
        );
    }
    Ok(Some(b.build()?))
}

pub fn scan(
    root: &Path,
    registry: &Registry,
    ruleset: &CompiledRuleSet,
    config: &Config,
    opts: &ScanOptions,
) -> Result<ScanOutcome> {
    let started = Instant::now();
    let mut errors: Vec<String> = Vec::new();

    // ---- candidate discovery -------------------------------------------
    let candidates: Vec<PathBuf> = if let Some(base) = &opts.diff_base {
        crate::diff::changed_files(root, base)?
            .into_iter()
            .map(|p| root.join(p))
            .filter(|p| p.is_file())
            .filter(|p| {
                // Explicit paths narrow the diff scope further.
                opts.paths.is_empty() || opts.paths.iter().any(|t| p.starts_with(t))
            })
            .collect()
    } else {
        walk_files(root, &opts.paths, opts.no_ignore)
    };

    let include = build_globset(&{
        let mut v = config.scan.include.clone();
        v.extend(opts.include.iter().cloned());
        v
    })?;
    let exclude = build_globset(&{
        let mut v = config.scan.exclude.clone();
        v.extend(opts.exclude.iter().cloned());
        v
    })?;

    let lang_filter: BTreeSet<&str> = opts.languages.iter().map(|s| s.as_str()).collect();
    let max_size = opts
        .max_file_size
        .or(config.scan.max_file_size)
        .unwrap_or(DEFAULT_MAX_FILE_SIZE);

    let mut stats = ScanStats::default();
    let mut jobs: Vec<Job> = Vec::new();
    for abs in candidates {
        let Some(lang) = registry.detect(&abs) else {
            continue;
        };
        if !lang_filter.is_empty() && !lang_filter.contains(lang.id.as_str()) {
            continue;
        }
        let rel_path = abs.strip_prefix(root).unwrap_or(&abs).to_path_buf();
        let rel = rel_str(&rel_path);
        if rel.starts_with(".crit/") {
            continue;
        }
        if let Some(inc) = &include {
            if !inc.is_match(&rel) {
                continue;
            }
        }
        if let Some(exc) = &exclude {
            if exc.is_match(&rel) {
                continue;
            }
        }
        stats.files_considered += 1;
        if let Ok(meta) = std::fs::metadata(&abs) {
            if meta.len() > max_size {
                stats.files_skipped_size += 1;
                continue;
            }
        }
        jobs.push(Job {
            abs,
            rel,
            lang_id: lang.id.clone(),
        });
    }

    // ---- findings cache -------------------------------------------------
    let mut cache = if opts.use_cache {
        Cache::load(root, &ruleset.rules_hash)
    } else {
        Cache {
            engine: crate::ENGINE_VERSION.to_string(),
            rules_hash: ruleset.rules_hash.clone(),
            files: Default::default(),
        }
    };

    // ---- three-phase pipeline: summarize -> link -> evaluate ------------
    let pipeline = || run_pipeline(&jobs, &cache, ruleset, root, opts.use_cache);
    let PipelineOut {
        entries,
        errors: pipe_errors,
        files_summarized,
        summaries_from_cache,
    } = if let Some(jobs_n) = opts.jobs {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(jobs_n)
            .build()
            .context("failed to build thread pool")?;
        pool.install(pipeline)
    } else {
        pipeline()
    };
    stats.files_summarized = files_summarized;
    stats.summaries_from_cache = summaries_from_cache;
    errors.extend(pipe_errors);
    for (rel, entry, kind, had_errors) in entries {
        match kind {
            EvalKind::Cached => stats.files_from_cache += 1,
            EvalKind::Fresh => {
                stats.files_scanned += 1;
                if had_errors {
                    stats.files_with_parse_errors += 1;
                }
            }
        }
        cache.insert(rel, entry);
    }

    // ---- collect findings ------------------------------------------------
    let scanned_rels: BTreeSet<&String> = jobs.iter().map(|j| &j.rel).collect();
    let rule_filter: BTreeSet<&str> = opts.rule_filter.iter().map(|s| s.as_str()).collect();
    let mut findings: Vec<Finding> = cache
        .files
        .iter()
        .filter(|(rel, _)| scanned_rels.contains(rel))
        .flat_map(|(_, e)| e.findings.iter().cloned())
        .filter(|f| rule_filter.is_empty() || rule_filter.contains(f.rule_id.as_str()))
        .collect();

    // ---- baseline ---------------------------------------------------------
    if opts.compare_baseline {
        let baseline = Baseline::load(root)?;
        let before = findings.len();
        findings.retain(|f| !baseline.contains(&f.fingerprint));
        stats.baseline_suppressed = before - findings.len();
    }

    findings.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    // ---- persist cache -----------------------------------------------------
    if opts.use_cache {
        if let Err(e) = cache.save(root) {
            errors.push(format!("failed to save cache: {e}"));
        }
    }

    stats.duration_ms = started.elapsed().as_millis();
    Ok(ScanOutcome {
        findings,
        stats,
        errors,
    })
}

struct Job {
    abs: PathBuf,
    rel: String,
    lang_id: String,
}

enum EvalKind {
    Cached,
    Fresh,
}

struct PipelineOut {
    entries: Vec<(String, CacheEntry, EvalKind, bool)>,
    errors: Vec<String>,
    files_summarized: usize,
    summaries_from_cache: usize,
}

/// One file's extraction result, retained across the three phases.
struct Prepared {
    rel: String,
    lang_id: String,
    content_hash: String,
    source: String,
    artifact: crate::state::summary_store::FileSummaryArtifact,
    from_summary_cache: bool,
    error: Option<String>,
}

/// summarize (parallel, cacheable) -> link (serial) -> evaluate (parallel).
fn run_pipeline(
    jobs: &[Job],
    cache: &Cache,
    ruleset: &CompiledRuleSet,
    root: &Path,
    use_cache: bool,
) -> PipelineOut {
    use crate::state::summary_store::{self, FileSummaryArtifact};

    // ---- Phase A: summarize --------------------------------------------
    let prepared: Vec<Prepared> = jobs
        .par_iter()
        .map(|job| {
            let mut p = Prepared {
                rel: job.rel.clone(),
                lang_id: job.lang_id.clone(),
                content_hash: String::new(),
                source: String::new(),
                artifact: FileSummaryArtifact {
                    schema: summary_store::SUMMARY_SCHEMA,
                    file: job.rel.clone(),
                    content_hash: String::new(),
                    bindings: Default::default(),
                    rules: Default::default(),
                    summary_hash: String::new(),
                },
                from_summary_cache: false,
                error: None,
            };
            let bytes = match std::fs::read(&job.abs) {
                Ok(b) => b,
                Err(e) => {
                    p.error = Some(e.to_string());
                    return p;
                }
            };
            p.content_hash = crate::state::hash_bytes(&bytes);
            p.source = String::from_utf8_lossy(&bytes).into_owned();

            let key = summary_store::key(&p.content_hash, &ruleset.rules_hash);
            if use_cache {
                if let Some(art) = summary_store::load(root, &key) {
                    p.artifact = art;
                    p.from_summary_cache = true;
                    return p;
                }
            }
            let Some(lang_rules) = ruleset.for_language(&job.lang_id) else {
                p.error = Some("no rules for language".into());
                return p;
            };
            match engine::extract(&job.rel, &p.source, &lang_rules) {
                Ok((bindings, rules)) => {
                    p.artifact = FileSummaryArtifact {
                        schema: summary_store::SUMMARY_SCHEMA,
                        file: job.rel.clone(),
                        content_hash: p.content_hash.clone(),
                        bindings,
                        rules,
                        summary_hash: String::new(),
                    }
                    .finalize();
                    if use_cache {
                        let _ = summary_store::store(root, &key, &p.artifact);
                    }
                }
                Err(e) => p.error = Some(e.to_string()),
            }
            p
        })
        .collect();

    let files_summarized = prepared
        .iter()
        .filter(|p| p.error.is_none() && !p.from_summary_cache)
        .count();
    let summaries_from_cache = prepared.iter().filter(|p| p.from_summary_cache).count();

    // ---- Phase B: link -------------------------------------------------
    let file_artifacts: Vec<crate::linker::FileArtifact> = prepared
        .iter()
        .filter(|p| p.error.is_none())
        .map(|p| {
            let resolution = ruleset.for_language(&p.lang_id).and_then(|lr| {
                lr.profile
                    .as_ref()
                    .and_then(|pr| pr.module_resolution.clone())
            });
            crate::linker::FileArtifact {
                file: p.rel.clone(),
                summary_hash: p.artifact.summary_hash.clone(),
                bindings: p.artifact.bindings.clone(),
                rules: p.artifact.rules.clone().into_iter().collect(),
                resolution,
            }
        })
        .collect();
    let link = crate::linker::link(&file_artifacts);

    // ---- Phase C: evaluate ---------------------------------------------
    let empty_linked = crate::engine::taint::FileLinked::new();
    let entries: Vec<(String, CacheEntry, EvalKind, bool)> = prepared
        .par_iter()
        .filter_map(|p| {
            if p.error.is_some() {
                return None; // read/parse error, reported separately
            }
            let link_fp = link.link_fp.get(&p.rel).cloned().unwrap_or_default();
            if let Some(entry) = cache.lookup(&p.rel, &p.content_hash, &link_fp) {
                return Some((p.rel.clone(), entry.clone(), EvalKind::Cached, false));
            }
            let lang_rules = ruleset.for_language(&p.lang_id)?;
            let linked = link.linked.get(&p.rel).unwrap_or(&empty_linked);
            match engine::evaluate(&p.rel, &p.source, &lang_rules, linked) {
                Ok(findings) => Some((
                    p.rel.clone(),
                    CacheEntry {
                        hash: p.content_hash.clone(),
                        link_fp,
                        findings,
                    },
                    EvalKind::Fresh,
                    false,
                )),
                Err(_) => None,
            }
        })
        .collect();

    // Surface per-file errors (read/parse) collected in Phase A.
    let errors: Vec<String> = prepared
        .iter()
        .filter_map(|p| p.error.as_ref().map(|e| format!("{}: {e}", p.rel)))
        .collect();

    PipelineOut {
        entries,
        errors,
        files_summarized,
        summaries_from_cache,
    }
}

/// Should the process exit non-zero, given a threshold?
pub fn exceeds_threshold(findings: &[Finding], fail_on: Option<Severity>) -> bool {
    match fail_on {
        Some(threshold) => findings.iter().any(|f| f.severity >= threshold),
        None => false,
    }
}
