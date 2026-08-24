//! `crit scan` — the main entry point.

use super::Context;
use anyhow::{Context as _, Result};
use clap::Args;
use crit_core::findings::Severity;
use crit_core::output::{human, json, sarif, Format};
use crit_core::scanner::{self, ScanOptions};
use std::path::PathBuf;

#[derive(Args)]
pub struct ScanArgs {
    /// Files or directories to scan (default: the whole scan root).
    pub paths: Vec<PathBuf>,

    /// Differential scan: only files changed since this git ref
    /// (merge-base aware), including uncommitted and untracked files.
    #[arg(long, value_name = "REF")]
    pub diff_base: Option<String>,

    /// Output format.
    #[arg(long, short = 'f', default_value = "human")]
    pub format: Format,

    /// Write output to a file instead of stdout.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Additionally write a SARIF report to this file.
    #[arg(long, value_name = "FILE")]
    pub sarif_out: Option<PathBuf>,

    /// Additional rule files/directories (repeatable).
    #[arg(long = "rules", value_name = "PATH")]
    pub rule_paths: Vec<PathBuf>,

    /// Disable the built-in rule packs.
    #[arg(long)]
    pub no_default_rules: bool,

    /// Only run these rule ids (repeatable).
    #[arg(long = "rule", value_name = "ID")]
    pub rule_filter: Vec<String>,

    /// Only scan these languages (repeatable, e.g. --lang objectscript).
    #[arg(long = "lang", value_name = "LANG")]
    pub languages: Vec<String>,

    /// Only scan paths matching this glob, relative to the root (repeatable).
    #[arg(long, value_name = "GLOB")]
    pub include: Vec<String>,

    /// Skip paths matching this glob (repeatable).
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,

    /// Disable the persistent result cache for this run.
    #[arg(long)]
    pub no_cache: bool,

    /// Also scan files matched by .gitignore/.critignore.
    #[arg(long)]
    pub no_ignore: bool,

    /// Suppress findings recorded in the baseline (see `crit baseline`).
    #[arg(long)]
    pub baseline: bool,

    /// Exit non-zero when findings at or above this severity exist
    /// (info|low|medium|high|critical|never).
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<String>,

    /// Number of parallel scan threads (default: all cores).
    #[arg(long, short = 'j', value_name = "N")]
    pub jobs: Option<usize>,

    /// Maximum file size in bytes (larger files are skipped).
    #[arg(long, value_name = "BYTES")]
    pub max_file_size: Option<u64>,

    /// Force colored/uncolored human output (auto-detected by default).
    #[arg(long, value_name = "WHEN", value_parser = ["auto", "always", "never"], default_value = "auto")]
    pub color: String,

    /// Print all warnings, not just the first few.
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

pub fn run(ctx: &Context, args: ScanArgs) -> Result<i32> {
    let ruleset = ctx.compile_rules(&args.rule_paths, args.no_default_rules)?;
    super::print_warnings(&ruleset.warnings, args.verbose);

    let fail_on = parse_fail_on(
        args.fail_on
            .as_deref()
            .or(ctx.config.scan.fail_on.as_deref()),
    )?;

    let opts = ScanOptions {
        paths: ctx.resolve_paths(&args.paths)?,
        diff_base: args.diff_base.clone(),
        languages: args.languages.clone(),
        rule_filter: args.rule_filter.clone(),
        include: args.include.clone(),
        exclude: args.exclude.clone(),
        use_cache: !args.no_cache,
        compare_baseline: args.baseline,
        max_file_size: args.max_file_size,
        jobs: args.jobs,
        no_ignore: args.no_ignore,
    };

    let outcome = scanner::scan(&ctx.root, &ctx.registry, &ruleset, &ctx.config, &opts)?;

    let color = match args.color.as_str() {
        "always" => true,
        "never" => false,
        _ => args.output.is_none() && human::stdout_wants_color(),
    };

    let rendered = match args.format {
        Format::Human => human::render(
            &outcome.findings,
            &outcome.stats,
            &outcome.errors,
            &ruleset,
            &ctx.root,
            color,
        ),
        Format::Json => json::render(&outcome.findings, &outcome.stats, &outcome.errors)?,
        Format::Sarif => sarif::render(&outcome.findings, &ruleset)?,
    };

    match &args.output {
        Some(path) => std::fs::write(path, rendered.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?,
        None => print!("{rendered}"),
    }

    if let Some(path) = &args.sarif_out {
        let report = sarif::render(&outcome.findings, &ruleset)?;
        std::fs::write(path, report.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
    }

    Ok(if scanner::exceeds_threshold(&outcome.findings, fail_on) {
        1
    } else {
        0
    })
}

fn parse_fail_on(value: Option<&str>) -> Result<Option<Severity>> {
    // Default: fail CI on high or critical findings.
    let value = value.unwrap_or("high");
    if value.eq_ignore_ascii_case("never") {
        return Ok(None);
    }
    Severity::parse(value)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("invalid --fail-on `{value}`"))
}
