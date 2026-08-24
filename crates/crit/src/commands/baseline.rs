//! `crit baseline` — record the current findings as accepted, so future
//! scans with `--baseline` only report new issues.

use super::Context;
use anyhow::Result;
use clap::{Args, Subcommand};
use crit_core::scanner::{self, ScanOptions};
use crit_core::state::baseline::Baseline;
use std::path::PathBuf;

#[derive(Args)]
pub struct BaselineArgs {
    #[command(subcommand)]
    pub command: BaselineCommand,
}

#[derive(Subcommand)]
pub enum BaselineCommand {
    /// Scan and store all current findings as the baseline.
    Update(UpdateArgs),
    /// Show baseline statistics.
    Info,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Additional rule files/directories (repeatable). Use the same rule
    /// setup you scan with, or fingerprints won't line up.
    #[arg(long = "rules", value_name = "PATH")]
    pub rule_paths: Vec<PathBuf>,

    /// Disable the built-in rule packs.
    #[arg(long)]
    pub no_default_rules: bool,

    /// Number of parallel scan threads.
    #[arg(long, short = 'j', value_name = "N")]
    pub jobs: Option<usize>,
}

pub fn run(ctx: &Context, args: BaselineArgs) -> Result<i32> {
    match args.command {
        BaselineCommand::Update(update) => {
            let ruleset = ctx.compile_rules(&update.rule_paths, update.no_default_rules)?;
            super::print_warnings(&ruleset.warnings, false);
            let opts = ScanOptions {
                use_cache: true,
                jobs: update.jobs,
                ..Default::default()
            };
            let outcome = scanner::scan(&ctx.root, &ctx.registry, &ruleset, &ctx.config, &opts)?;
            let baseline = Baseline::from_findings(outcome.findings.iter());
            baseline.save(&ctx.root)?;
            println!(
                "baseline updated: {} findings recorded across {} files",
                baseline.fingerprints.len(),
                outcome.stats.files_from_cache + outcome.stats.files_scanned
            );
        }
        BaselineCommand::Info => {
            if !Baseline::exists(&ctx.root) {
                println!("no baseline (create one with `crit baseline update`)");
                return Ok(0);
            }
            let baseline = Baseline::load(&ctx.root)?;
            println!(
                "baseline created {} with {} fingerprints",
                if baseline.created.is_empty() {
                    "(unknown)"
                } else {
                    &baseline.created
                },
                baseline.fingerprints.len()
            );
        }
    }
    Ok(0)
}
