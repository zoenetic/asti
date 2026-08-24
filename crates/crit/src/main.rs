//! crit — AST-based multi-language SAST and code-quality scanner.

mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "crit",
    version,
    about = "AST-based SAST and code-quality scanner built on tree-sitter",
    long_about = "crit scans source code using tree-sitter syntax trees and YAML rule packs \
                  (pattern rules and intra-file taint rules) mapped to OWASP Top 10, CWE and \
                  NIST SP 800-53. It supports differential scans against a git ref, persistent \
                  result caching, baselines for new-findings-only CI gating, and SARIF output."
)]
struct Cli {
    /// Path to crit.toml (default: <root>/crit.toml if present).
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Scan root (default: enclosing git repository root, else current dir).
    #[arg(long, global = true, value_name = "DIR")]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan files for security and quality findings.
    Scan(Box<commands::scan::ScanArgs>),
    /// List loaded rules and rule-pack diagnostics.
    Rules(commands::rules::RulesArgs),
    /// List supported languages.
    Languages,
    /// Parse a file and dump its syntax tree (rule-authoring aid).
    Parse(commands::parse::ParseArgs),
    /// Explain how the taint engine sees a file (scopes, call resolution,
    /// per-sink verdicts).
    Explain(commands::explain::ExplainArgs),
    /// Report taxonomy coverage against OWASP Top 10 and CWE Top 25.
    Coverage(commands::coverage::CoverageArgs),
    /// Manage the finding baseline used by `scan --baseline`.
    Baseline(commands::baseline::BaselineArgs),
    /// Manage the incremental scan cache.
    Cache(commands::cache::CacheArgs),
}

fn main() {
    // Die quietly when piped into `head` etc. instead of panicking on
    // broken-pipe write errors.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(2);
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    let ctx = commands::Context::new(cli.root.as_deref(), cli.config.as_deref())?;
    match cli.command {
        Command::Scan(args) => commands::scan::run(&ctx, *args),
        Command::Rules(args) => commands::rules::run(&ctx, args),
        Command::Languages => commands::languages::run(&ctx),
        Command::Parse(args) => commands::parse::run(&ctx, args),
        Command::Explain(args) => commands::explain::run(&ctx, args),
        Command::Coverage(args) => commands::coverage::run(&ctx, args),
        Command::Baseline(args) => commands::baseline::run(&ctx, args),
        Command::Cache(args) => commands::cache::run(&ctx, args),
    }
}
