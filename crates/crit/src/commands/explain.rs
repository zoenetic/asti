//! `crit explain` — show how the taint engine sees one file: scopes, resolved
//! calls, and per-rule source/sink verdicts (including why a sink is *not*
//! reported). A read-only diagnostic and rule-authoring aid.

use super::Context;
use anyhow::{Context as _, Result};
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ExplainArgs {
    /// File to explain.
    pub file: PathBuf,

    /// Language id (default: detected from the file extension).
    #[arg(long = "lang", value_name = "LANG")]
    pub language: Option<String>,

    /// Only explain this rule id.
    #[arg(long = "rule", value_name = "ID")]
    pub rule: Option<String>,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,

    /// Additional rule files/directories to load (repeatable).
    #[arg(long = "rules", value_name = "PATH")]
    pub rule_paths: Vec<PathBuf>,

    /// Disable the built-in rule packs.
    #[arg(long)]
    pub no_default_rules: bool,
}

pub fn run(ctx: &Context, args: ExplainArgs) -> Result<i32> {
    let ruleset = ctx.compile_rules(&args.rule_paths, args.no_default_rules)?;
    let lang = match &args.language {
        Some(id) => ctx
            .registry
            .get(id)
            .with_context(|| format!("unknown language `{id}`"))?,
        None => ctx
            .registry
            .detect(&args.file)
            .with_context(|| format!("cannot detect language for {}", args.file.display()))?,
    };
    let source = std::fs::read_to_string(&args.file)
        .with_context(|| format!("failed to read {}", args.file.display()))?;
    let lang_rules = ruleset
        .for_language(&lang.id)
        .with_context(|| format!("no rules loaded for language `{}`", lang.id))?;

    let rel = args
        .file
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let explanation = crit_core::engine::explain(&rel, &source, &lang_rules, args.rule.as_deref())?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&explanation)?);
        return Ok(0);
    }
    render(&explanation);
    Ok(0)
}

fn render(e: &crit_core::engine::taint::explain::Explanation) {
    println!("{} ({})", e.file, e.language);

    if !e.scopes.is_empty() {
        println!("\nscopes:");
        for s in &e.scopes {
            println!("  {} [lines {}-{}]", s.name, s.start_line, s.end_line);
        }
    }

    if !e.calls.is_empty() {
        println!("\ncalls:");
        for c in &e.calls {
            println!("  line {}: {} — {}", c.line, c.callee, c.resolution);
        }
    }

    if e.rules.is_empty() {
        println!("\nno taint rules apply to this file");
        return;
    }
    for r in &e.rules {
        println!("\nrule {}:", r.rule_id);
        if !r.linked.is_empty() {
            println!("  cross-file summaries: {}", r.linked.join(", "));
        }
        if r.sources.is_empty() {
            println!("  sources: none");
        } else {
            println!("  sources:");
            for s in &r.sources {
                println!(
                    "    line {}:{} {} — {}",
                    s.line, s.column, s.label, s.snippet
                );
            }
        }
        if r.sinks.is_empty() {
            println!("  sinks: none");
        } else {
            println!("  sinks:");
            for s in &r.sinks {
                let mark = if s.reported { "REPORTED" } else { "ok      " };
                println!(
                    "    {} line {}:{} — {}\n              {}",
                    mark, s.line, s.column, s.reason, s.snippet
                );
            }
        }
    }
}
