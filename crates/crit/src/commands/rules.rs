//! `crit rules` — list loaded rules, surface rule-pack diagnostics, and
//! verify rule fixture evidence.

use super::Context;
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub action: Option<RulesAction>,

    /// Additional rule files/directories to load (repeatable).
    #[arg(long = "rules", value_name = "PATH")]
    pub rule_paths: Vec<PathBuf>,

    /// Disable the built-in rule packs.
    #[arg(long)]
    pub no_default_rules: bool,

    /// Only show rules for this language.
    #[arg(long = "lang", value_name = "LANG")]
    pub language: Option<String>,

    /// Show all diagnostics and full rule details.
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum RulesAction {
    /// Run the per-rule fixture harness (`<pack>/tests/<rule-id>/`) and
    /// report verified evidence.
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Rules directory containing packs and their tests (default: <root>/rules).
    #[arg(value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Rewrite <DIR>/evidence.yaml with the verified results.
    #[arg(long)]
    pub write_evidence: bool,
}

pub fn run(ctx: &Context, args: RulesArgs) -> Result<i32> {
    let ruleset = ctx.compile_rules(&args.rule_paths, args.no_default_rules)?;
    if let Some(RulesAction::Verify(verify)) = args.action {
        return run_verify(ctx, &ruleset, verify);
    }
    super::print_warnings(&ruleset.warnings, args.verbose);

    let mut count = 0;
    for rule in ruleset.sorted_rules() {
        if let Some(lang) = &args.language {
            if !rule.languages.iter().any(|l| l == lang) {
                continue;
            }
        }
        count += 1;
        let kind = match rule.kind {
            crit_core::rules::RuleKind::Pattern => "pattern",
            crit_core::rules::RuleKind::Taint => "taint",
        };
        println!(
            "{:<40} {:<9} {:<8} {:<12} [{}]",
            rule.id,
            rule.severity.to_string(),
            kind,
            rule.category.to_string(),
            rule.languages.join(", ")
        );
        if args.verbose {
            println!("    {}", rule.message);
            let m = &rule.metadata;
            if !(m.cwe.is_empty() && m.owasp.is_empty() && m.nist.is_empty()) {
                println!(
                    "    {}",
                    m.cwe
                        .iter()
                        .cloned()
                        .chain(m.owasp.iter().map(|o| format!("OWASP {o}")))
                        .chain(m.nist.iter().map(|n| format!("NIST {n}")))
                        .collect::<Vec<_>>()
                        .join(" · ")
                );
            }
        }
    }
    println!("\n{count} rules");
    Ok(0)
}

fn run_verify(
    ctx: &Context,
    ruleset: &crit_core::rules::CompiledRuleSet,
    args: VerifyArgs,
) -> Result<i32> {
    let dir = args.dir.unwrap_or_else(|| ctx.root.join("rules"));
    let report = crit_core::evidence::run(&dir, &ctx.registry, ruleset)?;

    if report.per_rule.is_empty() {
        println!("no fixture directories found under {}", dir.display());
        return Ok(0);
    }
    let mut verified = 0;
    for (id, r) in &report.per_rule {
        if r.failures.is_empty() {
            verified += 1;
            println!(
                "ok   {id:<40} {} positive, {} negative",
                r.entry.positives, r.entry.negatives
            );
        } else {
            println!("FAIL {id}");
            for f in &r.failures {
                println!("       {f}");
            }
        }
    }
    println!(
        "\n{verified}/{} rules verified against fixtures",
        report.per_rule.len()
    );

    if args.write_evidence {
        let path = dir.join(crit_core::evidence::EVIDENCE_FILE);
        std::fs::write(&path, report.to_evidence_file().to_yaml())?;
        println!("wrote {}", path.display());
    }
    Ok(if report.is_ok() { 0 } else { 1 })
}
