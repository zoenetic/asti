//! Human-readable terminal output: findings grouped by file with code
//! frames, severity badges, framework tags, taint flow traces and a summary.

use crate::findings::{Finding, Severity};
use crate::rules::CompiledRuleSet;
use crate::scanner::ScanStats;
use owo_colors::{OwoColorize, Stream, Style};
use std::collections::BTreeMap;
use std::fmt::Write as _;

fn severity_style(sev: Severity) -> Style {
    match sev {
        Severity::Critical => Style::new().red().bold(),
        Severity::High => Style::new().red(),
        Severity::Medium => Style::new().yellow(),
        Severity::Low => Style::new().cyan(),
        Severity::Info => Style::new().dimmed(),
    }
}

fn paint(text: &str, style: Style, color: bool) -> String {
    if color {
        format!("{}", text.style(style))
    } else {
        text.to_string()
    }
}

/// True if stdout is a terminal that wants color.
pub fn stdout_wants_color() -> bool {
    use owo_colors::Stream::Stdout;
    // owo-colors handles NO_COLOR/TERM detection via supports-colors.
    "x".if_supports_color(Stdout, |t| t.bold()).to_string() != "x"
}

pub fn render(
    findings: &[Finding],
    stats: &ScanStats,
    errors: &[String],
    ruleset: &CompiledRuleSet,
    sources_root: &std::path::Path,
    color: bool,
) -> String {
    let mut out = String::new();
    let dim = Style::new().dimmed();
    let bold = Style::new().bold();

    // Group findings by file, preserving the (already sorted) order within.
    let mut by_file: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_file.entry(f.file.as_str()).or_default().push(f);
    }

    for (file, file_findings) in &by_file {
        let _ = writeln!(out, "{}", paint(file, bold, color));
        for f in file_findings {
            render_finding(&mut out, f, ruleset, sources_root, color);
        }
    }

    if !errors.is_empty() {
        let _ = writeln!(out, "{}", paint("warnings:", bold, color));
        for e in errors {
            let _ = writeln!(out, "  {}", paint(e, dim, color));
        }
        let _ = writeln!(out);
    }

    // Summary line.
    let mut counts: BTreeMap<Severity, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(f.severity).or_default() += 1;
    }
    let summary: Vec<String> = counts
        .iter()
        .rev()
        .map(|(sev, n)| paint(&format!("{n} {sev}"), severity_style(*sev), color))
        .collect();

    let files_total = stats.files_from_cache + stats.files_scanned;
    let mut line = format!(
        "{} finding{} ({}) in {} file{} — {} scanned, {} cached, {} ms",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        if summary.is_empty() {
            "none".to_string()
        } else {
            summary.join(", ")
        },
        files_total,
        if files_total == 1 { "" } else { "s" },
        stats.files_scanned,
        stats.files_from_cache,
        stats.duration_ms,
    );
    if stats.baseline_suppressed > 0 {
        let _ = write!(
            line,
            " ({} pre-existing suppressed by baseline)",
            stats.baseline_suppressed
        );
    }
    if stats.files_skipped_size > 0 {
        let _ = write!(line, " ({} oversized skipped)", stats.files_skipped_size);
    }
    if findings.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            paint("✓ no findings", Style::new().green().bold(), color)
        );
    }
    let _ = writeln!(out, "{line}");
    out
}

fn render_finding(
    out: &mut String,
    f: &Finding,
    ruleset: &CompiledRuleSet,
    sources_root: &std::path::Path,
    color: bool,
) {
    let dim = Style::new().dimmed();
    let sev_style = severity_style(f.severity);

    // Header: severity badge, rule id, message.
    let badge = paint(&f.severity.to_string().to_uppercase(), sev_style, color);
    let loc = format!("{}:{}:{}", f.file, f.span.start.line, f.span.start.column);
    let _ = writeln!(
        out,
        "  {badge} {} {}",
        paint(&f.rule_id, Style::new().bold(), color),
        paint(&loc, dim, color)
    );
    let _ = writeln!(out, "    {}", f.message);

    // Framework tags.
    let mut tags: Vec<String> = Vec::new();
    tags.extend(f.cwe.iter().cloned());
    tags.extend(f.owasp.iter().map(|o| format!("OWASP {o}")));
    tags.extend(f.nist.iter().map(|n| format!("NIST {n}")));
    if !tags.is_empty() {
        let _ = writeln!(out, "    {}", paint(&tags.join(" · "), dim, color));
    }

    // Code frame around the finding.
    render_frame(out, sources_root, f, color);

    // Taint flow.
    if !f.trace.is_empty() {
        let _ = writeln!(out, "    {}", paint("flow:", Style::new().bold(), color));
        for (i, step) in f.trace.iter().enumerate() {
            let arrow = if i == 0 { "●" } else { "→" };
            // Cross-file steps show `otherfile:line`; local steps just `line`.
            let loc = match &step.file {
                Some(file) => format!("{file}:{}", step.span.start.line),
                None => format!("line {}", step.span.start.line),
            };
            let _ = writeln!(
                out,
                "      {arrow} {} {}  {}",
                paint(&loc, dim, color),
                step.label,
                paint(&truncate(&step.snippet, 90), dim, color)
            );
        }
    }

    // Remediation, if the rule has one.
    if let Some(rule) = ruleset.rules.get(&f.rule_id) {
        if let Some(fix) = &rule.remediation {
            let _ = writeln!(
                out,
                "    {} {}",
                paint("fix:", Style::new().green(), color),
                fix.trim().replace('\n', "\n         ")
            );
        }
    }
    let _ = writeln!(out);
}

fn render_frame(out: &mut String, root: &std::path::Path, f: &Finding, color: bool) {
    let dim = Style::new().dimmed();
    let Ok(source) = std::fs::read_to_string(root.join(&f.file)) else {
        return;
    };
    let lines: Vec<&str> = source.lines().collect();
    let start = f.span.start.line as usize;
    let end = (f.span.end.line as usize).min(start + 4); // cap tall frames
    let first = start.saturating_sub(2).max(1);
    let width = end.to_string().len().max(3);

    for n in first..=end.min(lines.len()) {
        let text = lines.get(n - 1).unwrap_or(&"");
        let text = truncate(text, 160);
        let gutter = format!("{n:>width$} │");
        let in_span = n >= start && n <= f.span.end.line as usize;
        if in_span {
            let _ = writeln!(
                out,
                "    {} {}",
                paint(&gutter, dim, color),
                if color {
                    format!("{}", text.style(Style::new().bold()))
                } else {
                    text.clone()
                }
            );
            // Caret underline on the first line of the span.
            if n == start {
                let col = f.span.start.column as usize;
                let caret_len = if f.span.end.line == f.span.start.line {
                    (f.span.end.column as usize).saturating_sub(col).max(1)
                } else {
                    text.len().saturating_sub(col - 1).max(1)
                };
                let underline = format!(
                    "{}{}",
                    " ".repeat(col.saturating_sub(1)),
                    "^".repeat(caret_len.min(120))
                );
                let _ = writeln!(
                    out,
                    "    {} {}",
                    paint(&format!("{:>width$} │", ""), dim, color),
                    paint(&underline, severity_style(f.severity), color)
                );
            }
        } else {
            let _ = writeln!(
                out,
                "    {} {}",
                paint(&gutter, dim, color),
                paint(&text, dim, color)
            );
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

// Suppress unused import warning on platforms where Stream isn't referenced
// directly.
#[allow(unused)]
fn _stream_marker(_: Stream) {}
