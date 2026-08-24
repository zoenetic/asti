//! SARIF 2.1.0 output, compatible with GitHub code scanning and other SARIF
//! consumers. Taint traces are emitted as `codeFlows` and fingerprints as
//! `partialFingerprints` so consumers can track findings across commits.

use crate::findings::Finding;
use crate::rules::CompiledRuleSet;
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

pub fn render(findings: &[Finding], ruleset: &CompiledRuleSet) -> Result<String> {
    // Emit descriptors only for rules that fired, in stable order.
    let fired: BTreeSet<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    let mut rule_index: Map<String, Value> = Map::new();
    let mut rules_json: Vec<Value> = Vec::new();
    for (i, rule_id) in fired.iter().enumerate() {
        rule_index.insert((*rule_id).to_string(), json!(i));
        let descriptor = match ruleset.rules.get(*rule_id) {
            Some(rule) => {
                let mut tags: Vec<String> = vec![rule.category.to_string()];
                tags.extend(
                    rule.metadata
                        .cwe
                        .iter()
                        .map(|c| format!("external/cwe/{}", c.to_lowercase())),
                );
                tags.extend(rule.metadata.owasp.iter().map(|o| format!("owasp/{o}")));
                tags.extend(rule.metadata.nist.iter().map(|n| format!("nist/{n}")));
                tags.extend(rule.metadata.tags.iter().cloned());
                let mut help_text = rule.description.clone().unwrap_or_default();
                if let Some(rem) = &rule.remediation {
                    if !help_text.is_empty() {
                        help_text.push_str("\n\n");
                    }
                    help_text.push_str("Remediation: ");
                    help_text.push_str(rem);
                }
                json!({
                    "id": rule.id,
                    "name": rule.display_name(),
                    "shortDescription": { "text": rule.message },
                    "fullDescription": {
                        "text": rule.description.clone().unwrap_or_else(|| rule.message.clone())
                    },
                    "help": {
                        "text": if help_text.is_empty() { rule.message.clone() } else { help_text }
                    },
                    "helpUri": rule.metadata.references.first().cloned()
                        .unwrap_or_else(|| crate::PROJECT_URL.to_string()),
                    "defaultConfiguration": { "level": rule.severity.sarif_level() },
                    "properties": {
                        "tags": tags,
                        "security-severity": rule.severity.security_severity(),
                        // Measured from fixture evidence; rules without
                        // verified fixtures honestly report "low".
                        "precision": rule.precision.as_deref().unwrap_or("low")
                    }
                })
            }
            // Cached finding whose rule vanished shouldn't happen (cache is
            // keyed on rules hash), but degrade gracefully.
            None => json!({ "id": rule_id }),
        };
        rules_json.push(descriptor);
    }

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let mut result = json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index.get(f.rule_id.as_str()).cloned().unwrap_or(json!(null)),
                "level": f.severity.sarif_level(),
                "message": { "text": f.message },
                "locations": [ location(&f.file, &f.span, Some(&f.snippet)) ],
                "partialFingerprints": {
                    "crit/v1": f.fingerprint
                }
            });
            if !f.trace.is_empty() {
                let steps: Vec<Value> = f
                    .trace
                    .iter()
                    .map(|step| {
                        json!({
                            "location": {
                                "physicalLocation": physical_location(
                                    step.file.as_deref().unwrap_or(&f.file),
                                    &step.span,
                                    Some(&step.snippet),
                                ),
                                "message": { "text": step.label }
                            }
                        })
                    })
                    .collect();
                result["codeFlows"] = json!([
                    { "threadFlows": [ { "locations": steps } ] }
                ]);
            }
            result
        })
        .collect();

    let sarif = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "crit",
                        "informationUri": crate::PROJECT_URL,
                        "version": crate::ENGINE_VERSION,
                        "rules": rules_json
                    }
                },
                "columnKind": "utf16CodeUnits",
                "results": results
            }
        ]
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn physical_location(file: &str, span: &crate::findings::Span, snippet: Option<&str>) -> Value {
    let mut region = json!({
        "startLine": span.start.line,
        "startColumn": span.start.column,
        "endLine": span.end.line,
        "endColumn": span.end.column,
    });
    if let Some(s) = snippet {
        region["snippet"] = json!({ "text": s });
    }
    json!({
        "artifactLocation": { "uri": file, "uriBaseId": "%SRCROOT%" },
        "region": region
    })
}

fn location(file: &str, span: &crate::findings::Span, snippet: Option<&str>) -> Value {
    json!({ "physicalLocation": physical_location(file, span, snippet) })
}
