use crate::advisories::parse::{
    advisory_id, concrete_version, fix_from_available, normalize_severity,
};
use crate::findings::{Finding, FindingKind};
use crate::manager::Manager;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct NpmReport {
    #[serde(default)]
    advisories: BTreeMap<String, ClassicAdvisory>,
    #[serde(default)]
    vulnerabilities: BTreeMap<String, V7Vulnerability>,
}

#[derive(Deserialize)]
struct ClassicAdvisory {
    #[serde(default)]
    findings: Vec<ClassicFindingRow>,
    #[serde(default)]
    #[serde(rename = "fixAvailable")]
    fix_available: Value,
    #[serde(default)]
    github_advisory_id: Option<Value>,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    cve: Option<Value>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    module_name: Option<String>,
    #[serde(default)]
    severity: Option<Value>,
    #[serde(default)]
    title: Option<String>,
}

#[derive(Deserialize)]
struct ClassicFindingRow {
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct V7Vulnerability {
    #[serde(default)]
    #[serde(rename = "fixAvailable")]
    fix_available: Value,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    severity: Option<Value>,
    #[serde(default)]
    via: Vec<Value>,
}

#[derive(Deserialize)]
struct V7Via {
    #[serde(default)]
    github_advisory_id: Option<Value>,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    cve: Option<Value>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    severity: Option<Value>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

fn finding(
    package: Option<String>,
    version: Option<&str>,
    severity: crate::findings::Severity,
    id: String,
    message: String,
    fix: Option<String>,
    path: &str,
) -> Finding {
    Finding {
        kind: FindingKind::Advisory,
        code: if id.is_empty() {
            "advisory.unknown".to_string()
        } else {
            id
        },
        message,
        severity,
        path: path.to_string(),
        fixable: fix.is_some(),
        manager: Some(Manager::Npm),
        package,
        current_version: version.and_then(concrete_version),
        fix_version: fix,
    }
}

pub fn parse_npm_audit(stdout: &str, lockfile_path: &str) -> Result<Vec<Finding>, serde_json::Error> {
    let report: NpmReport = serde_json::from_str(stdout)?;
    let mut findings = Vec::new();

    for advisory in report.advisories.values() {
        let severity = normalize_severity(advisory.severity.as_ref());
        let name = advisory.module_name.clone();
        let id = advisory_id(
            advisory.github_advisory_id.as_ref(),
            advisory.id.as_ref(),
            advisory.cve.as_ref(),
            advisory.url.as_deref(),
        );
        let message = advisory.title.clone().unwrap_or_else(|| {
            format!(
                "{} {} advisory",
                name.as_deref().unwrap_or("unknown"),
                severity_word(severity)
            )
        });
        let fix = fix_from_available(&advisory.fix_available);
        let versions: Vec<Option<&str>> = if advisory.findings.is_empty() {
            vec![None]
        } else {
            advisory
                .findings
                .iter()
                .map(|f| f.version.as_deref())
                .collect()
        };
        for version in versions {
            findings.push(finding(
                name.clone(),
                version,
                severity,
                id.clone(),
                message.clone(),
                fix.clone(),
                lockfile_path,
            ));
        }
    }

    for (key, vuln) in &report.vulnerabilities {
        let name = vuln.name.clone().or_else(|| Some(key.clone()));
        let item_fix = fix_from_available(&vuln.fix_available);
        let object_vias: Vec<V7Via> = vuln
            .via
            .iter()
            .filter(|v| v.is_object())
            .filter_map(|v| serde_json::from_value(v.clone()).ok())
            .collect();
        if object_vias.is_empty() {
            let severity = normalize_severity(vuln.severity.as_ref());
            findings.push(finding(
                name.clone(),
                None,
                severity,
                String::new(),
                format!("{} {} advisory", key, severity_word(severity)),
                item_fix.clone(),
                lockfile_path,
            ));
            continue;
        }
        for via in object_vias {
            let severity = normalize_severity(via.severity.as_ref().or(vuln.severity.as_ref()));
            let id = advisory_id(
                via.github_advisory_id.as_ref(),
                via.id.as_ref(),
                via.cve.as_ref(),
                via.url.as_deref(),
            );
            let message = via
                .title
                .clone()
                .or_else(|| via.summary.clone())
                .unwrap_or_else(|| format!("{} {} advisory", key, severity_word(severity)));
            findings.push(finding(
                name.clone(),
                via.version.as_deref(),
                severity,
                id,
                message,
                item_fix.clone(),
                lockfile_path,
            ));
        }
    }

    Ok(findings)
}

fn severity_word(severity: crate::findings::Severity) -> &'static str {
    match severity {
        crate::findings::Severity::Critical => "critical",
        crate::findings::Severity::High => "high",
        crate::findings::Severity::Moderate => "moderate",
        crate::findings::Severity::Low => "low",
        crate::findings::Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{FindingKind, Severity};

    #[test]
    fn parses_classic_advisories_map() {
        let stdout = r#"{
            "advisories": {
                "1": {
                    "findings": [{"version": "1.0.0"}],
                    "fixAvailable": {"name": "left-pad", "version": "1.3.0"},
                    "github_advisory_id": "GHSA-left-pad",
                    "module_name": "left-pad",
                    "severity": "high",
                    "title": "left-pad high advisory"
                }
            }
        }"#;
        let findings = parse_npm_audit(stdout, "/p/package-lock.json").unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::Advisory);
        assert_eq!(f.code, "GHSA-left-pad");
        assert_eq!(f.package.as_deref(), Some("left-pad"));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.message, "left-pad high advisory");
        assert_eq!(f.current_version.as_deref(), Some("1.0.0"));
        assert_eq!(f.fix_version.as_deref(), Some("1.3.0"));
        assert!(f.fixable);
        assert_eq!(f.path, "/p/package-lock.json");
    }

    #[test]
    fn parses_v7_vulnerabilities_map() {
        let stdout = r#"{
            "auditReportVersion": 2,
            "vulnerabilities": {
                "left-pad": {
                    "fixAvailable": {"name": "left-pad", "version": "1.3.0"},
                    "name": "left-pad",
                    "severity": "high",
                    "via": [
                        {
                            "github_advisory_id": "GHSA-v7",
                            "severity": "high",
                            "title": "left-pad v7 advisory",
                            "version": "1.0.0"
                        }
                    ]
                }
            }
        }"#;
        let findings = parse_npm_audit(stdout, "/p/package-lock.json").unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.code, "GHSA-v7");
        assert_eq!(f.package.as_deref(), Some("left-pad"));
        assert_eq!(f.message, "left-pad v7 advisory");
        assert_eq!(f.fix_version.as_deref(), Some("1.3.0"));
    }

    #[test]
    fn missing_id_falls_back_to_advisory_unknown() {
        let stdout = r#"{
            "advisories": {
                "1": {
                    "module_name": "left-pad",
                    "severity": "medium",
                    "title": "t"
                }
            }
        }"#;
        let findings = parse_npm_audit(stdout, "/p/package-lock.json").unwrap();
        assert_eq!(findings[0].code, "advisory.unknown");
        // "medium" normalizes to moderate, npm has no fix info here
        assert_eq!(findings[0].severity, Severity::Moderate);
        assert!(!findings[0].fixable);
        assert_eq!(findings[0].fix_version, None);
    }

    #[test]
    fn string_via_entries_are_skipped_in_favor_of_object_vias() {
        // npm v7 lists transitive deps as string vias; only object vias carry
        // advisory data. A vulnerability with only string vias still yields a
        // finding with the item-level severity.
        let stdout = r#"{
            "auditReportVersion": 2,
            "vulnerabilities": {
                "wrapper": {
                    "name": "wrapper",
                    "severity": "low",
                    "fixAvailable": true,
                    "via": ["left-pad"]
                }
            }
        }"#;
        let findings = parse_npm_audit(stdout, "/p/package-lock.json").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].code, "advisory.unknown");
    }

    #[test]
    fn clean_audit_yields_no_findings() {
        let stdout = r#"{"auditReportVersion": 2, "vulnerabilities": {}}"#;
        assert_eq!(
            parse_npm_audit(stdout, "/p/package-lock.json").unwrap().len(),
            0
        );
    }

    #[test]
    fn invalid_json_is_an_error() {
        assert!(parse_npm_audit("not json at all", "/p/package-lock.json").is_err());
    }
}
