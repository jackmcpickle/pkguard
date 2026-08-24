use crate::advisories::parse::{advisory_id, concrete_version, normalize_severity};
use crate::findings::{Finding, FindingKind, Severity};
use crate::manager::Manager;
use serde_json::{Map, Value};

fn parse_stdout(stdout: &str) -> Result<Value, serde_json::Error> {
    if let Ok(value) = serde_json::from_str(stdout) {
        return Ok(value);
    }
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() <= 1 {
        return serde_json::from_str(stdout);
    }
    let mut items = Vec::new();
    for line in lines {
        items.push(serde_json::from_str(line)?);
    }
    Ok(Value::Array(items))
}

/// npm-shaped reports keep the dedicated parser. Cargo's `{vulnerabilities:
/// {list: [...]}}` is not npm v7 and must stay on this walker.
fn looks_like_npm_report(value: &Value) -> bool {
    if value.get("advisories").is_some_and(Value::is_object)
        || value.get("auditReportVersion").is_some()
    {
        return true;
    }
    match value.get("vulnerabilities") {
        Some(Value::Object(map)) => !map.contains_key("list"),
        _ => false,
    }
}

fn string_field<'a>(item: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| item.get(*key).and_then(Value::as_str))
}

fn yarn_tree_finding(item: &Value, path: &str, manager: Manager) -> Option<Finding> {
    let name = item.get("value").and_then(Value::as_str)?;
    let children = item.get("children")?;
    if !children.is_object() {
        return None;
    }
    let severity = normalize_severity(
        children
            .get("Severity")
            .or_else(|| children.get("severity")),
    );
    let message = string_field(children, &["Issue", "issue"])
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{name} {} advisory", severity.as_str()));
    let id = match children.get("ID") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => advisory_id(
            children.get("github_advisory_id"),
            children.get("id"),
            children.get("cve"),
            children.get("url").and_then(Value::as_str),
        ),
    };
    let version = children
        .get("Tree Versions")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .and_then(concrete_version);
    Some(Finding {
        kind: FindingKind::Advisory,
        code: if id.is_empty() {
            "advisory.unknown".into()
        } else {
            id
        },
        message,
        severity,
        path: path.to_string(),
        fixable: false,
        manager: Some(manager),
        package: Some(name.to_string()),
        current_version: version,
        fix_version: None,
        fix: None,
    })
}

fn advisory_like(item: &Value, path: &str, manager: Manager) -> Option<Finding> {
    if item.get("value").is_some() && item.get("children").is_some() {
        return yarn_tree_finding(item, path, manager);
    }
    let has_signal = item.get("severity").is_some()
        || item.get("title").is_some()
        || item.get("advisory").is_some()
        || item.get("github_advisory_id").is_some()
        || item.get("advisoryId").is_some();
    if !has_signal {
        return None;
    }
    let nested = item.get("advisory");
    let source = nested.filter(|v| v.is_object()).unwrap_or(item);
    let severity = normalize_severity(
        source
            .get("severity")
            .or_else(|| source.get("criticality"))
            .or_else(|| item.get("severity"))
            .or_else(|| item.get("criticality")),
    );
    let package = string_field(item, &["name", "package", "module_name"])
        .or_else(|| string_field(source, &["package", "name"]))
        .or_else(|| {
            item.get("package")
                .and_then(|pkg| pkg.get("name"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            item.get("gem").and_then(|gem| {
                gem.as_str()
                    .or_else(|| gem.get("name").and_then(Value::as_str))
            })
        });
    let id = advisory_id(
        source
            .get("github_advisory_id")
            .or_else(|| item.get("github_advisory_id")),
        source
            .get("id")
            .or_else(|| source.get("advisoryId"))
            .or_else(|| item.get("id")),
        source.get("cve").or_else(|| item.get("cve")),
        source
            .get("url")
            .or_else(|| item.get("url"))
            .and_then(Value::as_str),
    );
    let message = string_field(source, &["title", "summary", "Issue"])
        .or_else(|| string_field(item, &["title", "summary"]))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "{} {} advisory",
                package.unwrap_or("unknown"),
                severity.as_str()
            )
        });
    Some(Finding {
        kind: FindingKind::Advisory,
        code: if id.is_empty() {
            "advisory.unknown".into()
        } else {
            id
        },
        message,
        severity,
        path: path.to_string(),
        fixable: false,
        manager: Some(manager),
        package: package.map(ToOwned::to_owned),
        current_version: string_field(item, &["version", "installedVersion"])
            .or_else(|| {
                item.get("gem")
                    .and_then(|gem| gem.get("version"))
                    .and_then(Value::as_str)
            })
            .or_else(|| {
                item.get("package")
                    .and_then(|pkg| pkg.get("version"))
                    .and_then(Value::as_str)
            })
            .and_then(concrete_version),
        fix_version: None,
        fix: None,
    })
}

fn walk_item(value: &Value, path: &str, manager: Manager, out: &mut Vec<Finding>) {
    if let Some(finding) = advisory_like(value, path, manager) {
        out.push(finding);
        return;
    }
    walk_collection(value, path, manager, out);
}

fn walk_collection(value: &Value, path: &str, manager: Manager, out: &mut Vec<Finding>) {
    match value {
        Value::Array(items) => {
            for item in items {
                walk_item(item, path, manager, out);
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                walk_item(child, path, manager, out);
            }
        }
        _ => {}
    }
}

fn walk_abandoned(abandoned: &Value, path: &str, manager: Manager, out: &mut Vec<Finding>) {
    let Some(map) = abandoned.as_object() else {
        return;
    };
    for name in map.keys() {
        if name.is_empty() {
            continue;
        }
        out.push(Finding {
            kind: FindingKind::Deprecated,
            code: "advisory.abandoned".into(),
            message: format!("{name} is abandoned"),
            severity: Severity::Info,
            path: path.to_string(),
            fixable: false,
            manager: Some(manager),
            package: Some(name.clone()),
            current_version: None,
            fix_version: None,
            fix: None,
        });
    }
}

fn walk_audit_roots(
    obj: &Map<String, Value>,
    path: &str,
    manager: Manager,
    out: &mut Vec<Finding>,
) {
    if let Some(advisories) = obj.get("advisories") {
        walk_collection(advisories, path, manager, out);
    }
    match obj.get("vulnerabilities") {
        Some(Value::Object(vulns)) if vulns.get("list").is_some_and(Value::is_array) => {
            if let Some(list) = vulns.get("list") {
                walk_collection(list, path, manager, out);
            }
        }
        Some(vulns) => walk_collection(vulns, path, manager, out),
        None => {}
    }
    for key in ["results", "dependencies", "audits"] {
        if let Some(child) = obj.get(key) {
            walk_collection(child, path, manager, out);
        }
    }
    if let Some(abandoned) = obj.get("abandoned") {
        walk_abandoned(abandoned, path, manager, out);
    }
}

pub fn parse_audit_json(
    stdout: &str,
    lockfile_path: &str,
    manager: Manager,
) -> Result<Vec<Finding>, serde_json::Error> {
    let parsed = parse_stdout(stdout)?;
    if looks_like_npm_report(&parsed) {
        return crate::advisories::parse::npm::parse_npm_audit(stdout, lockfile_path, manager);
    }
    let mut findings = Vec::new();
    match parsed {
        Value::Array(_) => walk_collection(&parsed, lockfile_path, manager, &mut findings),
        Value::Object(map)
            if map.get("value").and_then(Value::as_str).is_some()
                && map.get("children").is_some_and(Value::is_object) =>
        {
            walk_item(&Value::Object(map), lockfile_path, manager, &mut findings);
        }
        Value::Object(map) => walk_audit_roots(&map, lockfile_path, manager, &mut findings),
        _ => {}
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yarn_tree_node() {
        let stdout = r#"{"value":"left-pad","children":{"ID":"GHSA-yarn","Severity":"high","Issue":"yarn tree advisory","Tree Versions":["1.0.0"]}}"#;
        let findings = parse_audit_json(stdout, "/p/yarn.lock", Manager::Yarn).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "GHSA-yarn");
        assert_eq!(findings[0].package.as_deref(), Some("left-pad"));
    }

    #[test]
    fn parses_yarn_ndjson_tree() {
        let stdout = r#"{"value":"a","children":{"ID":"GHSA-a","Severity":"high","Issue":"one"}}
{"value":"b","children":{"ID":"GHSA-b","Severity":"moderate","Issue":"two"}}
"#;
        let findings = parse_audit_json(stdout, "/p/yarn.lock", Manager::Yarn).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].code, "GHSA-a");
        assert_eq!(findings[1].code, "GHSA-b");
    }

    #[test]
    fn parses_cargo_vuln_list_once() {
        let stdout = r#"{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-2024-0001","title":"cargo issue","package":"foo"},"severity":"high"}]}}"#;
        let findings = parse_audit_json(stdout, "/p/Cargo.lock", Manager::Cargo).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "RUSTSEC-2024-0001");
        assert_eq!(findings[0].manager, Some(Manager::Cargo));
    }

    #[test]
    fn parses_bundle_audit_results() {
        let stdout = r#"{"results":[{"advisory":{"criticality":"high","id":"CVE-2015-7576","title":"Possible XSS in rails"},"gem":{"name":"rails","version":"4.2.0"}}],"version":"0.9.3"}"#;
        let findings = parse_audit_json(stdout, "/p/Gemfile.lock", Manager::Bundler).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "CVE-2015-7576");
        assert_eq!(findings[0].package.as_deref(), Some("rails"));
        assert_eq!(findings[0].current_version.as_deref(), Some("4.2.0"));
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn reports_abandoned_packages() {
        let stdout = r#"{"abandoned":{"left-pad":true}}"#;
        let findings = parse_audit_json(stdout, "/p/composer.lock", Manager::Composer).unwrap();
        assert_eq!(findings[0].code, "advisory.abandoned");
        assert_eq!(findings[0].kind, FindingKind::Deprecated);
        assert_eq!(findings[0].package.as_deref(), Some("left-pad"));
    }
}
