use crate::advisories::parse::{advisory_id, concrete_version, normalize_severity};
use crate::findings::{Finding, FindingKind, Severity};
use crate::manager::Manager;
use serde_json::{Map, Value};

pub fn parse_stdout(stdout: &str) -> Result<Value, serde_json::Error> {
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

/// npm-shaped reports need the dedicated npm parser. Cargo's
/// `{vulnerabilities: {list: [...]}}` is not npm v7 and must stay on this
/// walker.
///
/// The caller acts on this; `parse_output` is the only dispatcher.
pub fn looks_like_npm_report(value: &Value) -> bool {
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

/// uv lists every release that clears the advisory in `fix_versions`, oldest
/// first, so the first concrete entry is the nearest upgrade. An empty array
/// means there is no fix yet.
fn fix_version(item: &Value) -> Option<String> {
    item.get("fix_versions")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .find_map(concrete_version)
}

/// uv is the only manager that reports one vulnerability more than once. It
/// queries several advisory databases and does not merge them, so a
/// vulnerability arrives as its GHSA record and again as the PYSEC record that
/// lists that GHSA among its aliases. Preferring the GHSA gives the twins a
/// shared code, which is what lets them be collapsed — and keeps uv codes
/// comparable with every other manager, the precedence `bun.rs` set for the
/// same reason.
fn ghsa_alias(item: &Value) -> Option<String> {
    item.get("aliases")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .find(|alias| alias.starts_with("GHSA-"))
        .map(ToOwned::to_owned)
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
    let message = string_field(children, &["Issue", "issue"]).map_or_else(
        || format!("{name} {} advisory", severity.as_str()),
        ToOwned::to_owned,
    );
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
        code: super::advisory_code(id),
        message,
        detail: None,
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

/// Every spelling a manager uses for the vulnerable package: `packageName` is
/// composer's, `gem` is bundler's, `dependency` is uv's.
fn package_name<'a>(item: &'a Value, source: &'a Value) -> Option<&'a str> {
    string_field(item, &["name", "package", "module_name", "packageName"])
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
        })
        .or_else(|| {
            item.get("dependency")
                .and_then(|dep| dep.get("name"))
                .and_then(Value::as_str)
        })
}

/// The resolved version in the lockfile, wherever the manager hangs it. A
/// range is not a version, so `concrete_version` has the last word.
fn installed_version(item: &Value) -> Option<String> {
    string_field(item, &["version", "installedVersion"])
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
        .or_else(|| {
            item.get("dependency")
                .and_then(|dep| dep.get("version"))
                .and_then(Value::as_str)
        })
        .and_then(concrete_version)
}

fn advisory_like(item: &Value, path: &str, manager: Manager) -> Option<Finding> {
    if item.get("value").is_some() && item.get("children").is_some() {
        return yarn_tree_finding(item, path, manager);
    }
    // uv reports neither a severity nor a title: an entry is an advisory
    // because it names a `dependency` and carries an id.
    let uv_shaped =
        item.get("dependency").is_some_and(Value::is_object) && item.get("id").is_some();
    let has_signal = item.get("severity").is_some()
        || item.get("title").is_some()
        || item.get("advisory").is_some()
        || item.get("github_advisory_id").is_some()
        || item.get("advisoryId").is_some()
        || uv_shaped;
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
    let package = package_name(item, source);
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
    // Only uv carries `aliases`, and only uv reports a vulnerability twice, so
    // every other manager's id precedence is left alone.
    let id = if uv_shaped && !id.starts_with("GHSA-") {
        ghsa_alias(item).unwrap_or(id)
    } else {
        id
    };
    let message = string_field(source, &["title", "summary", "Issue"])
        .or_else(|| string_field(item, &["title", "summary"]))
        .map_or_else(
            || {
                format!(
                    "{} {} advisory",
                    package.unwrap_or("unknown"),
                    severity.as_str()
                )
            },
            ToOwned::to_owned,
        );
    let fix = fix_version(item).or_else(|| fix_version(source));
    Some(Finding {
        kind: FindingKind::Advisory,
        code: super::advisory_code(id),
        message,
        detail: None,
        severity,
        path: path.to_string(),
        fixable: fix.is_some(),
        manager: Some(manager),
        package: package.map(ToOwned::to_owned),
        current_version: installed_version(item),
        fix_version: fix,
        fix: None,
    })
}

/// The message `advisory_like` invents when a payload names no title or
/// summary. uv's PYSEC records usually carry neither, so this is what marks the
/// twin worth dropping in favour of its GHSA counterpart.
fn message_was_generated(finding: &Finding) -> bool {
    finding.message
        == format!(
            "{} {} advisory",
            finding.package.as_deref().unwrap_or("unknown"),
            finding.severity.as_str()
        )
}

/// Collapse entries describing the same advisory against the same installed
/// package, keeping whichever carries a real summary.
///
/// Scoped to uv because uv is the only manager that reports a vulnerability
/// more than once. Elsewhere two rows sharing a code and a package are two
/// genuine findings, and merging them would hide one.
fn dedupe_alias_twins(findings: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
    let mut seen: std::collections::HashMap<(String, Option<String>, Option<String>), usize> =
        std::collections::HashMap::new();
    for finding in findings {
        // An unidentified advisory has no id to match on, so it can never be
        // shown to be the same as another and is always kept.
        if finding.code == super::advisory_code(String::new()) {
            out.push(finding);
            continue;
        }
        let key = (
            finding.code.clone(),
            finding.package.clone(),
            finding.current_version.clone(),
        );
        if let Some(&at) = seen.get(&key) {
            if message_was_generated(&out[at]) && !message_was_generated(&finding) {
                out[at] = finding;
            }
        } else {
            seen.insert(key, out.len());
            out.push(finding);
        }
    }
    out
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
            detail: None,
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

/// Walk an already-parsed audit payload. Takes the `Value` so the dispatcher
/// can inspect the shape without this module parsing it twice.
///
/// # Errors
///
/// Currently infallible. The `Result` is part of the published signature and
/// matches the other parsers, which do fail; narrowing it would be a breaking
/// change for a promise this function may need again.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Result is a published API contract; see the doc comment"
)]
pub fn parse_value(
    parsed: Value,
    lockfile_path: &str,
    manager: Manager,
) -> Result<Vec<Finding>, serde_json::Error> {
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
    if manager == Manager::Uv {
        findings = dedupe_alias_twins(findings);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse then walk. Deliberately not a production entry point: walking a
    /// payload and *choosing* which walker it needs are separate jobs, and only
    /// `advisories::parse_output` does the choosing.
    fn parse_audit_json(
        stdout: &str,
        lockfile_path: &str,
        manager: Manager,
    ) -> Result<Vec<Finding>, serde_json::Error> {
        parse_value(parse_stdout(stdout)?, lockfile_path, manager)
    }

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

    /// Trimmed from real `uv audit --output-format json --frozen` output.
    /// uv reports no severity at all, and hangs the package name off a
    /// `dependency` object rather than the advisory.
    const UV_AUDIT: &str = r#"{
      "schema": {"version": "preview"},
      "summary": {"audited_packages": 2, "vulnerabilities": 2, "adverse_statuses": 0},
      "vulnerabilities": [
        {
          "dependency": {"name": "jinja2", "version": "3.1.2"},
          "id": "GHSA-cpwx-vrp4-4pq7",
          "display_id": "GHSA-cpwx-vrp4-4pq7",
          "aliases": ["CVE-2025-27516", "PYSEC-2026-1471"],
          "summary": "Jinja2 vulnerable to sandbox breakout through attr filter",
          "description": "long prose",
          "link": "https://nvd.nist.gov/vuln/detail/CVE-2025-27516",
          "fix_versions": ["3.1.6"]
        },
        {
          "dependency": {"name": "jinja2", "version": "3.1.2"},
          "id": "GHSA-gmj6-6f8f-6699",
          "display_id": "GHSA-gmj6-6f8f-6699",
          "aliases": ["CVE-2024-56201"],
          "summary": "Jinja has a sandbox breakout through malicious filenames",
          "description": "long prose",
          "link": "https://example.test/2",
          "fix_versions": []
        }
      ]
    }"#;

    #[test]
    fn every_uv_vulnerability_becomes_a_finding() {
        let findings = parse_audit_json(UV_AUDIT, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].code, "GHSA-cpwx-vrp4-4pq7");
        assert_eq!(findings[1].code, "GHSA-gmj6-6f8f-6699");
    }

    #[test]
    fn a_uv_finding_carries_the_dependency_name_and_version() {
        let findings = parse_audit_json(UV_AUDIT, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings[0].package.as_deref(), Some("jinja2"));
        assert_eq!(findings[0].current_version.as_deref(), Some("3.1.2"));
        assert_eq!(findings[0].manager, Some(Manager::Uv));
        assert_eq!(findings[0].path, "/p/uv.lock");
    }

    #[test]
    fn a_uv_finding_keeps_the_first_fix_version() {
        let findings = parse_audit_json(UV_AUDIT, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings[0].fix_version.as_deref(), Some("3.1.6"));
        assert!(findings[0].fixable);
    }

    #[test]
    fn a_uv_finding_without_fix_versions_is_not_fixable() {
        let findings = parse_audit_json(UV_AUDIT, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings[1].fix_version, None);
        assert!(!findings[1].fixable);
    }

    /// uv queries several advisory databases and does not merge them, so one
    /// vulnerability arrives twice: its GHSA record, and the PYSEC record that
    /// lists that GHSA among its aliases. The PYSEC twin usually carries no
    /// summary, so it used to render as a placeholder row directly beneath the
    /// row that had the real text.
    const UV_ALIAS_TWINS: &str = r#"{
      "schema": {"version": "preview"},
      "vulnerabilities": [
        {
          "dependency": {"name": "urllib3", "version": "1.26.5"},
          "id": "GHSA-v845-jxx5-vc9f",
          "aliases": ["CVE-2023-43804", "PYSEC-2023-192"],
          "summary": "`Cookie` HTTP header isn't stripped on cross-origin redirects",
          "fix_versions": ["1.26.17", "2.0.6"]
        },
        {
          "dependency": {"name": "urllib3", "version": "1.26.5"},
          "id": "PYSEC-2023-192",
          "aliases": ["CVE-2023-43804", "GHSA-v845-jxx5-vc9f"],
          "fix_versions": ["1.26.17", "2.0.6"]
        }
      ]
    }"#;

    #[test]
    fn one_uv_vulnerability_listed_by_two_databases_is_reported_once() {
        let findings = parse_audit_json(UV_ALIAS_TWINS, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].code, "GHSA-v845-jxx5-vc9f");
    }

    #[test]
    fn the_surviving_uv_twin_is_the_one_carrying_the_summary() {
        let findings = parse_audit_json(UV_ALIAS_TWINS, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(
            findings[0].message,
            "`Cookie` HTTP header isn't stripped on cross-origin redirects"
        );
    }

    /// Order is uv's, not ours: the twin without a summary may arrive first.
    #[test]
    fn the_summary_wins_whichever_twin_uv_lists_first() {
        let reversed = r#"{"vulnerabilities":[
          {"dependency":{"name":"urllib3","version":"1.26.5"},"id":"PYSEC-2023-192",
           "aliases":["GHSA-v845-jxx5-vc9f"]},
          {"dependency":{"name":"urllib3","version":"1.26.5"},"id":"GHSA-v845-jxx5-vc9f",
           "aliases":["PYSEC-2023-192"],"summary":"the real text"}]}"#;
        let findings = parse_audit_json(reversed, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].message, "the real text");
    }

    #[test]
    fn a_uv_pysec_id_with_no_ghsa_alias_keeps_its_own_id() {
        let stdout = r#"{"vulnerabilities":[
          {"dependency":{"name":"foo","version":"1.0"},"id":"PYSEC-2023-112",
           "aliases":["CVE-2023-1"],"summary":"s"}]}"#;
        let findings = parse_audit_json(stdout, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings[0].code, "PYSEC-2023-112");
    }

    #[test]
    fn the_same_uv_advisory_against_two_packages_stays_two_findings() {
        let stdout = r#"{"vulnerabilities":[
          {"dependency":{"name":"foo","version":"1.0"},"id":"GHSA-a-b-c","summary":"s"},
          {"dependency":{"name":"bar","version":"1.0"},"id":"GHSA-a-b-c","summary":"s"}]}"#;
        let findings = parse_audit_json(stdout, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings.len(), 2);
    }

    /// Only uv reports a vulnerability twice. Collapsing rows for any other
    /// manager would hide a genuine second finding.
    #[test]
    fn other_managers_keep_every_row_even_when_a_code_repeats() {
        let stdout = r#"{"vulnerabilities":{"list":[
          {"advisory":{"id":"RUSTSEC-2024-0001","title":"bad"},"package":{"name":"foo","version":"0.1.0"}},
          {"advisory":{"id":"RUSTSEC-2024-0001","title":"bad"},"package":{"name":"foo","version":"0.1.0"}}]}}"#;
        let findings = parse_audit_json(stdout, "/p/Cargo.lock", Manager::Cargo).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn a_uv_summary_is_the_message() {
        let findings = parse_audit_json(UV_AUDIT, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(
            findings[0].message,
            "Jinja2 vulnerable to sandbox breakout through attr filter"
        );
    }

    #[test]
    fn uv_reports_no_severity_so_findings_land_on_info() {
        let findings = parse_audit_json(UV_AUDIT, "/p/uv.lock", Manager::Uv).unwrap();
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn the_uv_summary_block_is_not_mistaken_for_an_advisory() {
        let findings = parse_audit_json(UV_AUDIT, "/p/uv.lock", Manager::Uv).unwrap();
        assert!(findings
            .iter()
            .all(|f| f.package.as_deref() == Some("jinja2")));
    }

    #[test]
    fn a_clean_uv_report_is_zero_findings() {
        let stdout = r#"{"schema":{"version":"preview"},"summary":{"audited_packages":2,"vulnerabilities":0,"adverse_statuses":0},"vulnerabilities":[]}"#;
        let findings = parse_audit_json(stdout, "/p/uv.lock", Manager::Uv).unwrap();
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn parses_composer_advisories() {
        let stdout = r#"{"advisories":{"acme/lib":[{
            "advisoryId":"PKSA-1111-2222-3333","packageName":"acme/lib",
            "affectedVersions":"<1.2.0","title":"Remote code execution",
            "cve":"CVE-2024-0001","severity":"high",
            "link":"https://example.test/a"}]}}"#;
        let findings = parse_audit_json(stdout, "/p/composer.lock", Manager::Composer).unwrap();
        assert_eq!(findings.len(), 1);
        // composer's own advisory id wins over the CVE alias.
        assert_eq!(findings[0].code, "PKSA-1111-2222-3333");
        assert_eq!(findings[0].package.as_deref(), Some("acme/lib"));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].message, "Remote code execution");
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
