//! `bun audit --json` has a shape of its own: a flat object keyed by package
//! name, each value an array of advisories.
//!
//! ```json
//! {"shell-quote": [{"id": 1120422, "url": "https://github.com/advisories/GHSA-w7jw-789q-3m8p",
//!                   "title": "...", "severity": "critical",
//!                   "vulnerable_versions": ">=1.1.0 <=1.8.3"}]}
//! ```
//!
//! Nothing in that document matches the keys the generic walker looks for, so
//! bun reports used to parse to zero findings — a silent clean bill of health.

use crate::advisories::parse::{advisory_code, ghsa_from_url, id_value, normalize_severity};
use crate::findings::{Finding, FindingKind};
use crate::manager::Manager;
use serde_json::Value;

/// bun prints a `bun audit vX.Y.Z (hash)` banner before the document. It
/// normally lands on stderr, but a redirected or older bun puts it on stdout.
pub fn json_slice(stdout: &str) -> &str {
    stdout.find('{').map_or("", |start| &stdout[start..])
}

/// bun's numeric `id` (`1120422`) is an npm registry advisory number, useless
/// as a report code and not comparable with the GHSA ids every other manager
/// emits. Prefer the GHSA sniffed out of `url` and keep the number as a
/// fallback, which inverts the precedence `advisory_id` uses elsewhere.
fn code_for(advisory: &Value) -> String {
    let ghsa = advisory
        .get("url")
        .and_then(Value::as_str)
        .and_then(ghsa_from_url);
    advisory_code(
        ghsa.or_else(|| id_value(advisory.get("id")))
            .unwrap_or_default(),
    )
}

/// The raw fields bun gives us that do not fit the row, joined but not
/// reinterpreted. bun reports no installed version, so the vulnerable range is
/// the only thing that makes the row actionable.
fn detail_for(advisory: &Value) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(range) = advisory
        .get("vulnerable_versions")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        parts.push(format!("vulnerable {range}"));
    }
    if let Some(vector) = advisory
        .get("cvss")
        .and_then(|cvss| cvss.get("vectorString"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        parts.push(vector.to_string());
    }
    if let Some(url) = advisory
        .get("url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        parts.push(url.to_string());
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" · "))
    }
}

fn finding(package: &str, advisory: &Value, path: &str) -> Finding {
    let severity = normalize_severity(advisory.get("severity"));
    let message = advisory.get("title").and_then(Value::as_str).map_or_else(
        || format!("{package} {severity} advisory"),
        ToOwned::to_owned,
    );
    Finding {
        kind: FindingKind::Advisory,
        code: code_for(advisory),
        message,
        detail: detail_for(advisory),
        severity,
        path: path.to_string(),
        fixable: false,
        manager: Some(Manager::Bun),
        package: Some(package.to_string()),
        // bun reports the vulnerable range, never the resolved version.
        current_version: None,
        fix_version: None,
        fix: None,
    }
}

/// A clean project is not an error. bun emits `{}` with `--json`, and older
/// builds print a prose line instead; both mean zero advisories, so neither may
/// surface as `AdvisoryError::Incomplete`.
pub fn parse_bun_audit(
    stdout: &str,
    lockfile_path: &str,
    _manager: Manager,
) -> Result<Vec<Finding>, serde_json::Error> {
    let body = json_slice(stdout);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let report: Value = serde_json::from_str(body)?;
    let Some(packages) = report.as_object() else {
        return Ok(Vec::new());
    };
    Ok(packages
        .iter()
        .flat_map(|(package, advisories)| {
            advisories
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .map(move |advisory| finding(package, advisory, lockfile_path))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    /// Trimmed from real `bun audit --json` output.
    const BUN_AUDIT: &str = r#"{
        "shell-quote": [
            {"id": 1120422, "url": "https://github.com/advisories/GHSA-w7jw-789q-3m8p",
             "title": "shell-quote quote() does not escape newlines in object .op values",
             "severity": "critical", "vulnerable_versions": ">=1.1.0 <=1.8.3",
             "cvss": {"score": 8.1, "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
        ],
        "nanoid": [
            {"id": 1138811, "url": "https://github.com/advisories/GHSA-28wg-ghj8-5hjv",
             "title": "nanoid: non-secure generators can loop indefinitely with negative size",
             "severity": "high", "vulnerable_versions": "<3.3.16",
             "cvss": {"score": 5.9, "vectorString": null}},
            {"id": 1139427, "url": "https://github.com/advisories/GHSA-2v37-7h3g-55p8",
             "title": "nanoid: custom generators can loop indefinitely when size is zero",
             "severity": "high", "vulnerable_versions": "<3.3.18"}
        ]
    }"#;

    fn parse(stdout: &str) -> Vec<Finding> {
        parse_bun_audit(stdout, "/p/bun.lock", Manager::Bun).unwrap()
    }

    #[test]
    fn every_advisory_under_every_package_key_becomes_a_finding() {
        assert_eq!(parse(BUN_AUDIT).len(), 3);
    }

    #[test]
    fn a_package_with_several_advisories_reports_each_one() {
        let findings = parse(BUN_AUDIT);
        let nanoid: Vec<&str> = findings
            .iter()
            .filter(|f| f.package.as_deref() == Some("nanoid"))
            .map(|f| f.code.as_str())
            .collect();
        assert_eq!(nanoid, ["GHSA-28wg-ghj8-5hjv", "GHSA-2v37-7h3g-55p8"]);
    }

    #[test]
    fn the_code_is_the_ghsa_id_not_bun_s_registry_number() {
        let findings = parse(BUN_AUDIT);
        assert_eq!(findings[0].code, "GHSA-w7jw-789q-3m8p");
    }

    #[test]
    fn a_registry_number_without_a_ghsa_url_is_the_fallback_code() {
        let findings = parse(r#"{"left-pad":[{"id":1234,"severity":"high","title":"t"}]}"#);
        assert_eq!(findings[0].code, "1234");
    }

    #[test]
    fn an_unidentified_advisory_falls_back_to_the_shared_code() {
        let findings = parse(r#"{"left-pad":[{"severity":"high","title":"t"}]}"#);
        assert_eq!(findings[0].code, "advisory.unknown");
    }

    #[test]
    fn severity_comes_from_the_advisory() {
        let findings = parse(BUN_AUDIT);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn the_package_name_is_the_map_key() {
        let findings = parse(BUN_AUDIT);
        assert_eq!(findings[0].package.as_deref(), Some("shell-quote"));
    }

    #[test]
    fn no_installed_version_is_invented() {
        assert!(parse(BUN_AUDIT).iter().all(|f| f.current_version.is_none()));
    }

    #[test]
    fn the_detail_line_carries_the_raw_range_vector_and_url() {
        let findings = parse(BUN_AUDIT);
        assert_eq!(
            findings[0].detail.as_deref(),
            Some(
                "vulnerable >=1.1.0 <=1.8.3 · CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H · https://github.com/advisories/GHSA-w7jw-789q-3m8p"
            )
        );
    }

    #[test]
    fn a_null_cvss_vector_is_left_out_of_the_detail_line() {
        let findings = parse(BUN_AUDIT);
        let nanoid = findings
            .iter()
            .find(|f| f.code == "GHSA-28wg-ghj8-5hjv")
            .unwrap();
        assert_eq!(
            nanoid.detail.as_deref(),
            Some("vulnerable <3.3.16 · https://github.com/advisories/GHSA-28wg-ghj8-5hjv")
        );
    }

    #[test]
    fn a_missing_title_falls_back_to_a_generated_message() {
        let findings = parse(r#"{"left-pad":[{"severity":"low"}]}"#);
        assert_eq!(findings[0].message, "left-pad low advisory");
    }

    #[test]
    fn a_leading_version_banner_does_not_break_the_parse() {
        let stdout = format!("bun audit v1.3.13 (bf2e2cec)\n{BUN_AUDIT}");
        assert_eq!(parse(&stdout).len(), 3);
    }

    #[test]
    fn an_empty_report_is_zero_findings_not_an_error() {
        assert!(parse("{}").is_empty());
    }

    #[test]
    fn prose_output_with_no_json_is_zero_findings_not_an_error() {
        assert!(parse("No vulnerabilities found\n").is_empty());
    }

    #[test]
    fn the_lockfile_path_is_carried_onto_every_finding() {
        assert!(parse(BUN_AUDIT)
            .iter()
            .all(|f| f.path == "/p/bun.lock" && f.manager == Some(Manager::Bun)));
    }
}
