pub mod bun;
pub mod generic;
pub mod npm;

use crate::findings::Severity;
use serde_json::Value;

/// Accepts strings, arrays (first entry wins), numbers; "medium" maps to
/// moderate; anything unrecognized is info — mirrors the TS asSeverity.
pub fn normalize_severity(value: Option<&Value>) -> Severity {
    let raw = match value {
        Some(Value::Array(items)) => items.first(),
        other => other,
    };
    let s = match raw {
        Some(Value::String(s)) => s.to_lowercase(),
        Some(other) => other.to_string().to_lowercase(),
        None => String::new(),
    };
    match s.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" | "medium" => Severity::Moderate,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn id_value(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub fn ghsa_from_url(url: &str) -> Option<String> {
    let start = url.to_uppercase().find("GHSA-")?;
    let id: String = url[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    Some(id)
}

/// Precedence mirrors the TS rawAdvisoryId: `github_advisory_id`, id, cve,
/// then a GHSA id sniffed out of the advisory URL. Empty string = unknown.
pub fn advisory_id(
    github_advisory_id: Option<&Value>,
    id: Option<&Value>,
    cve: Option<&Value>,
    url: Option<&str>,
) -> String {
    id_value(github_advisory_id)
        .or_else(|| id_value(id))
        .or_else(|| id_value(cve))
        .or_else(|| url.and_then(ghsa_from_url))
        .unwrap_or_default()
}

/// The finding code for an advisory id. `advisory_id` returns an empty string
/// when nothing identifies the advisory; that sentinel is meaningless outside
/// this fallback, so the two live together.
pub fn advisory_code(id: String) -> String {
    if id.is_empty() {
        "advisory.unknown".to_string()
    } else {
        id
    }
}

/// npm's fixAvailable is an object {version}, a boolean, or a version string.
pub fn fix_from_available(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => match map.get("version") {
            Some(Value::String(v)) if !v.is_empty() => Some(v.clone()),
            _ => None,
        },
        Value::String(s) if !s.is_empty() && s != "true" => Some(s.clone()),
        _ => None,
    }
}

/// Only concrete installed versions count — ranges and x-ranges do not.
pub fn concrete_version(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| "<> =|^~*".contains(c)) {
        return None;
    }
    let core = trimmed.split(['-', '+']).next().unwrap_or("");
    let segments: Vec<&str> = core.split('.').collect();
    if segments.len() < 2 {
        return None;
    }
    if !segments
        .iter()
        .all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod code_tests {
    use super::*;

    #[test]
    fn an_identified_advisory_keeps_its_id_as_the_code() {
        assert_eq!(advisory_code("GHSA-abcd".into()), "GHSA-abcd");
        assert_eq!(advisory_code("CVE-2024-1".into()), "CVE-2024-1");
    }

    #[test]
    fn an_unidentified_advisory_falls_back_to_a_shared_code() {
        // `advisory_id` returns "" when nothing identifies the advisory.
        assert_eq!(advisory_code(String::new()), "advisory.unknown");
        assert_eq!(
            advisory_code(advisory_id(None, None, None, None)),
            "advisory.unknown"
        );
    }
}
