use super::setting_finding;
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::manager::Manager;
use std::collections::BTreeMap;
use std::path::Path;

fn severity_of(name: &str) -> Option<Severity> {
    match name {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "moderate" => Some(Severity::Moderate),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

/// audit=true always passes; otherwise an explicit audit-level at or below the
/// gate passes (a stricter-than-gate level would miss required findings).
fn audit_meets_gate(audit_enabled: bool, audit_level: Option<&str>, gate: Severity) -> bool {
    if audit_enabled {
        return true;
    }
    let Some(level) = audit_level.map(str::to_lowercase).and_then(|l| severity_of(&l)) else {
        return false;
    };
    gate >= level
}

pub fn npm_check(
    settings: &ResolvedSettings,
    npmrc: &BTreeMap<String, String>,
    npmrc_path: &Path,
) -> Vec<Finding> {
    let enabled = npmrc.get("audit").map(String::as_str) == Some("true");
    if audit_meets_gate(
        enabled,
        npmrc.get("audit-level").map(String::as_str),
        settings.audit_level,
    ) {
        Vec::new()
    } else {
        vec![setting_finding(
            "audit.disabled",
            "npm audit must be enabled at the preset gate",
            Severity::High,
            npmrc_path,
            Manager::Npm,
        )]
    }
}
