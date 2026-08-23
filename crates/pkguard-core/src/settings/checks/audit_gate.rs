use super::setting_finding;
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::format::yaml::{self, Yaml};
use crate::manager::{Manager, PackageManagerPin};
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
    let Some(level) = audit_level
        .map(str::to_lowercase)
        .and_then(|l| severity_of(&l))
    else {
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

fn pnpm_audit_level(yaml: &Yaml) -> Option<&str> {
    if let Some(audit) = yaml::get(yaml, "audit") {
        if let Some(level) = yaml::get(audit, "level").and_then(yaml::as_str) {
            return Some(level);
        }
    }
    yaml::first(yaml, &["auditLevel", "audit-level"]).and_then(yaml::as_str)
}

pub fn pnpm_check(
    settings: &ResolvedSettings,
    yaml: &Yaml,
    yaml_path: &Path,
    pin: Option<&PackageManagerPin>,
) -> Vec<Finding> {
    if audit_meets_gate(false, pnpm_audit_level(yaml), settings.audit_level) {
        return Vec::new();
    }
    let modern = PackageManagerPin::at_least_or_unknown(pin, 11, 16);
    vec![setting_finding(
        "audit.disabled",
        if modern {
            "pnpm audit.level must meet the preset gate"
        } else {
            "pnpm auditLevel must meet the preset gate"
        },
        Severity::High,
        yaml_path,
        Manager::Pnpm,
    )]
}

pub fn yarn_check(yarnrc: &Yaml, yarnrc_path: &Path) -> Vec<Finding> {
    let disabled = ["audit", "npmAudit", "enableNpmAudit"]
        .into_iter()
        .any(|key| yaml::is_false(yaml::get(yarnrc, key)));
    if disabled {
        vec![setting_finding(
            "audit.disabled",
            "yarn audit must not be disabled",
            Severity::High,
            yarnrc_path,
            Manager::Yarn,
        )]
    } else {
        Vec::new()
    }
}

pub fn uv_malware(
    cfg: &toml::Value,
    config_path: &Path,
    pin: Option<&PackageManagerPin>,
) -> Vec<Finding> {
    if !PackageManagerPin::at_least_patch_or_unknown(pin, 0, 11, 31) {
        return Vec::new();
    }
    let enabled = cfg
        .get("audit")
        .and_then(toml::Value::as_table)
        .and_then(|audit| audit.get("malware-check"))
        .and_then(toml::Value::as_bool)
        == Some(true);
    if enabled {
        Vec::new()
    } else {
        vec![setting_finding(
            "audit.malware-disabled",
            "uv audit malware-check must be true",
            Severity::High,
            config_path,
            Manager::Uv,
        )]
    }
}

pub fn composer_policy(
    policy_disabled: bool,
    advisories_audit_ignore: bool,
    advisories_block: bool,
    malware_block: bool,
    config_path: &Path,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if policy_disabled || advisories_audit_ignore {
        findings.push(setting_finding(
            "audit.disabled",
            "composer policy.advisories.audit must not be ignore",
            Severity::High,
            config_path,
            Manager::Composer,
        ));
    }
    if !advisories_block {
        findings.push(setting_finding(
            "audit.blocking-disabled",
            "composer policy.advisories.block must be true",
            Severity::High,
            config_path,
            Manager::Composer,
        ));
    }
    if !malware_block {
        findings.push(setting_finding(
            "audit.malware-disabled",
            "composer policy.malware.block must be true",
            Severity::High,
            config_path,
            Manager::Composer,
        ));
    }
    findings
}
