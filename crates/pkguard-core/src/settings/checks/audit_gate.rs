use super::{fix_for, fixable_finding, ComposerSecurity};
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::fix::ConfigEdit;
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
        vec![fixable_finding(
            "audit.disabled",
            "npm audit must be enabled at the preset gate",
            Severity::High,
            npmrc_path,
            Manager::Npm,
            fix_for(
                Manager::Npm,
                npmrc_path,
                vec![
                    ConfigEdit::set("audit", true),
                    ConfigEdit::set("audit-level", settings.audit_level.as_str()),
                ],
            ),
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

#[must_use]
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
    let key = if modern { "audit.level" } else { "auditLevel" };
    vec![fixable_finding(
        "audit.disabled",
        if modern {
            "pnpm audit.level must meet the preset gate"
        } else {
            "pnpm auditLevel must meet the preset gate"
        },
        Severity::High,
        yaml_path,
        Manager::Pnpm,
        fix_for(
            Manager::Pnpm,
            yaml_path,
            vec![ConfigEdit::set(key, settings.audit_level.as_str())],
        ),
    )]
}

#[must_use]
pub fn yarn_check(yarnrc: &Yaml, yarnrc_path: &Path) -> Vec<Finding> {
    let disabled = ["audit", "npmAudit", "enableNpmAudit"]
        .into_iter()
        .any(|key| yaml::is_false(yaml::get(yarnrc, key)));
    if disabled {
        vec![fixable_finding(
            "audit.disabled",
            "yarn audit must not be disabled",
            Severity::High,
            yarnrc_path,
            Manager::Yarn,
            fix_for(Manager::Yarn, yarnrc_path, yarn_audit_edits(yarnrc)),
        )]
    } else {
        Vec::new()
    }
}

fn yarn_audit_edits(yarnrc: &Yaml) -> Vec<ConfigEdit> {
    let mut edits = Vec::new();
    if yaml::get(yarnrc, "audit").is_some() {
        edits.push(ConfigEdit::unset("audit"));
    }
    if yaml::get(yarnrc, "npmAudit").is_some() {
        edits.push(ConfigEdit::unset("npmAudit"));
    }
    edits.push(ConfigEdit::set("enableNpmAudit", true));
    edits
}

pub fn uv_malware(
    cfg: &toml::Value,
    config_path: &Path,
    pin: Option<&PackageManagerPin>,
    key_prefix: &str,
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
        vec![fixable_finding(
            "audit.malware-disabled",
            "uv audit malware-check must be true",
            Severity::High,
            config_path,
            Manager::Uv,
            fix_for(
                Manager::Uv,
                config_path,
                vec![ConfigEdit::set(
                    format!("{key_prefix}audit.malware-check"),
                    true,
                )],
            ),
        )]
    }
}

/// Composer's audit-gate findings, read straight off the parsed manifest
/// settings rather than from four positional booleans.
#[must_use]
pub fn composer_policy(security: &ComposerSecurity, config_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    if security.policy_disabled || security.advisories_ignore {
        findings.push(fixable_finding(
            "audit.disabled",
            "composer policy.advisories.audit must not be ignore",
            Severity::High,
            config_path,
            Manager::Composer,
            fix_for(
                Manager::Composer,
                config_path,
                vec![
                    ConfigEdit::set("config.policy.advisories.audit", "fail"),
                    ConfigEdit::set("config.policy.advisories.block", true),
                    ConfigEdit::set("config.policy.malware.block", true),
                ],
            ),
        ));
    }
    if !security.advisories_block {
        findings.push(fixable_finding(
            "audit.blocking-disabled",
            "composer policy.advisories.block must be true",
            Severity::High,
            config_path,
            Manager::Composer,
            fix_for(
                Manager::Composer,
                config_path,
                vec![ConfigEdit::set("config.policy.advisories.block", true)],
            ),
        ));
    }
    if !security.malware_block {
        findings.push(fixable_finding(
            "audit.malware-disabled",
            "composer policy.malware.block must be true",
            Severity::High,
            config_path,
            Manager::Composer,
            fix_for(
                Manager::Composer,
                config_path,
                vec![ConfigEdit::set("config.policy.malware.block", true)],
            ),
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_enabled_audit_always_meets_the_gate() {
        assert!(audit_meets_gate(true, None, Severity::Critical));
        assert!(audit_meets_gate(true, Some("low"), Severity::Info));
    }

    #[test]
    fn a_disabled_audit_without_a_level_never_meets_the_gate() {
        assert!(!audit_meets_gate(false, None, Severity::Info));
        assert!(!audit_meets_gate(false, Some("nonsense"), Severity::Info));
    }

    #[test]
    fn a_level_at_or_below_the_gate_passes() {
        // A level stricter than the gate would miss findings the gate requires.
        assert!(audit_meets_gate(false, Some("low"), Severity::High));
        assert!(audit_meets_gate(false, Some("high"), Severity::High));
        assert!(!audit_meets_gate(false, Some("critical"), Severity::High));
    }

    #[test]
    fn levels_are_matched_case_insensitively() {
        assert!(audit_meets_gate(false, Some("HIGH"), Severity::High));
        assert!(audit_meets_gate(false, Some("Moderate"), Severity::High));
    }

    #[test]
    fn severity_names_map_to_every_severity() {
        assert_eq!(severity_of("critical"), Some(Severity::Critical));
        assert_eq!(severity_of("info"), Some(Severity::Info));
        assert_eq!(severity_of("bogus"), None);
    }
}
