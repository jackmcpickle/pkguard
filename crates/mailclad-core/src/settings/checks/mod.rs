//! One deep module per check family; per-manager variation is data passed in
//! from the manager profile, not a per-manager reimplementation.

pub mod audit_gate;
pub mod lockfile;
pub mod min_age;
pub mod pm_pin;
pub mod registry;
pub mod scripts;
pub mod source;

use crate::config::ResolvedSettings;
use crate::discover::DetectedManager;
use crate::findings::{Finding, FindingKind, Severity};
use crate::format::npmrc;
use crate::manager::Manager;
use crate::policy::Preset;
use std::collections::BTreeMap;
use std::path::Path;

/// Severity for "you're relying on a safe default instead of pinning it".
pub fn default_reliance_severity(preset: Preset) -> Severity {
    if preset == Preset::Strict {
        Severity::Moderate
    } else {
        Severity::Info
    }
}

/// Severity for missing pins (registry, packageManager).
pub fn pin_severity(preset: Preset) -> Severity {
    if preset == Preset::Strict {
        Severity::High
    } else {
        Severity::Info
    }
}

pub fn setting_finding(
    code: &str,
    message: impl Into<String>,
    severity: Severity,
    path: &Path,
    manager: Manager,
) -> Finding {
    Finding {
        kind: FindingKind::Settings,
        code: code.to_string(),
        message: message.into(),
        severity,
        path: path.to_string_lossy().into_owned(),
        fixable: true,
        manager: Some(manager),
        package: None,
        current_version: None,
        fix_version: None,
    }
}

pub fn advice_finding(
    code: &str,
    message: impl Into<String>,
    severity: Severity,
    path: &Path,
    manager: Manager,
) -> Finding {
    Finding {
        fixable: false,
        ..setting_finding(code, message, severity, path, manager)
    }
}

fn manifest_json(project_root: &Path) -> Option<serde_json::Value> {
    let raw = std::fs::read_to_string(project_root.join("package.json")).ok()?;
    serde_json::from_str(&raw).ok()
}

/// The npm settings audit: check families composed over the parsed .npmrc.
pub fn npm_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let npmrc_path = manager
        .config_path
        .clone()
        .unwrap_or_else(|| project_root.join(".npmrc"));
    let npmrc: BTreeMap<String, String> = std::fs::read_to_string(&npmrc_path)
        .map(|raw| npmrc::parse(&raw))
        .unwrap_or_default();
    let manifest = manifest_json(project_root);
    let preset = settings.preset;

    let mut findings = Vec::new();
    findings.extend(scripts::npm_checks(
        settings, &npmrc, manifest.as_ref(), &npmrc_path, preset,
    ));
    findings.extend(source::npm_check(settings, &npmrc, &npmrc_path));
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager
            .lockfile_path
            .as_deref()
            .is_some_and(Path::is_file),
        &manager
            .lockfile_path
            .clone()
            .unwrap_or_else(|| project_root.join("package-lock.json")),
        "package-lock.json is required",
        Manager::Npm,
    ));
    findings.extend(audit_gate::npm_check(settings, &npmrc, &npmrc_path));
    findings.extend(min_age::npm_check(settings, &npmrc, &npmrc_path));
    findings.extend(registry::check(
        npmrc.get("registry").map(String::as_str),
        settings,
        "registry must be set in .npmrc",
        preset,
        &npmrc_path,
        Manager::Npm,
    ));
    findings.extend(pm_pin::check(
        settings.require_pm_pin,
        manifest
            .as_ref()
            .and_then(|m| m.get("packageManager"))
            .and_then(|v| v.as_str())
            .is_some_and(|v| v.starts_with("npm@")),
        "package.json packageManager must start with npm@",
        preset,
        &project_root.join("package.json"),
        Manager::Npm,
    ));
    findings
}
