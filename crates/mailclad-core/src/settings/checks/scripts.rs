use super::{advice_finding, default_reliance_severity, setting_finding};
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::manager::Manager;
use crate::policy::Preset;
use std::collections::BTreeMap;
use std::path::Path;

type Npmrc = BTreeMap<String, String>;

fn is_true(npmrc: &Npmrc, key: &str) -> bool {
    npmrc.get(key).map(String::as_str) == Some("true")
}

pub fn npm_checks(
    settings: &ResolvedSettings,
    npmrc: &Npmrc,
    manifest: Option<&serde_json::Value>,
    npmrc_path: &Path,
    preset: Preset,
) -> Vec<Finding> {
    let scripts_ignored = is_true(npmrc, "ignore-scripts");
    let allow_scripts = manifest
        .and_then(|m| m.get("allowScripts"))
        .is_some_and(serde_json::Value::is_object);
    let strict_allow_scripts = is_true(npmrc, "strict-allow-scripts");
    let mut findings = Vec::new();

    if settings.ignore_scripts && !scripts_ignored && !(allow_scripts && strict_allow_scripts) {
        findings.push(setting_finding(
            "scripts.unrestricted",
            "npm ignore-scripts must be true, or allowScripts with strict-allow-scripts",
            Severity::High,
            npmrc_path,
            Manager::Npm,
        ));
    }

    if settings.ignore_scripts && allow_scripts && !strict_allow_scripts {
        findings.push(advice_finding(
            "scripts.allowlist-advisory",
            "allowScripts is advisory until strict-allow-scripts=true (npm 12 default)",
            Severity::Info,
            npmrc_path,
            Manager::Npm,
        ));
    }
    // npm/cli#9450: ignore-scripts hides the allowScripts tooling entirely.
    if scripts_ignored && allow_scripts {
        findings.push(advice_finding(
            "scripts.allowlist-masked",
            "ignore-scripts=true masks the package.json allowScripts policy",
            Severity::Info,
            npmrc_path,
            Manager::Npm,
        ));
    }

    if settings.ignore_scripts && !is_true(npmrc, "allow-scripts-pin") {
        if npmrc.get("allow-scripts-pin").map(String::as_str) == Some("false") {
            findings.push(setting_finding(
                "scripts.pin-missing",
                "allow-scripts-pin must be true",
                Severity::High,
                npmrc_path,
                Manager::Npm,
            ));
        } else {
            let mut advice = advice_finding(
                "scripts.pin-missing",
                "npm defaults allow-scripts-pin to true; set it explicitly",
                default_reliance_severity(preset),
                npmrc_path,
                Manager::Npm,
            );
            advice.fixable = true;
            findings.push(advice);
        }
    }

    if settings.ignore_scripts && is_true(npmrc, "dangerously-allow-all-scripts") {
        findings.push(setting_finding(
            "scripts.bypass-enabled",
            "dangerously-allow-all-scripts must not be true",
            Severity::High,
            npmrc_path,
            Manager::Npm,
        ));
    }

    findings
}
