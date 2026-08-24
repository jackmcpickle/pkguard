use super::{fixable_finding, pin_severity, setting_finding};
use crate::config::ResolvedSettings;
use crate::findings::Finding;
use crate::fix::SettingsFix;
use crate::manager::Manager;
use crate::policy::Preset;
use std::path::Path;

fn normalize(url: &str) -> &str {
    url.trim().trim_end_matches('/')
}

pub fn same_registry(actual: &str, expected: &str) -> bool {
    normalize(actual) == normalize(expected)
}

pub fn check(
    current_url: Option<&str>,
    settings: &ResolvedSettings,
    unpinned_message: &str,
    preset: Preset,
    path: &Path,
    manager: Manager,
    fix: Option<SettingsFix>,
) -> Vec<Finding> {
    let current = current_url.map(str::trim).filter(|s| !s.is_empty());
    let Some(current) = current else {
        return vec![match fix {
            Some(fix) => fixable_finding(
                "registry.unpinned",
                unpinned_message,
                pin_severity(preset),
                path,
                manager,
                fix,
            ),
            None => setting_finding(
                "registry.unpinned",
                unpinned_message,
                pin_severity(preset),
                path,
                manager,
            ),
        }];
    };
    match settings.registry.as_deref() {
        Some(expected) if !same_registry(current, expected) => vec![setting_finding(
            "registry.mismatch",
            format!("registry must be {expected}"),
            pin_severity(preset),
            path,
            manager,
        )],
        _ => Vec::new(),
    }
}
