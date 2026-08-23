use super::setting_finding;
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::manager::Manager;
use std::collections::BTreeMap;
use std::path::Path;

pub fn npm_check(
    settings: &ResolvedSettings,
    npmrc: &BTreeMap<String, String>,
    npmrc_path: &Path,
) -> Vec<Finding> {
    if settings.min_release_age_days == 0 {
        return Vec::new();
    }
    let days: Option<f64> = npmrc
        .get("min-release-age")
        .and_then(|raw| raw.trim().parse().ok());
    if days.is_some_and(|d| d >= f64::from(settings.min_release_age_days)) {
        return Vec::new();
    }
    vec![setting_finding(
        "min-age.disabled",
        format!(
            "min-release-age must be at least {} days",
            settings.min_release_age_days
        ),
        Severity::High,
        npmrc_path,
        Manager::Npm,
    )]
}
