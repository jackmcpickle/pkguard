use super::setting_finding;
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::manager::Manager;
use std::collections::BTreeMap;
use std::path::Path;

const NON_REGISTRY_KEYS: [&str; 4] = ["allow-git", "allow-remote", "allow-file", "allow-directory"];

pub fn npm_check(
    settings: &ResolvedSettings,
    npmrc: &BTreeMap<String, String>,
    npmrc_path: &Path,
) -> Vec<Finding> {
    let allows_non_registry = NON_REGISTRY_KEYS
        .iter()
        .any(|key| npmrc.get(*key).map(String::as_str) == Some("all"));
    if settings.ignore_scripts && allows_non_registry {
        vec![setting_finding(
            "source.non-registry",
            "allow-git, allow-remote, allow-file, and allow-directory must not be set to all",
            Severity::High,
            npmrc_path,
            Manager::Npm,
        )]
    } else {
        Vec::new()
    }
}
