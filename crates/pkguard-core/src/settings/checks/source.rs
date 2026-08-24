use super::{fix_for, fixable_finding, setting_finding};
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::fix::{ConfigEdit, ConfigValue};
use crate::format::yaml::{self, Yaml};
use crate::manager::{Manager, PackageManagerPin};
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
        vec![fixable_finding(
            "source.non-registry",
            "allow-git, allow-remote, allow-file, and allow-directory must not be set to all",
            Severity::High,
            npmrc_path,
            Manager::Npm,
            fix_for(
                Manager::Npm,
                npmrc_path,
                vec![
                    ConfigEdit::set("allow-directory", "none"),
                    ConfigEdit::set("allow-file", "none"),
                    ConfigEdit::set("allow-git", "none"),
                    ConfigEdit::set("allow-remote", "none"),
                ],
            ),
        )]
    } else {
        Vec::new()
    }
}

pub fn pnpm_check(yaml: &Yaml, yaml_path: &Path) -> Vec<Finding> {
    if yaml::is_false(yaml::get(yaml, "blockExoticSubdeps")) {
        vec![fixable_finding(
            "source.non-registry",
            "pnpm blockExoticSubdeps must not be false",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            fix_for(
                Manager::Pnpm,
                yaml_path,
                vec![ConfigEdit::set("blockExoticSubdeps", true)],
            ),
        )]
    } else {
        Vec::new()
    }
}

fn yarn_git_blocked(yarnrc: &Yaml) -> bool {
    let Some(raw) = yaml::get(yarnrc, "approvedGitRepositories") else {
        return false;
    };
    let Some(items) = raw.as_sequence() else {
        return false;
    };
    items.is_empty() || !items.iter().any(yaml::is_star)
}

pub fn yarn_git_check(
    settings: &ResolvedSettings,
    yarnrc: &Yaml,
    yarnrc_path: &Path,
    pin: Option<&PackageManagerPin>,
) -> Vec<Finding> {
    if !settings.ignore_scripts {
        return Vec::new();
    }
    let git_blocking = PackageManagerPin::at_least_or_unknown(pin, 4, 14);
    if git_blocking && yarn_git_blocked(yarnrc) {
        return Vec::new();
    }
    let message = if yaml::get(yarnrc, "approvedGitRepositories").is_none() {
        "yarn approvedGitRepositories must block git-sourced dependencies"
    } else {
        "yarn approvedGitRepositories must not allow every git repository"
    };
    vec![fixable_finding(
        "source.git-unrestricted",
        message,
        Severity::High,
        yarnrc_path,
        Manager::Yarn,
        fix_for(
            Manager::Yarn,
            yarnrc_path,
            vec![ConfigEdit::set(
                "approvedGitRepositories",
                ConfigValue::List(Vec::new()),
            )],
        ),
    )]
}

pub fn composer_source_fallback(
    source_fallback: bool,
    preset: crate::policy::Preset,
    config_path: &Path,
) -> Vec<Finding> {
    if source_fallback {
        vec![setting_finding(
            "source-fallback.enabled",
            "composer source-fallback must not be true",
            super::pin_severity(preset),
            config_path,
            Manager::Composer,
        )]
    } else {
        Vec::new()
    }
}
