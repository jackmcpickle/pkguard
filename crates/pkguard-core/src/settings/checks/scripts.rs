use super::{advice_finding, default_reliance_severity, fix_for, fixable_finding};
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::fix::{ConfigEdit, ConfigValue};
use crate::format::yaml::{self, Yaml};
use crate::manager::{Manager, PackageManagerPin};
use crate::policy::Preset;
use std::collections::BTreeMap;
use std::path::Path;
use toml::Value as TomlValue;

const PNPM_LEGACY_BUILD_KEYS: [&str; 5] = [
    "onlyBuiltDependencies",
    "onlyBuiltDependenciesFile",
    "neverBuiltDependencies",
    "ignoredBuiltDependencies",
    "ignoreDepScripts",
];

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
        findings.push(fixable_finding(
            "scripts.unrestricted",
            "npm ignore-scripts must be true, or allowScripts with strict-allow-scripts",
            Severity::High,
            npmrc_path,
            Manager::Npm,
            fix_for(
                Manager::Npm,
                npmrc_path,
                vec![ConfigEdit::set("ignore-scripts", true)],
            ),
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
        let pin_fix = fix_for(
            Manager::Npm,
            npmrc_path,
            vec![ConfigEdit::set("allow-scripts-pin", true)],
        );
        if npmrc.get("allow-scripts-pin").map(String::as_str) == Some("false") {
            findings.push(fixable_finding(
                "scripts.pin-missing",
                "allow-scripts-pin must be true",
                Severity::High,
                npmrc_path,
                Manager::Npm,
                pin_fix,
            ));
        } else {
            findings.push(fixable_finding(
                "scripts.pin-missing",
                "npm defaults allow-scripts-pin to true; set it explicitly",
                default_reliance_severity(preset),
                npmrc_path,
                Manager::Npm,
                pin_fix,
            ));
        }
    }

    if settings.ignore_scripts && is_true(npmrc, "dangerously-allow-all-scripts") {
        findings.push(fixable_finding(
            "scripts.bypass-enabled",
            "dangerously-allow-all-scripts must not be true",
            Severity::High,
            npmrc_path,
            Manager::Npm,
            fix_for(
                Manager::Npm,
                npmrc_path,
                vec![ConfigEdit::set("dangerously-allow-all-scripts", false)],
            ),
        ));
    }

    findings
}

#[must_use]
pub fn pnpm_checks(
    settings: &ResolvedSettings,
    yaml: &Yaml,
    yaml_path: &Path,
    pin: Option<&PackageManagerPin>,
    preset: Preset,
) -> Vec<Finding> {
    if !settings.ignore_scripts {
        return Vec::new();
    }
    let mut findings = pnpm_builds_findings(yaml, yaml_path, pin, preset);
    if yaml::is_false(yaml::get(yaml, "strictDepBuilds")) {
        findings.push(fixable_finding(
            "scripts.non-strict",
            "pnpm strictDepBuilds must not be false",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            fix_for(
                Manager::Pnpm,
                yaml_path,
                vec![ConfigEdit::set("strictDepBuilds", true)],
            ),
        ));
    }
    findings
}

fn pnpm_builds_findings(
    yaml: &Yaml,
    yaml_path: &Path,
    pin: Option<&PackageManagerPin>,
    preset: Preset,
) -> Vec<Finding> {
    let uses_allow_builds = PackageManagerPin::at_least_or_unknown(pin, 11, 0);
    let builds_blocked_by_default = PackageManagerPin::at_least_or_unknown(pin, 10, 0);
    let has_allow_builds = yaml::is_mapping(yaml::get(yaml, "allowBuilds"));
    let legacy: Vec<&str> = PNPM_LEGACY_BUILD_KEYS
        .into_iter()
        .filter(|key| yaml::get(yaml, key).is_some())
        .collect();

    let build_fix = fix_for(Manager::Pnpm, yaml_path, pnpm_build_edits(yaml));
    if yaml::is_true(yaml::get(yaml, "dangerouslyAllowAllBuilds")) {
        return vec![fixable_finding(
            "scripts.unrestricted",
            "pnpm dangerouslyAllowAllBuilds must not be true",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            build_fix,
        )];
    }
    if uses_allow_builds && !legacy.is_empty() && !has_allow_builds {
        return vec![fixable_finding(
            "scripts.legacy-config",
            format!(
                "pnpm 11 removed {}; use allowBuilds instead",
                legacy.join(", ")
            ),
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            build_fix,
        )];
    }
    if !has_allow_builds && legacy.is_empty() {
        return vec![pnpm_default_builds_finding(
            yaml,
            yaml_path,
            builds_blocked_by_default,
            preset,
        )];
    }
    Vec::new()
}

#[must_use]
pub fn yarn_check(
    settings: &ResolvedSettings,
    yarnrc: &Yaml,
    yarnrc_path: &Path,
    pin: Option<&PackageManagerPin>,
    preset: Preset,
) -> Vec<Finding> {
    if !settings.ignore_scripts || yaml::is_false(yaml::get(yarnrc, "enableScripts")) {
        return Vec::new();
    }
    let scripts_off_by_default = PackageManagerPin::at_least_or_unknown(pin, 4, 14);
    let fix = fix_for(
        Manager::Yarn,
        yarnrc_path,
        vec![ConfigEdit::set("enableScripts", false)],
    );
    if yaml::is_true(yaml::get(yarnrc, "enableScripts")) || !scripts_off_by_default {
        return vec![fixable_finding(
            "scripts.unrestricted",
            "yarn enableScripts must be false",
            Severity::High,
            yarnrc_path,
            Manager::Yarn,
            fix,
        )];
    }
    vec![fixable_finding(
        "scripts.unrestricted",
        "yarn defaults enableScripts to false; set it explicitly to keep that guarantee",
        default_reliance_severity(preset),
        yarnrc_path,
        Manager::Yarn,
        fix,
    )]
}

const BUN_AUTO_SCRIPT_VALUES: [&str; 5] = ["auto", "force", "fallback", "true", "all"];

fn bun_auto_allows_scripts(auto: Option<&TomlValue>) -> bool {
    match auto {
        Some(TomlValue::Boolean(true)) => true,
        Some(TomlValue::String(value)) => {
            BUN_AUTO_SCRIPT_VALUES.contains(&value.trim().to_ascii_lowercase().as_str())
        }
        _ => false,
    }
}

fn bun_deny_scripts(bunfig: &TomlValue, install: Option<&toml::Table>) -> bool {
    let top = bunfig.get("ignoreScripts").and_then(TomlValue::as_bool) == Some(true)
        || bunfig.get("ignore-scripts").and_then(TomlValue::as_bool) == Some(true);
    let nested = install.is_some_and(|table| {
        table.get("ignoreScripts").and_then(toml::Value::as_bool) == Some(true)
            || table.get("ignore-scripts").and_then(toml::Value::as_bool) == Some(true)
    });
    top || nested
}

fn bun_has_trusted(bunfig: &toml::Value, install: Option<&toml::Table>) -> bool {
    bunfig.get("trustedDependencies").is_some()
        || install.is_some_and(|table| table.get("trustedDependencies").is_some())
}

pub fn bun_check(
    settings: &ResolvedSettings,
    bunfig: &toml::Value,
    bunfig_path: &Path,
) -> Vec<Finding> {
    if !settings.ignore_scripts {
        return Vec::new();
    }
    let install = bunfig.get("install").and_then(toml::Value::as_table);
    let unrestricted = bun_auto_allows_scripts(install.and_then(|t| t.get("auto")))
        || (!bun_has_trusted(bunfig, install)
            && install.is_none_or(|t| t.get("security").and_then(toml::Value::as_table).is_none())
            && !bun_deny_scripts(bunfig, install));
    if unrestricted {
        vec![fixable_finding(
            "scripts.unrestricted",
            "bun scripts must be restricted",
            Severity::High,
            bunfig_path,
            Manager::Bun,
            fix_for(
                Manager::Bun,
                bunfig_path,
                vec![ConfigEdit::set("install.ignoreScripts", true)],
            ),
        )]
    } else {
        Vec::new()
    }
}

#[must_use]
pub fn composer_check(
    settings: &ResolvedSettings,
    allow_plugins: Option<&serde_json::Value>,
    config_path: &Path,
) -> Vec<Finding> {
    if settings.ignore_scripts && allow_plugins == Some(&serde_json::Value::Bool(true)) {
        vec![fixable_finding(
            "scripts.unrestricted",
            "composer allow-plugins must not be true",
            Severity::High,
            config_path,
            Manager::Composer,
            fix_for(
                Manager::Composer,
                config_path,
                vec![ConfigEdit::set("config.allow-plugins", false)],
            ),
        )]
    } else {
        Vec::new()
    }
}

fn yaml_string_seq(value: Option<&Yaml>) -> Vec<String> {
    value
        .and_then(Yaml::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn yaml_bool_table(value: Option<&Yaml>) -> BTreeMap<String, ConfigValue> {
    let Some(map) = value.and_then(Yaml::as_mapping) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for (key, child) in map {
        if let (Some(name), Some(flag)) = (key.as_str(), child.as_bool()) {
            out.insert(name.to_string(), ConfigValue::Bool(flag));
        }
    }
    out
}

fn pnpm_build_edits(yaml: &Yaml) -> Vec<ConfigEdit> {
    let mut allow_builds = yaml_bool_table(yaml::get(yaml, "allowBuilds"));
    let merge = |allow_builds: &mut BTreeMap<String, ConfigValue>, key: &str, allowed: bool| {
        for name in yaml_string_seq(yaml::get(yaml, key)) {
            allow_builds
                .entry(name)
                .or_insert(ConfigValue::Bool(allowed));
        }
    };
    merge(&mut allow_builds, "onlyBuiltDependencies", true);
    merge(&mut allow_builds, "neverBuiltDependencies", false);
    merge(&mut allow_builds, "ignoredBuiltDependencies", false);
    let mut edits = vec![ConfigEdit::set("dangerouslyAllowAllBuilds", false)];
    for key in PNPM_LEGACY_BUILD_KEYS {
        if yaml::get(yaml, key).is_some() {
            edits.push(ConfigEdit::unset(key));
        }
    }
    edits.push(ConfigEdit::set(
        "allowBuilds",
        ConfigValue::Table(allow_builds),
    ));
    edits
}

fn pnpm_default_builds_finding(
    yaml: &Yaml,
    yaml_path: &Path,
    builds_blocked_by_default: bool,
    preset: Preset,
) -> Finding {
    let fix = fix_for(Manager::Pnpm, yaml_path, pnpm_build_edits(yaml));
    if builds_blocked_by_default {
        fixable_finding(
            "scripts.unrestricted",
            "pnpm blocks dependency builds by default; declare allowBuilds to review them explicitly",
            default_reliance_severity(preset),
            yaml_path,
            Manager::Pnpm,
            fix,
        )
    } else {
        fixable_finding(
            "scripts.unrestricted",
            "pnpm builds must be restricted",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            fix,
        )
    }
}
