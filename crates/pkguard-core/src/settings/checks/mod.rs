//! One deep module per check family; per-manager variation is data passed in
//! from the manager profile, not a per-manager reimplementation.

pub mod audit_gate;
pub mod integrity;
pub mod lockfile;
pub mod min_age;
pub mod pm_pin;
pub mod provenance;
pub mod registry;
pub mod scripts;
pub mod source;

use crate::clock::Clock;
use crate::config::ResolvedSettings;
use crate::discover::{DetectedManager, Project};
use crate::findings::{Finding, FindingKind, Severity};
use crate::fix::{ConfigEdit, SettingsFix};
use crate::format::{bundle_config, npmrc, yaml};
use crate::manager::{Manager, PackageManagerPin};
use crate::policy::Preset;
use std::collections::BTreeMap;
use std::path::Path;

/// Severity for "you're relying on a safe default instead of pinning it".
#[must_use]
pub fn default_reliance_severity(preset: Preset) -> Severity {
    if preset == Preset::Strict {
        Severity::Moderate
    } else {
        Severity::Info
    }
}

/// Severity for missing pins (registry, packageManager).
#[must_use]
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
        // Unfixable until a `SettingsFix` is attached via `fixable_finding`.
        // The two fields must stay in step — see the consistency test.
        fixable: false,
        manager: Some(manager),
        package: None,
        current_version: None,
        fix_version: None,
        fix: None,
    }
}

/// A settings finding that `--fix` can repair. `fixable` and `fix` must stay
/// in step; this builder is the only way to set them, so they cannot drift.
pub fn fixable_finding(
    code: &str,
    message: impl Into<String>,
    severity: Severity,
    path: &Path,
    manager: Manager,
    fix: SettingsFix,
) -> Finding {
    Finding {
        fixable: true,
        fix: Some(fix),
        ..setting_finding(code, message, severity, path, manager)
    }
}

/// Build a fix for `manager`'s config file. The format comes from
/// `Manager::config_format`, so a check module states *which manager* it is
/// checking — never which format that manager happens to use.
///
/// # Panics
///
/// Panics only for managers that cannot be written (`is_legacy_python`), which
/// never reach a check module.
#[must_use]
pub fn fix_for(manager: Manager, file: &Path, edits: Vec<ConfigEdit>) -> SettingsFix {
    let format = manager
        .config_format()
        .unwrap_or_else(|| panic!("{} has no writable config format", manager.name()));
    SettingsFix::new(file, format, edits)
}

fn registry_url_fix(
    manager: Manager,
    file: &Path,
    key: &str,
    settings: &ResolvedSettings,
) -> Option<SettingsFix> {
    settings
        .registry
        .as_ref()
        .map(|url| fix_for(manager, file, vec![ConfigEdit::set(key, url.as_str())]))
}

/// The config file to read and fix: whatever discovery found, else the
/// manager's default location.
fn config_path_for(project_root: &Path, manager: &DetectedManager) -> std::path::PathBuf {
    manager.config_path.clone().unwrap_or_else(|| {
        manager
            .manager
            .default_config_path(project_root)
            .unwrap_or_else(|| project_root.to_path_buf())
    })
}

/// The lockfile to report on: whatever discovery found, else the manager's
/// first accepted name.
fn lockfile_path_for(project_root: &Path, manager: &DetectedManager) -> std::path::PathBuf {
    manager.lockfile_path.clone().unwrap_or_else(|| {
        manager
            .manager
            .default_lockfile_path(project_root)
            .unwrap_or_else(|| project_root.to_path_buf())
    })
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
    let npmrc_path = config_path_for(project_root, manager);
    let npmrc: BTreeMap<String, String> = std::fs::read_to_string(&npmrc_path)
        .map(|raw| npmrc::parse(&raw))
        .unwrap_or_default();
    let manifest = manifest_json(project_root);
    let preset = settings.preset;

    let mut findings = Vec::new();
    findings.extend(scripts::npm_checks(
        settings,
        &npmrc,
        manifest.as_ref(),
        &npmrc_path,
        preset,
    ));
    findings.extend(source::npm_check(settings, &npmrc, &npmrc_path));
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &lockfile_path_for(project_root, manager),
        Manager::Npm,
    ));
    findings.extend(audit_gate::npm_check(settings, &npmrc, &npmrc_path));
    findings.extend(min_age::npm_check(settings, &npmrc, &npmrc_path));
    findings.extend(registry::check(
        npmrc.get("registry").map(String::as_str),
        settings,
        "registry must be set in .npmrc",
        &npmrc_path,
        Manager::Npm,
        registry_url_fix(Manager::Npm, &npmrc_path, "registry", settings),
    ));
    findings.extend(pm_pin::check(
        settings.require_pm_pin,
        PackageManagerPin::from_manifest(project_root).as_ref(),
        Manager::Npm,
        preset,
        project_root,
    ));
    findings
}

fn role_path(project_root: &Path, manager: &DetectedManager) -> std::path::PathBuf {
    manager
        .lockfile_path
        .clone()
        .unwrap_or_else(|| project_root.to_path_buf())
}

#[must_use]
pub fn leftover_finding(project_root: &Path, manager: &DetectedManager) -> Finding {
    lockfile::leftover(&role_path(project_root, manager), manager.manager)
}

const NODE_MANAGERS: [Manager; 4] = [Manager::Npm, Manager::Pnpm, Manager::Yarn, Manager::Bun];
const PYTHON_MANAGERS: [Manager; 4] = [Manager::Uv, Manager::Poetry, Manager::Pip, Manager::Pipenv];

fn multiple_pm_finding(
    project: &Project,
    code: &str,
    label: &str,
    managers: &[Manager],
) -> Option<Finding> {
    let present: Vec<&DetectedManager> = project
        .managers
        .iter()
        .filter(|detected| managers.contains(&detected.manager))
        .collect();
    if present.len() < 2 {
        return None;
    }
    let primary = present
        .iter()
        .find(|detected| detected.role == crate::discover::Role::Primary)
        .or_else(|| present.first())
        .copied()?;
    let names = present
        .iter()
        .map(|detected| detected.manager.name())
        .collect::<Vec<_>>()
        .join(", ");
    Some(Finding {
        kind: FindingKind::Settings,
        code: code.into(),
        message: format!("Multiple {label} package managers in use: {names}"),
        severity: Severity::High,
        path: project.root.to_string_lossy().into_owned(),
        fixable: false,
        manager: Some(primary.manager),
        package: None,
        current_version: None,
        fix_version: None,
        fix: None,
    })
}

/// Cross-manager findings from the TS `auditSettings` entry: leftover yarn
/// next to pnpm still counts as two node managers.
#[must_use]
pub fn multiple_pm_findings(project: &Project) -> Vec<Finding> {
    [
        multiple_pm_finding(project, "pm.multiple-node", "node", &NODE_MANAGERS),
        multiple_pm_finding(project, "pm.multiple-python", "python", &PYTHON_MANAGERS),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[must_use]
pub fn unsupported_finding(project_root: &Path, manager: &DetectedManager) -> Finding {
    lockfile::unsupported(&role_path(project_root, manager), manager.manager)
}

fn pnpm_registry_url(yaml_value: &yaml::Yaml) -> Option<String> {
    if let Some(url) = yaml::get(yaml_value, "registry")
        .and_then(yaml::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(url.to_string());
    }
    yaml::get(yaml_value, "registries")
        .and_then(|registries| yaml::get(registries, "default"))
        .and_then(yaml::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// The pnpm settings audit: check families composed over pnpm-workspace.yaml.
pub fn pnpm_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let yaml_path = config_path_for(project_root, manager);
    let yaml_value = std::fs::read_to_string(&yaml_path)
        .map_or_else(|_| yaml::parse(""), |raw| yaml::parse(&raw));
    let pin = PackageManagerPin::from_manifest(project_root).filter(|p| p.name == "pnpm");
    let uses_allow_builds = PackageManagerPin::at_least_or_unknown(pin.as_ref(), 11, 0);
    let preset = settings.preset;
    let lockfile_off = yaml::is_false(yaml::get(&yaml_value, "lockfile"));
    let registry = pnpm_registry_url(&yaml_value);

    let mut findings = Vec::new();
    findings.extend(scripts::pnpm_checks(
        settings,
        &yaml_value,
        &yaml_path,
        pin.as_ref(),
        preset,
    ));
    findings.extend(source::pnpm_check(&yaml_value, &yaml_path));
    findings.extend(lockfile::check(
        settings.require_lockfile,
        !lockfile_off && manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &lockfile_path_for(project_root, manager),
        Manager::Pnpm,
    ));
    findings.extend(audit_gate::pnpm_check(
        settings,
        &yaml_value,
        &yaml_path,
        pin.as_ref(),
    ));
    findings.extend(provenance::pnpm_checks(
        &yaml_value,
        &yaml_path,
        pin.as_ref(),
    ));
    findings.extend(min_age::pnpm_checks(
        settings,
        &yaml_value,
        &yaml_path,
        uses_allow_builds,
    ));
    findings.extend(lockfile::pnpm_trust_bypass(&yaml_value, &yaml_path));
    findings.extend(lockfile::pnpm_run_verify(
        &yaml_value,
        &yaml_path,
        pin.as_ref(),
    ));
    findings.extend(registry::check(
        registry.as_deref(),
        settings,
        "registry or registries.default must be set",
        &yaml_path,
        Manager::Pnpm,
        registry_url_fix(Manager::Pnpm, &yaml_path, "registry", settings),
    ));
    findings.extend(pm_pin::check(
        settings.require_pm_pin,
        PackageManagerPin::from_manifest(project_root).as_ref(),
        Manager::Pnpm,
        preset,
        project_root,
    ));
    findings
}

fn read_toml(path: &Path) -> toml::Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()))
}

fn read_uv_config(project_root: &Path) -> toml::Value {
    let mut merged = toml::map::Map::new();
    if let toml::Value::Table(pyproject) = read_toml(&project_root.join("pyproject.toml")) {
        if let Some(uv) = pyproject
            .get("tool")
            .and_then(|tool| tool.get("uv"))
            .and_then(toml::Value::as_table)
        {
            merged.extend(uv.clone());
        }
    }
    if let toml::Value::Table(uv_toml) = read_toml(&project_root.join("uv.toml")) {
        merged.extend(uv_toml);
    }
    toml::Value::Table(merged)
}

fn bun_registry_url(install: Option<&toml::Table>) -> Option<String> {
    let registry = install.and_then(|t| t.get("registry"))?;
    if let Some(url) = registry.as_str().map(str::trim).filter(|s| !s.is_empty()) {
        return Some(url.to_string());
    }
    registry
        .get("url")
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn uv_has_extra_indexes(cfg: &toml::Value) -> bool {
    let extra = cfg.get("extra-index-url");
    let extra_url = match extra {
        Some(toml::Value::String(s)) => !s.trim().is_empty(),
        Some(toml::Value::Array(items)) => !items.is_empty(),
        _ => false,
    };
    if extra_url {
        return true;
    }
    let Some(toml::Value::Array(index)) = cfg.get("index") else {
        return false;
    };
    index.len() > 1
        || index.iter().any(|entry| {
            entry
                .as_table()
                .is_some_and(|table| table.get("default") != Some(&toml::Value::Boolean(true)))
        })
}

fn json_bool(value: Option<&serde_json::Value>, fallback: bool) -> bool {
    value
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(fallback)
}

/// Composer's security-relevant manifest settings, read once.
///
/// Named fields rather than a tuple: these are eight adjacent booleans, and
/// positional destructuring let any two of them be swapped silently.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the eight booleans are the point; see the doc comment above"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerSecurity {
    pub allow_plugins_all: bool,
    pub disable_tls: bool,
    pub secure_http: bool,
    pub source_fallback: bool,
    pub policy_disabled: bool,
    pub advisories_block: bool,
    pub advisories_ignore: bool,
    pub malware_block: bool,
    pub http_repos: Vec<String>,
}

fn composer_security(manifest: &serde_json::Value) -> ComposerSecurity {
    let config = manifest.get("config").unwrap_or(&serde_json::Value::Null);
    let allow_plugins_all = config.get("allow-plugins") == Some(&serde_json::Value::Bool(true));
    let disable_tls = json_bool(config.get("disable-tls"), false);
    let secure_http = json_bool(config.get("secure-http"), true);
    let source_fallback = json_bool(config.get("source-fallback"), false);
    let policy = config.get("policy");
    let policy_disabled = policy == Some(&serde_json::Value::Bool(false));
    let advisories = policy
        .and_then(serde_json::Value::as_object)
        .and_then(|p| p.get("advisories"));
    let advisories_block = json_bool(
        advisories.and_then(|a| a.get("block")),
        json_bool(
            config.get("audit").and_then(|a| a.get("block-insecure")),
            true,
        ),
    );
    let advisories_ignore = advisories
        .and_then(|a| a.get("audit"))
        .and_then(serde_json::Value::as_str)
        == Some("ignore");
    let malware_block = policy
        .and_then(serde_json::Value::as_object)
        .and_then(|p| p.get("malware"))
        .is_none_or(|m| json_bool(m.get("block"), true));
    let mut http_repos = Vec::new();
    if let Some(repos) = manifest.get("repositories") {
        let entries: Vec<&serde_json::Value> = match repos {
            serde_json::Value::Array(items) => items.iter().collect(),
            serde_json::Value::Object(map) => map.values().collect(),
            _ => Vec::new(),
        };
        for entry in entries {
            if let Some(url) = entry.get("url").and_then(serde_json::Value::as_str) {
                if url.starts_with("http://") {
                    http_repos.push(url.to_string());
                }
            }
        }
    }
    ComposerSecurity {
        allow_plugins_all,
        disable_tls,
        secure_http,
        source_fallback,
        policy_disabled,
        advisories_block,
        advisories_ignore,
        malware_block,
        http_repos,
    }
}

#[must_use]
pub fn python_not_uv(project_root: &Path, manager: Manager) -> Finding {
    Finding {
        kind: FindingKind::NotUsingUv,
        code: "python.not-uv".into(),
        message: format!("{} project is not using uv", manager.name()),
        severity: Severity::High,
        path: project_root.to_string_lossy().into_owned(),
        fixable: false,
        manager: Some(manager),
        package: None,
        current_version: None,
        fix_version: None,
        fix: None,
    }
}

pub fn yarn_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let yarnrc_path = config_path_for(project_root, manager);
    let yarnrc = std::fs::read_to_string(&yarnrc_path)
        .map_or_else(|_| yaml::parse(""), |raw| yaml::parse(&raw));
    let pin = PackageManagerPin::from_manifest(project_root).filter(|p| p.name == "yarn");
    let preset = settings.preset;
    let registry = yaml::get(&yarnrc, "npmRegistryServer")
        .and_then(yaml::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let mut findings = Vec::new();
    findings.extend(scripts::yarn_check(
        settings,
        &yarnrc,
        &yarnrc_path,
        pin.as_ref(),
        preset,
    ));
    findings.extend(min_age::yarn_checks(
        settings,
        &yarnrc,
        &yarnrc_path,
        pin.as_ref(),
    ));
    findings.extend(integrity::yarn_checks(&yarnrc, &yarnrc_path));
    findings.extend(source::yarn_git_check(
        settings,
        &yarnrc,
        &yarnrc_path,
        pin.as_ref(),
    ));
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &lockfile_path_for(project_root, manager),
        Manager::Yarn,
    ));
    findings.extend(audit_gate::yarn_check(&yarnrc, &yarnrc_path));
    findings.extend(registry::check(
        registry.as_deref(),
        settings,
        "npmRegistryServer must be set",
        &yarnrc_path,
        Manager::Yarn,
        registry_url_fix(Manager::Yarn, &yarnrc_path, "npmRegistryServer", settings),
    ));
    findings.extend(pm_pin::check(
        settings.require_pm_pin,
        pin.as_ref(),
        Manager::Yarn,
        preset,
        project_root,
    ));
    findings
}

pub fn bun_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let bunfig_path = config_path_for(project_root, manager);
    let bunfig = read_toml(&bunfig_path);
    let install = bunfig.get("install").and_then(toml::Value::as_table);
    let registry = bun_registry_url(install);
    let lockfile_present = manager.lockfile_path.as_deref().is_some_and(Path::is_file)
        || project_root.join("bun.lock").is_file()
        || project_root.join("bun.lockb").is_file();

    let mut findings = Vec::new();
    findings.extend(scripts::bun_check(settings, &bunfig, &bunfig_path));
    findings.extend(lockfile::check(
        settings.require_lockfile,
        lockfile_present,
        &lockfile_path_for(project_root, manager),
        Manager::Bun,
    ));
    findings.extend(min_age::bun_checks(settings, install, &bunfig_path));
    findings.extend(registry::check(
        registry.as_deref(),
        settings,
        "install.registry must be set",
        &bunfig_path,
        Manager::Bun,
        registry_url_fix(Manager::Bun, &bunfig_path, "install.registry", settings),
    ));
    findings
}

pub fn uv_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
    clock: &dyn Clock,
) -> Vec<Finding> {
    let config_path = Manager::Uv
        .write_target(project_root)
        .map_or_else(|| project_root.join("pyproject.toml"), |(path, _)| path);
    let key_prefix = Manager::uv_key_prefix(&config_path);
    let cfg = read_uv_config(project_root);
    let pin = PackageManagerPin::from_manifest(project_root).filter(|p| p.name == "uv");
    let mut findings = Vec::new();
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &lockfile_path_for(project_root, manager),
        Manager::Uv,
    ));
    findings.extend(min_age::uv_checks(
        settings,
        &cfg,
        &config_path,
        key_prefix,
        clock,
    ));
    if settings.preset == crate::policy::Preset::Strict
        && uv_has_extra_indexes(&cfg)
        && cfg.get("index-strategy").and_then(toml::Value::as_str) != Some("first-index")
    {
        findings.extend(registry::check(
            None,
            settings,
            "extra indexes require index-strategy = \"first-index\"",
            &config_path,
            Manager::Uv,
            Some(fix_for(
                Manager::Uv,
                &config_path,
                vec![ConfigEdit::set(
                    format!("{key_prefix}index-strategy"),
                    "first-index",
                )],
            )),
        ));
    }
    findings.extend(audit_gate::uv_malware(
        &cfg,
        &config_path,
        pin.as_ref(),
        key_prefix,
    ));
    findings
}

fn cargo_config(
    project_root: &Path,
    manager: &DetectedManager,
) -> (std::path::PathBuf, toml::Value) {
    if let Some(path) = &manager.config_path {
        return (path.clone(), read_toml(path));
    }
    for rel in [".cargo/config.toml", ".cargo/config"] {
        let path = project_root.join(rel);
        if path.is_file() {
            return (path.clone(), read_toml(&path));
        }
    }
    let path = project_root.join(".cargo/config.toml");
    (path.clone(), read_toml(&path))
}

pub fn cargo_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let (config_path, cfg) = cargo_config(project_root, manager);
    let install = cfg.get("install").and_then(toml::Value::as_table);
    let mut findings = Vec::new();
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &lockfile_path_for(project_root, manager),
        Manager::Cargo,
    ));
    let write_path = Manager::Cargo
        .write_target(project_root)
        .map_or(config_path, |(path, _)| path);
    findings.extend(min_age::cargo_check(settings, install, &write_path));
    findings
}

pub fn composer_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let config_path = config_path_for(project_root, manager);
    let manifest = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
    let security = composer_security(&manifest);

    let mut findings = Vec::new();
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &lockfile_path_for(project_root, manager),
        Manager::Composer,
    ));
    findings.extend(scripts::composer_check(
        settings,
        security
            .allow_plugins_all
            .then_some(&serde_json::Value::Bool(true)),
        &config_path,
    ));
    if security.disable_tls || !security.secure_http {
        let mut edits = Vec::new();
        if security.disable_tls {
            edits.push(ConfigEdit::unset("config.disable-tls"));
        }
        edits.push(ConfigEdit::set("config.secure-http", true));
        findings.push(fixable_finding(
            "registry.unpinned",
            "composer must keep secure-http enabled and disable-tls off",
            Severity::High,
            &config_path,
            Manager::Composer,
            fix_for(Manager::Composer, &config_path, edits),
        ));
    }
    if let Some(url) = security.http_repos.first() {
        findings.push(advice_finding(
            "registry.unpinned",
            format!("composer repositories must use https ({url})"),
            pin_severity(settings.preset),
            &config_path,
            Manager::Composer,
        ));
    }
    findings.extend(audit_gate::composer_policy(&security, &config_path));
    findings.extend(source::composer_source_fallback(
        security.source_fallback,
        settings.preset,
        &config_path,
    ));
    findings
}

pub fn bundler_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let config_path = Manager::Bundler
        .write_target(project_root)
        .map_or_else(|| project_root.join(".bundle/config"), |(path, _)| path);
    let raw = std::fs::read_to_string(&config_path).unwrap_or_default();
    let config = bundle_config::parse(&raw);
    let cooldown = config.get("BUNDLE_COOLDOWN").and_then(|v| v.parse().ok());
    let mut findings = Vec::new();
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &lockfile_path_for(project_root, manager),
        Manager::Bundler,
    ));
    findings.extend(min_age::bundler_check(settings, cooldown, &config_path));
    findings
}

#[cfg(test)]
mod composer_security_tests {
    use super::*;

    fn read(json: &str) -> ComposerSecurity {
        composer_security(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn an_empty_manifest_uses_composers_safe_defaults() {
        let s = read("{}");
        assert!(!s.allow_plugins_all);
        assert!(!s.disable_tls);
        assert!(s.secure_http);
        assert!(!s.source_fallback);
        assert!(!s.policy_disabled);
        assert!(s.advisories_block);
        assert!(!s.advisories_ignore);
        assert!(s.malware_block);
        assert!(s.http_repos.is_empty());
    }

    #[test]
    fn each_flag_is_read_from_its_own_key() {
        let s = read(
            r#"{"config":{"allow-plugins":true,"disable-tls":true,
                 "secure-http":false,"source-fallback":true}}"#,
        );
        assert!(s.allow_plugins_all);
        assert!(s.disable_tls);
        assert!(!s.secure_http);
        assert!(s.source_fallback);
    }

    #[test]
    fn policy_false_disables_the_whole_policy() {
        assert!(read(r#"{"config":{"policy":false}}"#).policy_disabled);
        assert!(!read(r#"{"config":{"policy":{}}}"#).policy_disabled);
    }

    #[test]
    fn advisories_audit_ignore_is_detected() {
        let s = read(r#"{"config":{"policy":{"advisories":{"audit":"ignore"}}}}"#);
        assert!(s.advisories_ignore);
        assert!(
            !read(r#"{"config":{"policy":{"advisories":{"audit":"fail"}}}}"#).advisories_ignore
        );
    }

    #[test]
    fn advisories_block_falls_back_to_legacy_audit_block_insecure() {
        assert!(!read(r#"{"config":{"audit":{"block-insecure":false}}}"#).advisories_block);
        // The modern key wins over the legacy fallback.
        let s = read(
            r#"{"config":{"audit":{"block-insecure":false},
                 "policy":{"advisories":{"block":true}}}}"#,
        );
        assert!(s.advisories_block);
    }

    #[test]
    fn malware_block_defaults_true_but_can_be_turned_off() {
        assert!(read(r#"{"config":{"policy":{}}}"#).malware_block);
        assert!(!read(r#"{"config":{"policy":{"malware":{"block":false}}}}"#).malware_block);
    }

    #[test]
    fn plaintext_repositories_are_collected_from_arrays_and_objects() {
        let from_array = read(r#"{"repositories":[{"url":"http://a"},{"url":"https://b"}]}"#);
        assert_eq!(from_array.http_repos, vec!["http://a".to_string()]);
        let from_object = read(r#"{"repositories":{"one":{"url":"http://c"}}}"#);
        assert_eq!(from_object.http_repos, vec!["http://c".to_string()]);
    }
}
