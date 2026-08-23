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

use crate::config::ResolvedSettings;
use crate::discover::{DetectedManager, Project};
use crate::findings::{Finding, FindingKind, Severity};
use crate::format::{npmrc, yaml};
use crate::manager::{Manager, PackageManagerPin};
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

fn role_path(project_root: &Path, manager: &DetectedManager) -> std::path::PathBuf {
    manager
        .lockfile_path
        .clone()
        .unwrap_or_else(|| project_root.to_path_buf())
}

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
    })
}

/// Cross-manager findings from the TS `auditSettings` entry: leftover yarn
/// next to pnpm still counts as two node managers.
pub fn multiple_pm_findings(project: &Project) -> Vec<Finding> {
    [
        multiple_pm_finding(project, "pm.multiple-node", "node", &NODE_MANAGERS),
        multiple_pm_finding(project, "pm.multiple-python", "python", &PYTHON_MANAGERS),
    ]
    .into_iter()
    .flatten()
    .collect()
}

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
    let yaml_path = manager
        .config_path
        .clone()
        .unwrap_or_else(|| project_root.join("pnpm-workspace.yaml"));
    let yaml_value = std::fs::read_to_string(&yaml_path)
        .map(|raw| yaml::parse(&raw))
        .unwrap_or_else(|_| yaml::parse(""));
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
        &manager
            .lockfile_path
            .clone()
            .unwrap_or_else(|| project_root.join("pnpm-lock.yaml")),
        "pnpm-lock.yaml is required",
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
        preset,
        &yaml_path,
        Manager::Pnpm,
    ));
    findings.extend(pm_pin::check(
        settings.require_pm_pin,
        manifest_json(project_root)
            .as_ref()
            .and_then(|m| m.get("packageManager"))
            .and_then(|v| v.as_str())
            .is_some_and(|v| v.starts_with("pnpm@")),
        "package.json packageManager must start with pnpm@",
        preset,
        &project_root.join("package.json"),
        Manager::Pnpm,
    ));
    findings
}

fn read_toml(path: &Path) -> toml::Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(toml::Value::Table(toml::map::Map::new()))
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

fn parse_bundle_config(raw: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        out.insert(
            key.trim().to_string(),
            value.trim().trim_matches('"').to_string(),
        );
    }
    out
}

fn json_bool(value: Option<&serde_json::Value>, fallback: bool) -> bool {
    value
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(fallback)
}

fn composer_security(
    manifest: &serde_json::Value,
) -> (bool, bool, bool, bool, bool, bool, bool, bool, Vec<String>) {
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
        .map(|m| json_bool(m.get("block"), true))
        .unwrap_or(true);
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
    (
        allow_plugins_all,
        disable_tls,
        secure_http,
        source_fallback,
        policy_disabled,
        advisories_block,
        advisories_ignore,
        malware_block,
        http_repos,
    )
}

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
    }
}

pub fn yarn_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let yarnrc_path = manager
        .config_path
        .clone()
        .unwrap_or_else(|| project_root.join(".yarnrc.yml"));
    let yarnrc = std::fs::read_to_string(&yarnrc_path)
        .map(|raw| yaml::parse(&raw))
        .unwrap_or_else(|_| yaml::parse(""));
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
        &manager
            .lockfile_path
            .clone()
            .unwrap_or_else(|| project_root.join("yarn.lock")),
        "yarn.lock is required",
        Manager::Yarn,
    ));
    findings.extend(audit_gate::yarn_check(&yarnrc, &yarnrc_path));
    findings.extend(registry::check(
        registry.as_deref(),
        settings,
        "npmRegistryServer must be set",
        preset,
        &yarnrc_path,
        Manager::Yarn,
    ));
    findings.extend(pm_pin::check(
        settings.require_pm_pin,
        pin.as_ref().is_some_and(|p| p.major >= 2),
        "package.json packageManager must be yarn@ major >= 2",
        preset,
        &project_root.join("package.json"),
        Manager::Yarn,
    ));
    findings
}

pub fn bun_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let bunfig_path = manager
        .config_path
        .clone()
        .unwrap_or_else(|| project_root.join("bunfig.toml"));
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
        &manager
            .lockfile_path
            .clone()
            .unwrap_or_else(|| project_root.join("bun.lock")),
        "bun.lock or bun.lockb is required",
        Manager::Bun,
    ));
    findings.extend(min_age::bun_checks(settings, install, &bunfig_path));
    findings.extend(registry::check(
        registry.as_deref(),
        settings,
        "install.registry must be set",
        settings.preset,
        &bunfig_path,
        Manager::Bun,
    ));
    findings
}

pub fn uv_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let config_path = manager
        .config_path
        .clone()
        .unwrap_or_else(|| project_root.join("pyproject.toml"));
    let cfg = read_uv_config(project_root);
    let pin = PackageManagerPin::from_manifest(project_root).filter(|p| p.name == "uv");
    let mut findings = Vec::new();
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &manager
            .lockfile_path
            .clone()
            .unwrap_or_else(|| project_root.join("uv.lock")),
        "uv.lock is required",
        Manager::Uv,
    ));
    findings.extend(min_age::uv_checks(settings, &cfg, &config_path));
    if settings.preset == crate::policy::Preset::Strict
        && uv_has_extra_indexes(&cfg)
        && cfg.get("index-strategy").and_then(toml::Value::as_str) != Some("first-index")
    {
        findings.extend(registry::check(
            None,
            settings,
            "extra indexes require index-strategy = \"first-index\"",
            settings.preset,
            &config_path,
            Manager::Uv,
        ));
    }
    findings.extend(audit_gate::uv_malware(&cfg, &config_path, pin.as_ref()));
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
        &manager
            .lockfile_path
            .clone()
            .unwrap_or_else(|| project_root.join("Cargo.lock")),
        "Cargo.lock is required",
        Manager::Cargo,
    ));
    findings.extend(min_age::cargo_check(settings, install, &config_path));
    findings
}

pub fn composer_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    let config_path = manager
        .config_path
        .clone()
        .unwrap_or_else(|| project_root.join("composer.json"));
    let manifest = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
    let (
        allow_plugins_all,
        disable_tls,
        secure_http,
        source_fallback,
        policy_disabled,
        advisories_block,
        advisories_ignore,
        malware_block,
        http_repos,
    ) = composer_security(&manifest);

    let mut findings = Vec::new();
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &manager
            .lockfile_path
            .clone()
            .unwrap_or_else(|| project_root.join("composer.lock")),
        "composer.lock is required",
        Manager::Composer,
    ));
    findings.extend(scripts::composer_check(
        settings,
        allow_plugins_all.then_some(&serde_json::Value::Bool(true)),
        &config_path,
    ));
    if disable_tls || !secure_http {
        findings.push(setting_finding(
            "registry.unpinned",
            "composer must keep secure-http enabled and disable-tls off",
            Severity::High,
            &config_path,
            Manager::Composer,
        ));
    }
    if let Some(url) = http_repos.first() {
        findings.push(advice_finding(
            "registry.unpinned",
            format!("composer repositories must use https ({url})"),
            pin_severity(settings.preset),
            &config_path,
            Manager::Composer,
        ));
    }
    findings.extend(audit_gate::composer_policy(
        policy_disabled,
        advisories_ignore,
        advisories_block,
        malware_block,
        &config_path,
    ));
    findings.extend(source::composer_source_fallback(
        source_fallback,
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
    let config_path = manager
        .config_path
        .clone()
        .unwrap_or_else(|| project_root.join(".bundle/config"));
    let raw = std::fs::read_to_string(&config_path).unwrap_or_default();
    let config = parse_bundle_config(&raw);
    let cooldown = config.get("BUNDLE_COOLDOWN").and_then(|v| v.parse().ok());
    let mut findings = Vec::new();
    findings.extend(lockfile::check(
        settings.require_lockfile,
        manager.lockfile_path.as_deref().is_some_and(Path::is_file),
        &manager
            .lockfile_path
            .clone()
            .unwrap_or_else(|| project_root.join("Gemfile.lock")),
        "Gemfile.lock is required",
        Manager::Bundler,
    ));
    findings.extend(min_age::bundler_check(settings, cooldown, &config_path));
    findings
}
