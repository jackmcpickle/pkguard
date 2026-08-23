use crate::findings::Severity;
use crate::policy::Preset;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresetDefaults {
    pub audit_level: Severity,
    pub ignore_scripts: bool,
    pub min_release_age_days: u32,
    pub require_lockfile: bool,
    pub require_pm_pin: bool,
}

impl PresetDefaults {
    pub fn for_preset(preset: Preset) -> Self {
        match preset {
            Preset::Relaxed => PresetDefaults {
                audit_level: Severity::Critical,
                ignore_scripts: false,
                min_release_age_days: 0,
                require_lockfile: true,
                require_pm_pin: false,
            },
            Preset::Standard => PresetDefaults {
                audit_level: Severity::High,
                ignore_scripts: true,
                min_release_age_days: 1,
                require_lockfile: true,
                require_pm_pin: true,
            },
            Preset::Strict => PresetDefaults {
                audit_level: Severity::Moderate,
                ignore_scripts: true,
                min_release_age_days: 14,
                require_lockfile: true,
                require_pm_pin: true,
            },
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOverrides {
    pub ignore_scripts: Option<bool>,
    pub min_release_age_days: Option<u32>,
    pub require_lockfile: Option<bool>,
    pub require_pm_pin: Option<bool>,
    pub audit_level: Option<Severity>,
    pub registry: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgenticConfig {
    pub enabled: Option<bool>,
    pub apply: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub preset: Option<Preset>,
    pub managers: Option<Vec<String>>,
    pub jobs: Option<usize>,
    pub policy: Option<PolicyOverrides>,
    pub agentic: Option<AgenticConfig>,
    #[serde(default)]
    pub manager: BTreeMap<String, PolicyOverrides>,
}

pub fn parse_config(text: &str) -> Result<ConfigFile, toml::de::Error> {
    toml::from_str(text)
}

fn merge_policy(base: Option<&PolicyOverrides>, over: Option<&PolicyOverrides>) -> Option<PolicyOverrides> {
    match (base, over) {
        (None, None) => None,
        (Some(b), None) => Some(b.clone()),
        (None, Some(o)) => Some(o.clone()),
        (Some(b), Some(o)) => Some(PolicyOverrides {
            ignore_scripts: o.ignore_scripts.or(b.ignore_scripts),
            min_release_age_days: o.min_release_age_days.or(b.min_release_age_days),
            require_lockfile: o.require_lockfile.or(b.require_lockfile),
            require_pm_pin: o.require_pm_pin.or(b.require_pm_pin),
            audit_level: o.audit_level.or(b.audit_level),
            registry: o.registry.clone().or_else(|| b.registry.clone()),
        }),
    }
}

/// Field-wise layering, later layers win: user < scan-root < per-repo.
pub fn layer_configs<'a>(layers: impl IntoIterator<Item = &'a ConfigFile>) -> ConfigFile {
    let mut out = ConfigFile::default();
    for layer in layers {
        out.preset = layer.preset.or(out.preset);
        out.managers = layer.managers.clone().or(out.managers);
        out.jobs = layer.jobs.or(out.jobs);
        out.policy = merge_policy(out.policy.as_ref(), layer.policy.as_ref());
        out.agentic = match (out.agentic.take(), layer.agentic.as_ref()) {
            (base, None) => base,
            (None, Some(a)) => Some(a.clone()),
            (Some(b), Some(a)) => Some(AgenticConfig {
                enabled: a.enabled.or(b.enabled),
                apply: a.apply.or(b.apply),
            }),
        };
        for (name, table) in &layer.manager {
            let merged = merge_policy(out.manager.get(name), Some(table)).unwrap_or_default();
            out.manager.insert(name.clone(), merged);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSettings {
    pub preset: Preset,
    pub audit_level: Severity,
    pub ignore_scripts: bool,
    pub min_release_age_days: u32,
    pub require_lockfile: bool,
    pub require_pm_pin: bool,
    pub registry: Option<String>,
    pub agentic: bool,
    pub apply_agentic: bool,
}

/// Preset defaults < [policy] overrides < [manager.<name>] table.
pub fn resolve_settings(cfg: &ConfigFile, manager: &str) -> ResolvedSettings {
    let preset = cfg.preset.unwrap_or(Preset::Standard);
    let defaults = PresetDefaults::for_preset(preset);
    let policy = merge_policy(cfg.policy.as_ref(), cfg.manager.get(manager));
    let policy = policy.unwrap_or_default();
    let agentic = cfg.agentic.clone().unwrap_or_default();
    ResolvedSettings {
        preset,
        audit_level: policy.audit_level.unwrap_or(defaults.audit_level),
        ignore_scripts: policy.ignore_scripts.unwrap_or(defaults.ignore_scripts),
        min_release_age_days: policy
            .min_release_age_days
            .unwrap_or(defaults.min_release_age_days),
        require_lockfile: policy.require_lockfile.unwrap_or(defaults.require_lockfile),
        require_pm_pin: policy.require_pm_pin.unwrap_or(defaults.require_pm_pin),
        registry: policy.registry,
        agentic: agentic.enabled.unwrap_or(true),
        apply_agentic: agentic.apply.unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use crate::policy::Preset;

    #[test]
    fn preset_defaults_match_ts_contract() {
        let relaxed = PresetDefaults::for_preset(Preset::Relaxed);
        assert_eq!(relaxed.audit_level, Severity::Critical);
        assert!(!relaxed.ignore_scripts);
        assert_eq!(relaxed.min_release_age_days, 0);
        assert!(relaxed.require_lockfile);
        assert!(!relaxed.require_pm_pin);

        let standard = PresetDefaults::for_preset(Preset::Standard);
        assert_eq!(standard.audit_level, Severity::High);
        assert!(standard.ignore_scripts);
        assert_eq!(standard.min_release_age_days, 1);
        assert!(standard.require_lockfile);
        assert!(standard.require_pm_pin);

        let strict = PresetDefaults::for_preset(Preset::Strict);
        assert_eq!(strict.audit_level, Severity::Moderate);
        assert!(strict.ignore_scripts);
        assert_eq!(strict.min_release_age_days, 14);
        assert!(strict.require_lockfile);
        assert!(strict.require_pm_pin);
    }

    #[test]
    fn parses_full_config_file() {
        let cfg: ConfigFile = parse_config(
            r#"
preset = "strict"
managers = ["npm", "cargo"]
jobs = 8

[policy]
ignore_scripts = false
min_release_age_days = 3
audit_level = "critical"
registry = "https://registry.example.com"

[agentic]
enabled = true
apply = false

[manager.npm]
audit_level = "high"
"#,
        )
        .unwrap();
        assert_eq!(cfg.preset, Some(Preset::Strict));
        assert_eq!(cfg.managers.as_deref(), Some(&["npm".into(), "cargo".into()][..]));
        assert_eq!(cfg.jobs, Some(8));
        let policy = cfg.policy.as_ref().unwrap();
        assert_eq!(policy.ignore_scripts, Some(false));
        assert_eq!(policy.min_release_age_days, Some(3));
        assert_eq!(policy.audit_level, Some(Severity::Critical));
        assert_eq!(
            policy.registry.as_deref(),
            Some("https://registry.example.com")
        );
        assert_eq!(cfg.agentic.as_ref().unwrap().enabled, Some(true));
        assert_eq!(
            cfg.manager.get("npm").unwrap().audit_level,
            Some(Severity::High)
        );
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(parse_config("presett = \"strict\"").is_err());
        assert!(parse_config("[policy]\nignoreScripts = true").is_err());
    }

    #[test]
    fn later_layers_override_earlier_ones() {
        let user: ConfigFile = parse_config("preset = \"relaxed\"\n[policy]\nmin_release_age_days = 5").unwrap();
        let scan_root: ConfigFile = parse_config("preset = \"standard\"").unwrap();
        let per_repo: ConfigFile = parse_config("[policy]\nignore_scripts = false").unwrap();
        let layered = layer_configs([&user, &scan_root, &per_repo]);
        // per-repo left preset alone: scan-root's standard wins over user's relaxed
        assert_eq!(layered.preset, Some(Preset::Standard));
        // user's policy override survives because no later layer touched it
        assert_eq!(layered.policy.as_ref().unwrap().min_release_age_days, Some(5));
        // per-repo's ignore_scripts wins
        assert_eq!(layered.policy.as_ref().unwrap().ignore_scripts, Some(false));
    }

    #[test]
    fn resolve_applies_preset_then_policy_then_manager_table() {
        let cfg: ConfigFile = parse_config(
            r#"
preset = "standard"

[policy]
min_release_age_days = 7

[manager.npm]
audit_level = "critical"
"#,
        )
        .unwrap();
        let npm = resolve_settings(&cfg, "npm");
        // manager table beats preset default (standard => high)
        assert_eq!(npm.audit_level, Severity::Critical);
        // policy override beats preset default (standard => 1)
        assert_eq!(npm.min_release_age_days, 7);
        // untouched values fall through to preset defaults
        assert!(npm.ignore_scripts);
        assert!(npm.require_pm_pin);

        let cargo = resolve_settings(&cfg, "cargo");
        // no manager table for cargo: policy + preset defaults only
        assert_eq!(cargo.audit_level, Severity::High);
        assert_eq!(cargo.min_release_age_days, 7);
    }
}
