pub mod checks;

use crate::config::ResolvedSettings;
use crate::discover::{DetectedManager, Role};
use crate::findings::Finding;
use crate::manager::Manager;
use std::path::Path;

/// Pure-file settings audit for one detected manager. Reads config files under
/// the project root; never spawns anything.
pub fn audit_manager_settings(
    project_root: &Path,
    manager: &DetectedManager,
    settings: &ResolvedSettings,
) -> Vec<Finding> {
    match manager.role {
        Role::Leftover => vec![checks::leftover_finding(project_root, manager)],
        Role::Unsupported => vec![checks::unsupported_finding(project_root, manager)],
        Role::Primary => match manager.manager {
            Manager::Npm => checks::npm_settings(project_root, manager, settings),
            Manager::Pnpm => checks::pnpm_settings(project_root, manager, settings),
            Manager::Yarn => checks::yarn_settings(project_root, manager, settings),
            Manager::Bun => checks::bun_settings(project_root, manager, settings),
            Manager::Uv => checks::uv_settings(project_root, manager, settings),
            Manager::Cargo => checks::cargo_settings(project_root, manager, settings),
            Manager::Composer => checks::composer_settings(project_root, manager, settings),
            Manager::Bundler => checks::bundler_settings(project_root, manager, settings),
            Manager::Poetry | Manager::Pip | Manager::Pipenv => {
                vec![checks::python_not_uv(project_root, manager.manager)]
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse_config, resolve_settings, ConfigFile};
    use crate::discover::Role;
    use crate::findings::Severity;
    use crate::fix::{ConfigEdit, ConfigFormat, ConfigValue, SettingsFix};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join("package.json"), "{}").unwrap();
        fs::write(root.join("package-lock.json"), "lock").unwrap();
        Fixture { _tmp: tmp, root }
    }

    fn npm_manager(root: &Path, with_lockfile: bool) -> DetectedManager {
        DetectedManager {
            manager: Manager::Npm,
            role: Role::Primary,
            lockfile_path: with_lockfile.then(|| root.join("package-lock.json")),
            config_path: root.join(".npmrc").exists().then(|| root.join(".npmrc")),
        }
    }

    fn settings_for(config_toml: &str) -> ResolvedSettings {
        let cfg: ConfigFile = parse_config(config_toml).unwrap();
        resolve_settings(&cfg, "npm")
    }

    fn codes(findings: &[Finding]) -> Vec<&str> {
        let mut codes: Vec<&str> = findings.iter().map(|f| f.code.as_str()).collect();
        codes.sort_unstable();
        codes
    }

    fn audit(fx: &Fixture, config_toml: &str) -> Vec<Finding> {
        let manager = npm_manager(&fx.root, fx.root.join("package-lock.json").exists());
        audit_manager_settings(&fx.root, &manager, &settings_for(config_toml))
    }

    #[test]
    fn bare_npm_repo_under_standard_preset_flags_the_baseline_set() {
        let fx = fixture();
        let findings = audit(&fx, "preset = \"standard\"");
        assert_eq!(
            codes(&findings),
            vec![
                "audit.disabled",
                "min-age.disabled",
                "pm.unpinned",
                "registry.unpinned",
                "scripts.pin-missing",
                "scripts.unrestricted",
            ]
        );
        // scripts.unrestricted is a hard setting; registry.unpinned is
        // pin-severity (info under standard); pin-missing default-reliance advice
        let by_code = |c: &str| findings.iter().find(|f| f.code == c).unwrap();
        assert_eq!(by_code("scripts.unrestricted").severity, Severity::High);
        assert_eq!(by_code("registry.unpinned").severity, Severity::Info);
        assert_eq!(by_code("scripts.pin-missing").severity, Severity::Info);
        assert_eq!(by_code("audit.disabled").severity, Severity::High);
    }

    #[test]
    fn compliant_npm_repo_is_clean() {
        let fx = fixture();
        fs::write(
            fx.root.join(".npmrc"),
            "ignore-scripts=true\nallow-scripts-pin=true\naudit=true\naudit-level=high\nmin-release-age=1\nregistry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        fs::write(
            fx.root.join("package.json"),
            r#"{"packageManager": "npm@11.0.0"}"#,
        )
        .unwrap();
        assert_eq!(audit(&fx, "preset = \"standard\""), Vec::<Finding>::new());
    }

    #[test]
    fn relaxed_preset_skips_scripts_and_min_age() {
        let fx = fixture();
        let findings = audit(&fx, "preset = \"relaxed\"");
        // relaxed: ignore_scripts=false, min_age=0, require_pm_pin=false
        assert_eq!(
            codes(&findings),
            vec!["audit.disabled", "registry.unpinned"]
        );
    }

    #[test]
    fn missing_lockfile_is_flagged_high() {
        let fx = fixture();
        fs::remove_file(fx.root.join("package-lock.json")).unwrap();
        let findings = audit(&fx, "preset = \"standard\"");
        let lockfile = findings
            .iter()
            .find(|f| f.code == "lockfile.missing")
            .unwrap();
        assert_eq!(lockfile.severity, Severity::High);
    }

    #[test]
    fn dangerous_script_bypass_is_flagged() {
        let fx = fixture();
        fs::write(
            fx.root.join(".npmrc"),
            "ignore-scripts=true\ndangerously-allow-all-scripts=true\n",
        )
        .unwrap();
        let findings = audit(&fx, "preset = \"standard\"");
        assert!(codes(&findings).contains(&"scripts.bypass-enabled"));
    }

    #[test]
    fn registry_mismatch_when_policy_pins_a_registry() {
        let fx = fixture();
        fs::write(
            fx.root.join(".npmrc"),
            "registry=https://evil.example.com\n",
        )
        .unwrap();
        let findings = audit(
            &fx,
            "preset = \"strict\"\n[policy]\nregistry = \"https://registry.corp.dev\"",
        );
        let mismatch = findings
            .iter()
            .find(|f| f.code == "registry.mismatch")
            .unwrap();
        // pin severity under strict is high
        assert_eq!(mismatch.severity, Severity::High);
    }

    #[test]
    fn allow_scripts_interplay() {
        let fx = fixture();
        fs::write(
            fx.root.join("package.json"),
            r#"{"packageManager": "npm@11.0.0", "allowScripts": {"esbuild": true}}"#,
        )
        .unwrap();
        // allowScripts without strict-allow-scripts: unrestricted + advisory note
        let findings = audit(&fx, "preset = \"standard\"");
        let found = codes(&findings);
        assert!(found.contains(&"scripts.unrestricted"));
        assert!(found.contains(&"scripts.allowlist-advisory"));

        // with strict-allow-scripts=true it satisfies enforcement
        fs::write(fx.root.join(".npmrc"), "strict-allow-scripts=true\n").unwrap();
        let findings = audit(&fx, "preset = \"standard\"");
        assert!(!codes(&findings).contains(&"scripts.unrestricted"));

        // ignore-scripts=true masks the allowlist: advice finding
        fs::write(fx.root.join(".npmrc"), "ignore-scripts=true\n").unwrap();
        let findings = audit(&fx, "preset = \"standard\"");
        assert!(codes(&findings).contains(&"scripts.allowlist-masked"));
    }

    #[test]
    fn trailing_slash_registries_compare_equal() {
        let fx = fixture();
        fs::write(
            fx.root.join(".npmrc"),
            "registry=https://registry.npmjs.org\n",
        )
        .unwrap();
        let findings = audit(&fx, "preset = \"standard\"");
        assert!(!codes(&findings).contains(&"registry.unpinned"));
        assert!(!codes(&findings).contains(&"registry.mismatch"));
    }

    fn pnpm_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join("package.json"), "{}").unwrap();
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        Fixture { _tmp: tmp, root }
    }

    fn pnpm_manager(root: &Path, with_lockfile: bool) -> DetectedManager {
        DetectedManager {
            manager: Manager::Pnpm,
            role: Role::Primary,
            lockfile_path: with_lockfile.then(|| root.join("pnpm-lock.yaml")),
            config_path: root
                .join("pnpm-workspace.yaml")
                .exists()
                .then(|| root.join("pnpm-workspace.yaml")),
        }
    }

    fn audit_pnpm(fx: &Fixture, config_toml: &str) -> Vec<Finding> {
        let cfg: ConfigFile = parse_config(config_toml).unwrap();
        let manager = pnpm_manager(&fx.root, fx.root.join("pnpm-lock.yaml").exists());
        audit_manager_settings(&fx.root, &manager, &resolve_settings(&cfg, "pnpm"))
    }

    #[test]
    fn bare_pnpm_repo_under_standard_preset_flags_the_baseline_set() {
        let fx = pnpm_fixture();
        let findings = audit_pnpm(&fx, "preset = \"standard\"");
        assert_eq!(
            codes(&findings),
            vec![
                "audit.disabled",
                "lockfile.run-verify",
                "pm.unpinned",
                "provenance.ignore-after",
                "provenance.no-downgrade",
                "registry.unpinned",
                "scripts.unrestricted",
            ]
        );
        let by_code = |c: &str| findings.iter().find(|f| f.code == c).unwrap();
        assert_eq!(by_code("scripts.unrestricted").severity, Severity::Info);
        assert_eq!(by_code("audit.disabled").severity, Severity::High);
        assert_eq!(by_code("registry.unpinned").severity, Severity::Info);
        assert_eq!(by_code("lockfile.run-verify").severity, Severity::High);
    }

    #[test]
    fn compliant_pnpm_repo_is_clean() {
        let fx = pnpm_fixture();
        fs::write(
            fx.root.join("package.json"),
            r#"{"packageManager": "pnpm@11.7.0"}"#,
        )
        .unwrap();
        fs::write(
            fx.root.join("pnpm-workspace.yaml"),
            "allowBuilds:\n  esbuild: false\nminimumReleaseAge: 1440\nminimumReleaseAgeStrict: true\nminimumReleaseAgeIgnoreMissingTime: false\nblockExoticSubdeps: true\nstrictDepBuilds: true\naudit:\n  level: high\ntrustPolicyIgnoreAfter: 129600\ntrustPolicy: no-downgrade\nverifyDepsBeforeRun: error\nregistry: https://registry.npmjs.org/\n",
        )
        .unwrap();
        assert_eq!(
            audit_pnpm(&fx, "preset = \"standard\""),
            Vec::<Finding>::new()
        );
    }

    const PNPM_SITE_SUPPLY_CHAIN: &str = "\
allowBuilds:
  esbuild: false
minimumReleaseAge: 1440
minimumReleaseAgeStrict: true
minimumReleaseAgeIgnoreMissingTime: false
blockExoticSubdeps: true
strictDepBuilds: true
audit:
  level: high
trustPolicy: no-downgrade
trustPolicyIgnoreAfter: 129600
verifyDepsBeforeRun: error
registry: https://registry.npmjs.org/
";

    fn write_pnpm_workspace(fx: &Fixture, yaml: &str) {
        fs::write(fx.root.join("pnpm-workspace.yaml"), yaml).unwrap();
    }

    fn pin_pnpm(fx: &Fixture) {
        fs::write(
            fx.root.join("package.json"),
            r#"{"packageManager": "pnpm@11.22.0"}"#,
        )
        .unwrap();
    }

    #[test]
    fn pnpm_weak_gates_are_findings() {
        let fx = pnpm_fixture();
        pin_pnpm(&fx);
        write_pnpm_workspace(
            &fx,
            "allowBuilds:\n  esbuild: false\nminimumReleaseAge: 1440\nminimumReleaseAgeStrict: false\nblockExoticSubdeps: false\nstrictDepBuilds: false\naudit:\n  level: high\ntrustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\nverifyDepsBeforeRun: error\nregistry: https://registry.npmjs.org/\n",
        );
        assert_eq!(
            codes(&audit_pnpm(&fx, "preset = \"standard\"")),
            vec![
                "min-age.non-strict",
                "scripts.non-strict",
                "source.non-registry",
            ]
        );
    }

    #[test]
    fn pnpm_ignore_missing_time_is_required_only_under_strict() {
        let fx = pnpm_fixture();
        pin_pnpm(&fx);
        write_pnpm_workspace(
            &fx,
            "allowBuilds:\n  esbuild: false\nminimumReleaseAge: 20160\nminimumReleaseAgeStrict: true\nblockExoticSubdeps: true\nstrictDepBuilds: true\naudit:\n  level: moderate\ntrustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\nverifyDepsBeforeRun: error\nregistry: https://registry.npmjs.org/\n",
        );
        assert!(!codes(&audit_pnpm(&fx, "preset = \"standard\"")).contains(&"min-age.missing-time"));
        assert!(codes(&audit_pnpm(&fx, "preset = \"strict\"")).contains(&"min-age.missing-time"));

        write_pnpm_workspace(
            &fx,
            "allowBuilds:\n  esbuild: false\nminimumReleaseAge: 20160\nminimumReleaseAgeStrict: true\nminimumReleaseAgeIgnoreMissingTime: false\nblockExoticSubdeps: true\nstrictDepBuilds: true\naudit:\n  level: moderate\ntrustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\nverifyDepsBeforeRun: error\nregistry: https://registry.npmjs.org/\n",
        );
        assert!(!codes(&audit_pnpm(&fx, "preset = \"strict\"")).contains(&"min-age.missing-time"));
    }

    #[test]
    fn pnpm_site_style_config_is_clean_under_standard() {
        let fx = pnpm_fixture();
        pin_pnpm(&fx);
        write_pnpm_workspace(&fx, PNPM_SITE_SUPPLY_CHAIN);
        assert_eq!(
            audit_pnpm(&fx, "preset = \"standard\""),
            Vec::<Finding>::new()
        );
        let strict_findings = audit_pnpm(&fx, "preset = \"strict\"");
        let strict = codes(&strict_findings);
        assert!(strict.contains(&"min-age.disabled"));
        assert!(!strict.contains(&"min-age.non-strict"));
        assert!(!strict.contains(&"min-age.missing-time"));
        assert!(!strict.contains(&"scripts.non-strict"));
        assert!(!strict.contains(&"source.non-registry"));
    }

    #[test]
    fn committed_site_pnpm_workspace_yaml_is_clean_under_standard() {
        let yaml = fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../site/pnpm-workspace.yaml"),
        )
        .unwrap();
        let fx = pnpm_fixture();
        pin_pnpm(&fx);
        write_pnpm_workspace(&fx, &yaml);
        assert_eq!(
            audit_pnpm(&fx, "preset = \"standard\""),
            Vec::<Finding>::new()
        );
    }

    #[test]
    fn leftover_npm_lockfile_beside_pnpm_is_high_and_not_fixable() {
        let fx = pnpm_fixture();
        fs::write(fx.root.join("package-lock.json"), "leftover").unwrap();
        let leftover = DetectedManager {
            manager: Manager::Npm,
            role: Role::Leftover,
            lockfile_path: Some(fx.root.join("package-lock.json")),
            config_path: None,
        };
        let findings =
            audit_manager_settings(&fx.root, &leftover, &settings_for("preset = \"standard\""));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "lockfile.leftover");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(!findings[0].fixable);
    }

    #[test]
    fn pnpm_dangerously_allow_all_builds_is_unrestricted() {
        let fx = pnpm_fixture();
        fs::write(
            fx.root.join("pnpm-workspace.yaml"),
            "dangerouslyAllowAllBuilds: true\n",
        )
        .unwrap();
        let findings = audit_pnpm(&fx, "preset = \"standard\"");
        let unrestricted = findings
            .iter()
            .find(|f| f.code == "scripts.unrestricted")
            .unwrap();
        assert_eq!(unrestricted.severity, Severity::High);
        assert!(unrestricted.message.contains("dangerouslyAllowAllBuilds"));
    }

    #[test]
    fn relaxed_preset_skips_pnpm_scripts_and_min_age() {
        let fx = pnpm_fixture();
        let findings = audit_pnpm(&fx, "preset = \"relaxed\"");
        let found = codes(&findings);
        assert!(!found.contains(&"scripts.unrestricted"));
        assert!(!found.contains(&"min-age.disabled"));
        assert!(found.contains(&"audit.disabled"));
        assert!(found.contains(&"registry.unpinned"));
    }

    fn audit_named(fx: &Fixture, manager: DetectedManager, name: &str) -> Vec<Finding> {
        let cfg: ConfigFile = parse_config("preset = \"standard\"").unwrap();
        audit_manager_settings(&fx.root, &manager, &resolve_settings(&cfg, name))
    }

    fn yarn_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join("package.json"), "{}").unwrap();
        fs::write(root.join("yarn.lock"), "").unwrap();
        Fixture { _tmp: tmp, root }
    }

    fn yarn_manager(root: &Path) -> DetectedManager {
        DetectedManager {
            manager: Manager::Yarn,
            role: Role::Primary,
            lockfile_path: Some(root.join("yarn.lock")),
            config_path: root
                .join(".yarnrc.yml")
                .exists()
                .then(|| root.join(".yarnrc.yml")),
        }
    }

    #[test]
    fn bare_yarn_repo_under_standard_preset_flags_the_baseline_set() {
        let fx = yarn_fixture();
        let findings = audit_named(&fx, yarn_manager(&fx.root), "yarn");
        assert_eq!(
            codes(&findings),
            vec![
                "pm.unpinned",
                "registry.unpinned",
                "scripts.unrestricted",
                "source.git-unrestricted",
            ]
        );
        let by_code = |c: &str| findings.iter().find(|f| f.code == c).unwrap();
        assert_eq!(by_code("scripts.unrestricted").severity, Severity::Info);
        assert_eq!(by_code("source.git-unrestricted").severity, Severity::High);
        assert!(!codes(&findings).contains(&"min-age.disabled"));
    }

    #[test]
    fn compliant_yarn_repo_is_clean() {
        let fx = yarn_fixture();
        fs::write(
            fx.root.join("package.json"),
            r#"{"packageManager": "yarn@4.14.0"}"#,
        )
        .unwrap();
        fs::write(
            fx.root.join(".yarnrc.yml"),
            "enableScripts: false\napprovedGitRepositories: []\nnpmRegistryServer: https://registry.npmjs.org/\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, yarn_manager(&fx.root), "yarn"),
            Vec::<Finding>::new()
        );
    }

    fn bun_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join("package.json"), "{}").unwrap();
        fs::write(root.join("bun.lock"), "").unwrap();
        Fixture { _tmp: tmp, root }
    }

    fn bun_manager(root: &Path) -> DetectedManager {
        DetectedManager {
            manager: Manager::Bun,
            role: Role::Primary,
            lockfile_path: Some(root.join("bun.lock")),
            config_path: root
                .join("bunfig.toml")
                .exists()
                .then(|| root.join("bunfig.toml")),
        }
    }

    #[test]
    fn bare_bun_repo_under_standard_preset_flags_the_baseline_set() {
        let fx = bun_fixture();
        let findings = audit_named(&fx, bun_manager(&fx.root), "bun");
        assert_eq!(
            codes(&findings),
            vec![
                "min-age.disabled",
                "registry.unpinned",
                "scripts.unrestricted",
            ]
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.code == "scripts.unrestricted")
                .unwrap()
                .severity,
            Severity::High
        );
    }

    #[test]
    fn compliant_bun_repo_is_clean() {
        let fx = bun_fixture();
        fs::write(
            fx.root.join("bunfig.toml"),
            "[install]\nignoreScripts = true\nminimumReleaseAge = 86400\nregistry = \"https://registry.npmjs.org/\"\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, bun_manager(&fx.root), "bun"),
            Vec::<Finding>::new()
        );
    }

    fn uv_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join("pyproject.toml"), "[tool.uv]\n").unwrap();
        fs::write(root.join("uv.lock"), "").unwrap();
        Fixture { _tmp: tmp, root }
    }

    fn uv_manager(root: &Path) -> DetectedManager {
        DetectedManager {
            manager: Manager::Uv,
            role: Role::Primary,
            lockfile_path: Some(root.join("uv.lock")),
            config_path: Some(root.join("pyproject.toml")),
        }
    }

    #[test]
    fn bare_uv_repo_under_standard_preset_flags_the_baseline_set() {
        let fx = uv_fixture();
        let findings = audit_named(&fx, uv_manager(&fx.root), "uv");
        assert_eq!(
            codes(&findings),
            vec!["audit.malware-disabled", "min-age.disabled"]
        );
    }

    #[test]
    fn compliant_uv_repo_is_clean() {
        let fx = uv_fixture();
        fs::write(
            fx.root.join("pyproject.toml"),
            "[tool.uv]\nexclude-newer = 1\n\n[tool.uv.audit]\nmalware-check = true\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, uv_manager(&fx.root), "uv"),
            Vec::<Finding>::new()
        );
    }

    #[test]
    fn poetry_primary_is_python_not_uv() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join("pyproject.toml"), "[tool.poetry]\nname = \"x\"\n").unwrap();
        let fx = Fixture { _tmp: tmp, root };
        let manager = DetectedManager {
            manager: Manager::Poetry,
            role: Role::Primary,
            lockfile_path: None,
            config_path: Some(fx.root.join("pyproject.toml")),
        };
        let findings = audit_named(&fx, manager, "poetry");
        assert_eq!(codes(&findings), vec!["python.not-uv"]);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(!findings[0].fixable);
    }

    fn cargo_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), "").unwrap();
        Fixture { _tmp: tmp, root }
    }

    fn cargo_manager(root: &Path) -> DetectedManager {
        DetectedManager {
            manager: Manager::Cargo,
            role: Role::Primary,
            lockfile_path: Some(root.join("Cargo.lock")),
            config_path: root
                .join(".cargo/config.toml")
                .exists()
                .then(|| root.join(".cargo/config.toml")),
        }
    }

    #[test]
    fn bare_cargo_repo_under_standard_preset_flags_min_age() {
        let fx = cargo_fixture();
        let findings = audit_named(&fx, cargo_manager(&fx.root), "cargo");
        assert_eq!(codes(&findings), vec!["min-age.disabled"]);
    }

    #[test]
    fn compliant_cargo_repo_is_clean() {
        let fx = cargo_fixture();
        fs::create_dir_all(fx.root.join(".cargo")).unwrap();
        fs::write(
            fx.root.join(".cargo/config.toml"),
            "[install]\nminimum-release-age = 1440\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, cargo_manager(&fx.root), "cargo"),
            Vec::<Finding>::new()
        );
    }

    fn composer_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join("composer.json"), "{}").unwrap();
        fs::write(root.join("composer.lock"), "{}").unwrap();
        Fixture { _tmp: tmp, root }
    }

    fn composer_manager(root: &Path) -> DetectedManager {
        DetectedManager {
            manager: Manager::Composer,
            role: Role::Primary,
            lockfile_path: Some(root.join("composer.lock")),
            config_path: Some(root.join("composer.json")),
        }
    }

    #[test]
    fn bare_composer_repo_uses_secure_defaults() {
        let fx = composer_fixture();
        assert_eq!(
            audit_named(&fx, composer_manager(&fx.root), "composer"),
            Vec::<Finding>::new()
        );
    }

    #[test]
    fn composer_allow_plugins_true_is_unrestricted() {
        let fx = composer_fixture();
        fs::write(
            fx.root.join("composer.json"),
            r#"{"config":{"allow-plugins":true,"disable-tls":true,"policy":false,"source-fallback":true}}"#,
        )
        .unwrap();
        let findings = audit_named(&fx, composer_manager(&fx.root), "composer");
        assert_eq!(
            codes(&findings),
            vec![
                "audit.disabled",
                "registry.unpinned",
                "scripts.unrestricted",
                "source-fallback.enabled",
            ]
        );
    }

    fn bundler_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        fs::write(root.join("Gemfile"), "source 'https://rubygems.org'\n").unwrap();
        fs::write(root.join("Gemfile.lock"), "").unwrap();
        Fixture { _tmp: tmp, root }
    }

    fn bundler_manager(root: &Path) -> DetectedManager {
        DetectedManager {
            manager: Manager::Bundler,
            role: Role::Primary,
            lockfile_path: Some(root.join("Gemfile.lock")),
            config_path: root
                .join(".bundle/config")
                .exists()
                .then(|| root.join(".bundle/config")),
        }
    }

    #[test]
    fn bare_bundler_repo_under_standard_preset_flags_min_age() {
        let fx = bundler_fixture();
        let findings = audit_named(&fx, bundler_manager(&fx.root), "bundler");
        assert_eq!(codes(&findings), vec!["min-age.disabled"]);
    }

    #[test]
    fn compliant_bundler_repo_is_clean() {
        let fx = bundler_fixture();
        fs::create_dir_all(fx.root.join(".bundle")).unwrap();
        fs::write(fx.root.join(".bundle/config"), "BUNDLE_COOLDOWN: \"1\"\n").unwrap();
        assert_eq!(
            audit_named(&fx, bundler_manager(&fx.root), "bundler"),
            Vec::<Finding>::new()
        );
    }

    fn audit_preset(
        fx: &Fixture,
        manager: DetectedManager,
        name: &str,
        toml: &str,
    ) -> Vec<Finding> {
        let cfg: ConfigFile = parse_config(toml).unwrap();
        audit_manager_settings(&fx.root, &manager, &resolve_settings(&cfg, name))
    }

    #[test]
    fn yarn_version_defaults_match_ts() {
        let fx = yarn_fixture();
        fs::write(
            fx.root.join(".yarnrc.yml"),
            "npmRegistryServer: https://registry.npmjs.org/\nnpmMinimalAgeGate: 1440\napprovedGitRepositories: []\n",
        )
        .unwrap();
        fs::write(
            fx.root.join("package.json"),
            r#"{"packageManager":"yarn@4.13.0"}"#,
        )
        .unwrap();
        let old = audit_named(&fx, yarn_manager(&fx.root), "yarn");
        assert_eq!(
            old.iter()
                .find(|f| f.code == "scripts.unrestricted")
                .unwrap()
                .severity,
            Severity::High
        );

        fs::write(
            fx.root.join("package.json"),
            r#"{"packageManager":"yarn@4.15.0"}"#,
        )
        .unwrap();
        let current = audit_named(&fx, yarn_manager(&fx.root), "yarn");
        assert_eq!(
            current
                .iter()
                .find(|f| f.code == "scripts.unrestricted")
                .unwrap()
                .severity,
            Severity::Info
        );
        assert!(!codes(&current).contains(&"min-age.disabled"));
        assert!(!codes(&audit_preset(
            &fx,
            yarn_manager(&fx.root),
            "yarn",
            "preset = \"strict\""
        ))
        .contains(&"source.git-unrestricted"));
    }

    #[test]
    fn yarn_duration_and_git_allowlist_match_ts() {
        let fx = yarn_fixture();
        fs::write(
            fx.root.join("package.json"),
            r#"{"packageManager":"yarn@4.15.0"}"#,
        )
        .unwrap();
        fs::write(
            fx.root.join(".yarnrc.yml"),
            "enableScripts: false\nnpmMinimalAgeGate: 7d\napprovedGitRepositories:\n  - https://github.com/myorg/*\nnpmRegistryServer: https://registry.npmjs.org/\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, yarn_manager(&fx.root), "yarn"),
            Vec::<Finding>::new()
        );

        fs::write(
            fx.root.join(".yarnrc.yml"),
            "enableScripts: false\nnpmMinimalAgeGate: 1440\napprovedGitRepositories:\n  - \"*\"\nnpmRegistryServer: https://registry.npmjs.org/\n",
        )
        .unwrap();
        assert!(codes(&audit_named(&fx, yarn_manager(&fx.root), "yarn"))
            .contains(&"source.git-unrestricted"));
    }

    #[test]
    fn bun_minimum_release_age_is_seconds() {
        let fx = bun_fixture();
        fs::write(
            fx.root.join("bunfig.toml"),
            "trustedDependencies = [\"foo\"]\n\n[install]\nregistry = \"https://registry.npmjs.org/\"\nminimumReleaseAge = 86400\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, bun_manager(&fx.root), "bun"),
            Vec::<Finding>::new()
        );
        fs::write(
            fx.root.join("bunfig.toml"),
            "trustedDependencies = [\"foo\"]\n\n[install]\nregistry = \"https://registry.npmjs.org/\"\nminimumReleaseAge = 43200\n",
        )
        .unwrap();
        assert!(
            codes(&audit_named(&fx, bun_manager(&fx.root), "bun")).contains(&"min-age.disabled")
        );
    }

    #[test]
    fn cargo_duration_strings_and_legacy_config_match_ts() {
        let fx = cargo_fixture();
        fs::create_dir_all(fx.root.join(".cargo")).unwrap();
        fs::write(
            fx.root.join(".cargo/config.toml"),
            "[install]\nminimum-release-age = \"1d\"\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, cargo_manager(&fx.root), "cargo"),
            Vec::<Finding>::new()
        );
        fs::write(
            fx.root.join(".cargo/config.toml"),
            "[install]\nminimum-release-age = \"1 week\"\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, cargo_manager(&fx.root), "cargo"),
            Vec::<Finding>::new()
        );
        fs::write(
            fx.root.join(".cargo/config.toml"),
            "[install]\nminimum-release-age = \"12h\"\n",
        )
        .unwrap();
        assert!(codes(&audit_named(&fx, cargo_manager(&fx.root), "cargo"))
            .contains(&"min-age.disabled"));
        fs::write(
            fx.root.join(".cargo/config.toml"),
            "[install]\nminimum-release-age = 10080\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, cargo_manager(&fx.root), "cargo"),
            Vec::<Finding>::new()
        );

        fs::remove_file(fx.root.join(".cargo/config.toml")).unwrap();
        fs::write(
            fx.root.join(".cargo/config"),
            "[install]\nminimum-release-age = \"1d\"\n",
        )
        .unwrap();
        let no_path = DetectedManager {
            config_path: None,
            ..cargo_manager(&fx.root)
        };
        assert_eq!(audit_named(&fx, no_path, "cargo"), Vec::<Finding>::new());
    }

    #[test]
    fn uv_duration_strings_and_uv_toml_match_ts() {
        let fx = uv_fixture();
        fs::write(
            fx.root.join("pyproject.toml"),
            "[tool.uv]\nexclude-newer = \"1 days\"\n\n[tool.uv.audit]\nmalware-check = true\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, uv_manager(&fx.root), "uv"),
            Vec::<Finding>::new()
        );
        fs::write(
            fx.root.join("pyproject.toml"),
            "[tool.uv]\nexclude-newer = \"12 hours\"\n\n[tool.uv.audit]\nmalware-check = true\n",
        )
        .unwrap();
        assert!(codes(&audit_named(&fx, uv_manager(&fx.root), "uv")).contains(&"min-age.disabled"));

        fs::write(fx.root.join("pyproject.toml"), "[project]\nname = \"x\"\n").unwrap();
        fs::write(
            fx.root.join("uv.toml"),
            "exclude-newer = \"1 days\"\n\n[audit]\nmalware-check = true\n",
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, uv_manager(&fx.root), "uv"),
            Vec::<Finding>::new()
        );
    }

    #[test]
    fn composer_allowlist_and_http_repo_match_ts() {
        let fx = composer_fixture();
        fs::write(
            fx.root.join("composer.json"),
            r#"{"config":{"allow-plugins":{"php-http/discovery":true}}}"#,
        )
        .unwrap();
        assert_eq!(
            audit_named(&fx, composer_manager(&fx.root), "composer"),
            Vec::<Finding>::new()
        );
        fs::write(
            fx.root.join("composer.json"),
            r#"{"repositories":[{"type":"composer","url":"http://packagist.example"}]}"#,
        )
        .unwrap();
        let findings = audit_named(&fx, composer_manager(&fx.root), "composer");
        let http = findings
            .iter()
            .find(|f| f.code == "registry.unpinned")
            .unwrap();
        assert_eq!(http.severity, Severity::Info);
        assert!(!http.fixable);
        let strict = audit_preset(
            &fx,
            composer_manager(&fx.root),
            "composer",
            "preset = \"strict\"",
        );
        assert_eq!(
            strict
                .iter()
                .find(|f| f.code == "registry.unpinned")
                .unwrap()
                .severity,
            Severity::High
        );
    }

    #[test]
    fn bundler_unquoted_cooldown_is_read() {
        let fx = bundler_fixture();
        fs::create_dir_all(fx.root.join(".bundle")).unwrap();
        fs::write(fx.root.join(".bundle/config"), "---\nBUNDLE_COOLDOWN: 7\n").unwrap();
        assert_eq!(
            audit_named(&fx, bundler_manager(&fx.root), "bundler"),
            Vec::<Finding>::new()
        );
    }

    #[test]
    fn leftover_yarn_beside_pnpm_is_multiple_node() {
        let project = crate::discover::Project {
            root: PathBuf::from("/p"),
            git_root: None,
            managers: vec![
                DetectedManager {
                    manager: Manager::Pnpm,
                    role: Role::Primary,
                    lockfile_path: Some(PathBuf::from("/p/pnpm-lock.yaml")),
                    config_path: None,
                },
                DetectedManager {
                    manager: Manager::Yarn,
                    role: Role::Leftover,
                    lockfile_path: Some(PathBuf::from("/p/yarn.lock")),
                    config_path: None,
                },
            ],
        };
        let findings = checks::multiple_pm_findings(&project);
        assert_eq!(codes(&findings), vec!["pm.multiple-node"]);
        assert!(!findings[0].fixable);
    }

    #[test]
    fn npm_and_uv_together_are_not_multiple_pm() {
        let project = crate::discover::Project {
            root: PathBuf::from("/p"),
            git_root: None,
            managers: vec![
                DetectedManager {
                    manager: Manager::Npm,
                    role: Role::Primary,
                    lockfile_path: None,
                    config_path: None,
                },
                DetectedManager {
                    manager: Manager::Uv,
                    role: Role::Primary,
                    lockfile_path: None,
                    config_path: None,
                },
            ],
        };
        assert_eq!(
            checks::multiple_pm_findings(&project),
            Vec::<Finding>::new()
        );
    }

    fn assert_fix_consistency(findings: &[Finding]) {
        for finding in findings {
            assert_eq!(
                finding.fixable,
                finding.fix.is_some(),
                "{} drifted: fixable={} fix={:?}",
                finding.code,
                finding.fixable,
                finding.fix
            );
        }
    }

    fn collect_settings_findings() -> Vec<Finding> {
        let mut all = Vec::new();

        let npm = fixture();
        all.extend(audit(&npm, "preset = \"standard\""));
        fs::write(
            npm.root.join(".npmrc"),
            "ignore-scripts=true\ndangerously-allow-all-scripts=true\nallow-git=all\nallow-scripts-pin=false\n",
        )
        .unwrap();
        all.extend(audit(&npm, "preset = \"standard\""));
        fs::write(
            npm.root.join("package.json"),
            r#"{"packageManager":"npm@11.0.0","allowScripts":{"esbuild":true}}"#,
        )
        .unwrap();
        fs::write(npm.root.join(".npmrc"), "ignore-scripts=true\n").unwrap();
        all.extend(audit(&npm, "preset = \"standard\""));
        fs::remove_file(npm.root.join("package-lock.json")).unwrap();
        all.extend(audit(&npm, "preset = \"standard\""));
        fs::write(
            npm.root.join(".npmrc"),
            "registry=https://evil.example.com\n",
        )
        .unwrap();
        all.extend(audit(
            &npm,
            "preset = \"strict\"\n[policy]\nregistry = \"https://registry.corp.dev\"",
        ));

        let pnpm = pnpm_fixture();
        all.extend(audit_pnpm(&pnpm, "preset = \"standard\""));
        write_pnpm_workspace(
            &pnpm,
            "dangerouslyAllowAllBuilds: true\nonlyBuiltDependencies:\n  - esbuild\nminimumReleaseAgeExclude:\n  - \"*\"\ntrustLockfile: true\n",
        );
        all.extend(audit_pnpm(&pnpm, "preset = \"standard\""));
        pin_pnpm(&pnpm);
        write_pnpm_workspace(
            &pnpm,
            "allowBuilds:\n  esbuild: false\nminimumReleaseAge: 1440\nminimumReleaseAgeStrict: false\nblockExoticSubdeps: false\nstrictDepBuilds: false\naudit:\n  level: high\ntrustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\nverifyDepsBeforeRun: error\nregistry: https://registry.npmjs.org/\n",
        );
        all.extend(audit_pnpm(&pnpm, "preset = \"standard\""));
        all.extend(audit_pnpm(&pnpm, "preset = \"strict\""));

        let leftover = DetectedManager {
            manager: Manager::Npm,
            role: Role::Leftover,
            lockfile_path: Some(pnpm.root.join("package-lock.json")),
            config_path: None,
        };
        fs::write(pnpm.root.join("package-lock.json"), "leftover").unwrap();
        all.extend(audit_manager_settings(
            &pnpm.root,
            &leftover,
            &settings_for("preset = \"standard\""),
        ));

        let yarn = yarn_fixture();
        all.extend(audit_named(&yarn, yarn_manager(&yarn.root), "yarn"));
        fs::write(
            yarn.root.join(".yarnrc.yml"),
            "enableScripts: true\naudit: false\nnpmAudit: false\nchecksumBehavior: update\nenableStrictSsl: false\nenableHardenedMode: false\nnpmPreapprovedPackages:\n  - \"*\"\n",
        )
        .unwrap();
        all.extend(audit_named(&yarn, yarn_manager(&yarn.root), "yarn"));

        let bun = bun_fixture();
        all.extend(audit_named(&bun, bun_manager(&bun.root), "bun"));

        let uv = uv_fixture();
        all.extend(audit_named(&uv, uv_manager(&uv.root), "uv"));

        let cargo = cargo_fixture();
        all.extend(audit_named(&cargo, cargo_manager(&cargo.root), "cargo"));

        let composer = composer_fixture();
        fs::write(
            composer.root.join("composer.json"),
            r#"{"config":{"allow-plugins":true,"disable-tls":true,"policy":false,"source-fallback":true}}"#,
        )
        .unwrap();
        all.extend(audit_named(
            &composer,
            composer_manager(&composer.root),
            "composer",
        ));

        let bundler = bundler_fixture();
        all.extend(audit_named(
            &bundler,
            bundler_manager(&bundler.root),
            "bundler",
        ));

        let poetry = {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            fs::write(root.join("pyproject.toml"), "[tool.poetry]\nname = \"x\"\n").unwrap();
            Fixture { _tmp: tmp, root }
        };
        all.extend(audit_named(
            &poetry,
            DetectedManager {
                manager: Manager::Poetry,
                role: Role::Primary,
                lockfile_path: None,
                config_path: Some(poetry.root.join("pyproject.toml")),
            },
            "poetry",
        ));

        all
    }

    #[test]
    fn fixable_flag_matches_presence_of_a_fix_for_every_emitted_code() {
        let findings = collect_settings_findings();
        assert!(
            !findings.is_empty(),
            "fixture sweep produced no findings to check"
        );
        assert_fix_consistency(&findings);
    }

    fn assert_fixes_target(findings: &[Finding], root: &std::path::Path, manager: Manager) {
        // Ask the production mapping rather than restating it: a test that
        // keeps its own copy can only catch the checks drifting from the copy.
        let (expected, format) = manager
            .write_target(root)
            .unwrap_or_else(|| panic!("{manager:?} has no write target"));
        for finding in findings.iter().filter(|f| f.fix.is_some()) {
            let fix = finding.fix.as_ref().unwrap();
            assert_eq!(
                fix.file,
                expected,
                "{} targeted {} instead of {}",
                finding.code,
                fix.file.display(),
                expected.display()
            );
            assert_eq!(fix.format, format, "{} used {:?}", finding.code, fix.format);
        }
    }

    fn assert_manager_fixes(label: &str, fx: &Fixture, manager: DetectedManager) {
        let findings = audit_named(fx, manager, label);
        assert!(
            findings.iter().any(|f| f.fix.is_some()),
            "{label} produced no fixable findings"
        );
        assert_fixes_target(&findings, &fx.root, Manager::from_name(label).unwrap());
        assert_fix_consistency(&findings);
    }

    #[test]
    fn each_manager_fix_targets_its_write_file_and_format() {
        let npm = fixture();
        assert_manager_fixes("npm", &npm, npm_manager(&npm.root, true));

        let pnpm = pnpm_fixture();
        assert_manager_fixes("pnpm", &pnpm, pnpm_manager(&pnpm.root, true));

        let yarn = yarn_fixture();
        assert_manager_fixes("yarn", &yarn, yarn_manager(&yarn.root));

        let bun = bun_fixture();
        assert_manager_fixes("bun", &bun, bun_manager(&bun.root));

        let uv = uv_fixture();
        assert_manager_fixes("uv", &uv, uv_manager(&uv.root));

        let cargo = cargo_fixture();
        assert_manager_fixes("cargo", &cargo, cargo_manager(&cargo.root));

        let composer = composer_fixture();
        fs::write(
            composer.root.join("composer.json"),
            r#"{"config":{"allow-plugins":true,"disable-tls":true,"policy":false}}"#,
        )
        .unwrap();
        assert_manager_fixes("composer", &composer, composer_manager(&composer.root));

        let bundler = bundler_fixture();
        assert_manager_fixes("bundler", &bundler, bundler_manager(&bundler.root));
    }

    #[test]
    fn npm_scripts_unrestricted_sets_ignore_scripts() {
        let fx = fixture();
        let finding = audit(&fx, "preset = \"standard\"")
            .into_iter()
            .find(|f| f.code == "scripts.unrestricted")
            .unwrap();
        assert_eq!(
            finding.fix,
            Some(SettingsFix::new(
                fx.root.join(".npmrc"),
                ConfigFormat::Npmrc,
                vec![ConfigEdit::set("ignore-scripts", true)],
            ))
        );
    }

    #[test]
    fn pnpm_scripts_unrestricted_includes_legacy_build_unsets() {
        let fx = pnpm_fixture();
        write_pnpm_workspace(
            &fx,
            "dangerouslyAllowAllBuilds: true\nonlyBuiltDependencies:\n  - esbuild\n",
        );
        let finding = audit_pnpm(&fx, "preset = \"standard\"")
            .into_iter()
            .find(|f| f.code == "scripts.unrestricted")
            .unwrap();
        let fix = finding.fix.expect("scripts.unrestricted must be fixable");
        assert_eq!(fix.file, fx.root.join("pnpm-workspace.yaml"));
        assert_eq!(fix.format, ConfigFormat::Yaml);
        assert_eq!(
            fix.edits,
            vec![
                ConfigEdit::set("dangerouslyAllowAllBuilds", false),
                ConfigEdit::unset("onlyBuiltDependencies"),
                ConfigEdit::set(
                    "allowBuilds",
                    ConfigValue::Table(BTreeMap::from([(
                        "esbuild".into(),
                        ConfigValue::Bool(true)
                    )]))
                ),
            ]
        );
    }

    #[test]
    fn uv_write_target_follows_uv_toml_when_present() {
        let fx = uv_fixture();
        fs::write(fx.root.join("uv.toml"), "").unwrap();
        let findings = audit_named(&fx, uv_manager(&fx.root), "uv");
        let min_age = findings
            .iter()
            .find(|f| f.code == "min-age.disabled")
            .unwrap();
        let fix = min_age
            .fix
            .as_ref()
            .expect("min-age.disabled must be fixable");
        assert_eq!(fix.file, fx.root.join("uv.toml"));
        assert_eq!(fix.format, ConfigFormat::Toml);
        assert!(
            fix.edits.iter().any(|edit| edit.key() == "exclude-newer"),
            "uv.toml keys are unprefixed: {:?}",
            fix.edits
        );

        let py = uv_fixture();
        let findings = audit_named(&py, uv_manager(&py.root), "uv");
        let min_age = findings
            .iter()
            .find(|f| f.code == "min-age.disabled")
            .unwrap();
        let fix = min_age
            .fix
            .as_ref()
            .expect("min-age.disabled must be fixable");
        assert_eq!(fix.file, py.root.join("pyproject.toml"));
        assert!(
            fix.edits
                .iter()
                .any(|edit| edit.key() == "tool.uv.exclude-newer"),
            "pyproject.toml keys use tool.uv. prefix: {:?}",
            fix.edits
        );
    }

    #[test]
    fn listed_unfixable_codes_carry_no_fix_even_when_the_manager_can_write() {
        const UNFIXABLE: &[&str] = &[
            "pm.missing-binary",
            "pm.unsupported",
            "pm.multiple-node",
            "pm.multiple-python",
            "python.not-uv",
            "lockfile.missing",
            "lockfile.leftover",
            "overrides.present",
            "overrides.legacy-location",
            "scripts.allowlist-advisory",
            "scripts.allowlist-masked",
            "min-age.exclude-all",
            "registry.mismatch",
            "layout.pnp",
            "layout.shamefully-hoist",
            "cache.path-committed",
            "advisory.unknown",
            "agentic.cache-disabled",
        ];
        let findings = collect_settings_findings();
        let seen: Vec<&str> = findings
            .iter()
            .map(|f| f.code.as_str())
            .filter(|code| UNFIXABLE.contains(code))
            .collect();
        assert!(
            seen.contains(&"lockfile.missing"),
            "sweep must emit lockfile.missing"
        );
        assert!(
            seen.contains(&"registry.mismatch"),
            "sweep must emit registry.mismatch"
        );
        assert!(
            seen.contains(&"lockfile.leftover"),
            "sweep must emit lockfile.leftover"
        );
        assert!(
            seen.contains(&"python.not-uv"),
            "sweep must emit python.not-uv"
        );
        assert!(
            seen.contains(&"scripts.allowlist-masked"),
            "sweep must emit scripts.allowlist-masked"
        );
        assert!(
            seen.contains(&"min-age.exclude-all"),
            "sweep must emit min-age.exclude-all"
        );
        for finding in findings
            .iter()
            .filter(|f| UNFIXABLE.contains(&f.code.as_str()))
        {
            assert!(
                finding.fix.is_none(),
                "{} must stay unfixable, got {:?}",
                finding.code,
                finding.fix
            );
            assert!(!finding.fixable, "{} must stay unfixable", finding.code);
        }
    }

    #[test]
    fn registry_unpinned_without_a_configured_registry_has_no_fix() {
        let fx = fixture();
        let finding = audit(&fx, "preset = \"standard\"")
            .into_iter()
            .find(|f| f.code == "registry.unpinned")
            .unwrap();
        assert!(finding.fix.is_none());
        assert!(!finding.fixable);
    }

    #[test]
    fn registry_unpinned_with_a_configured_registry_writes_that_url() {
        let fx = fixture();
        let finding = audit(
            &fx,
            "preset = \"standard\"\n[policy]\nregistry = \"https://registry.corp.dev/\"",
        )
        .into_iter()
        .find(|f| f.code == "registry.unpinned")
        .unwrap();
        assert_eq!(
            finding.fix,
            Some(SettingsFix::new(
                fx.root.join(".npmrc"),
                ConfigFormat::Npmrc,
                vec![ConfigEdit::set("registry", "https://registry.corp.dev/")],
            ))
        );
    }
}
