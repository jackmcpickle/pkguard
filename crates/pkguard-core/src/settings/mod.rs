pub mod checks;

use crate::config::ResolvedSettings;
use crate::discover::DetectedManager;
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
    match manager.manager {
        Manager::Npm => checks::npm_settings(project_root, manager, settings),
        // Remaining managers arrive with the M2 check-family port.
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse_config, resolve_settings, ConfigFile};
    use crate::discover::Role;
    use crate::findings::Severity;
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
}
