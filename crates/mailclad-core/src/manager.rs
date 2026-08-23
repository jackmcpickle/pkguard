use serde::{Deserialize, Serialize};

/// The single registry of package-manager knowledge. Every capability is an
/// exhaustive `match`, so adding a manager without wiring a consumer is a
/// compile error (the TS version kept three hand-synced registries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Manager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Uv,
    Cargo,
    Composer,
    Poetry,
    Pip,
    Pipenv,
    Bundler,
}

/// Parsed `package.json#packageManager` pin, e.g. `pnpm@9.0.0`. This is the
/// single parser of that field — discovery, settings, and doctor all use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageManagerPin {
    pub name: String,
    pub major: i64,
}

impl PackageManagerPin {
    pub fn parse(field: &str) -> Option<Self> {
        let at = field.find('@')?;
        if at == 0 {
            return None;
        }
        let major: i64 = field[at + 1..].split('.').next()?.parse().ok()?;
        Some(Self {
            name: field[..at].to_string(),
            major,
        })
    }

    pub fn from_manifest(dir: &std::path::Path) -> Option<Self> {
        let raw = std::fs::read_to_string(dir.join("package.json")).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
        parsed
            .get("packageManager")
            .and_then(|v| v.as_str())
            .and_then(Self::parse)
    }

    pub fn manager(&self) -> Option<Manager> {
        Manager::from_name(&self.name)
    }
}

impl Manager {
    pub const ALL: [Manager; 11] = [
        Manager::Npm,
        Manager::Pnpm,
        Manager::Yarn,
        Manager::Bun,
        Manager::Uv,
        Manager::Cargo,
        Manager::Composer,
        Manager::Poetry,
        Manager::Pip,
        Manager::Pipenv,
        Manager::Bundler,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Manager::Npm => "npm",
            Manager::Pnpm => "pnpm",
            Manager::Yarn => "yarn",
            Manager::Bun => "bun",
            Manager::Uv => "uv",
            Manager::Cargo => "cargo",
            Manager::Composer => "composer",
            Manager::Poetry => "poetry",
            Manager::Pip => "pip",
            Manager::Pipenv => "pipenv",
            Manager::Bundler => "bundler",
        }
    }

    pub fn from_name(name: &str) -> Option<Manager> {
        Manager::ALL.into_iter().find(|m| m.name() == name)
    }

    /// poetry / pip / pipenv only ever produce a `python.not-uv` finding.
    pub fn is_legacy_python(self) -> bool {
        matches!(self, Manager::Poetry | Manager::Pip | Manager::Pipenv)
    }

    /// Binary checked at preflight; for bundler this is the audit tool itself.
    pub fn binary(self) -> Option<&'static str> {
        match self {
            Manager::Npm => Some("npm"),
            Manager::Pnpm => Some("pnpm"),
            Manager::Yarn => Some("yarn"),
            Manager::Bun => Some("bun"),
            Manager::Uv => Some("uv"),
            Manager::Cargo => Some("cargo"),
            Manager::Composer => Some("composer"),
            Manager::Bundler => Some("bundle-audit"),
            Manager::Poetry | Manager::Pip | Manager::Pipenv => None,
        }
    }

    pub fn audit_argv(self) -> Option<Vec<&'static str>> {
        match self {
            Manager::Npm => Some(vec!["npm", "audit", "--json"]),
            Manager::Pnpm => Some(vec!["pnpm", "audit", "--json"]),
            Manager::Yarn => Some(vec!["yarn", "npm", "audit", "--json"]),
            Manager::Bun => Some(vec!["bun", "audit", "--json"]),
            Manager::Uv => Some(vec!["uv", "audit", "--output-format", "json", "--frozen"]),
            Manager::Cargo => Some(vec!["cargo", "audit", "--json"]),
            Manager::Bundler => Some(vec!["bundle-audit", "check", "--format", "json"]),
            Manager::Composer => Some(vec!["composer", "audit", "--format", "json", "--locked"]),
            Manager::Poetry | Manager::Pip | Manager::Pipenv => None,
        }
    }

    pub fn lockfile_names(self) -> &'static [&'static str] {
        match self {
            Manager::Npm => &["package-lock.json"],
            Manager::Pnpm => &["pnpm-lock.yaml"],
            Manager::Yarn => &["yarn.lock"],
            Manager::Bun => &["bun.lock", "bun.lockb"],
            Manager::Uv => &["uv.lock"],
            Manager::Cargo => &["Cargo.lock"],
            Manager::Composer => &["composer.lock"],
            Manager::Bundler => &["Gemfile.lock"],
            Manager::Poetry | Manager::Pip | Manager::Pipenv => &[],
        }
    }

    pub fn config_names(self) -> &'static [&'static str] {
        match self {
            Manager::Npm => &[".npmrc"],
            Manager::Pnpm => &["pnpm-workspace.yaml"],
            Manager::Yarn => &[".yarnrc.yml"],
            Manager::Bun => &["bunfig.toml"],
            Manager::Uv => &["uv.toml", "pyproject.toml"],
            Manager::Cargo => &[".cargo/config.toml", ".cargo/config"],
            Manager::Composer => &["composer.json"],
            Manager::Bundler => &[".bundle/config"],
            Manager::Poetry | Manager::Pip | Manager::Pipenv => &[],
        }
    }

    pub fn write_config_name(self) -> Option<&'static str> {
        match self {
            Manager::Npm => Some(".npmrc"),
            Manager::Pnpm => Some("pnpm-workspace.yaml"),
            Manager::Yarn => Some(".yarnrc.yml"),
            Manager::Bun => Some("bunfig.toml"),
            Manager::Cargo => Some(".cargo/config.toml"),
            Manager::Composer => Some("composer.json"),
            Manager::Bundler => Some(".bundle/config"),
            // uv's write target depends on which config exists; see write_target
            Manager::Uv => None,
            Manager::Poetry | Manager::Pip | Manager::Pipenv => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manager_pin_parses_name_and_major() {
        let pin = PackageManagerPin::parse("pnpm@9.12.1").unwrap();
        assert_eq!(pin.name, "pnpm");
        assert_eq!(pin.major, 9);
        assert_eq!(pin.manager(), Some(Manager::Pnpm));
        assert_eq!(PackageManagerPin::parse("@9.0.0"), None);
        assert_eq!(PackageManagerPin::parse("pnpm"), None);
        assert_eq!(PackageManagerPin::parse("pnpm@x"), None);
    }

    #[test]
    fn all_managers_roundtrip_by_name() {
        for m in Manager::ALL {
            assert_eq!(Manager::from_name(m.name()), Some(m));
        }
        assert_eq!(Manager::from_name("maven"), None);
    }

    #[test]
    fn npm_capabilities() {
        assert_eq!(Manager::Npm.binary(), Some("npm"));
        assert_eq!(
            Manager::Npm.audit_argv(),
            Some(vec!["npm", "audit", "--json"])
        );
        assert_eq!(Manager::Npm.lockfile_names(), &["package-lock.json"]);
        assert_eq!(Manager::Npm.write_config_name(), Some(".npmrc"));
    }

    #[test]
    fn bundler_audits_via_bundle_audit_binary() {
        assert_eq!(Manager::Bundler.binary(), Some("bundle-audit"));
    }

    #[test]
    fn bun_has_two_lockfile_names() {
        assert_eq!(Manager::Bun.lockfile_names(), &["bun.lock", "bun.lockb"]);
    }

    #[test]
    fn legacy_python_managers_have_no_audit() {
        for m in [Manager::Poetry, Manager::Pip, Manager::Pipenv] {
            assert_eq!(m.binary(), None);
            assert_eq!(m.audit_argv(), None);
            assert!(m.is_legacy_python());
        }
        assert!(!Manager::Uv.is_legacy_python());
    }

    #[test]
    fn audit_argvs_match_ts_contract() {
        let expect = [
            (Manager::Pnpm, vec!["pnpm", "audit", "--json"]),
            (Manager::Yarn, vec!["yarn", "npm", "audit", "--json"]),
            (Manager::Bun, vec!["bun", "audit", "--json"]),
            (
                Manager::Uv,
                vec!["uv", "audit", "--output-format", "json", "--frozen"],
            ),
            (Manager::Cargo, vec!["cargo", "audit", "--json"]),
            (
                Manager::Bundler,
                vec!["bundle-audit", "check", "--format", "json"],
            ),
            (
                Manager::Composer,
                vec!["composer", "audit", "--format", "json", "--locked"],
            ),
        ];
        for (m, argv) in expect {
            assert_eq!(m.audit_argv(), Some(argv));
        }
    }
}
