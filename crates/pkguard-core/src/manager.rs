use crate::fix::ConfigFormat;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
    pub minor: i64,
    pub patch: i64,
}

fn int_prefix(part: &str) -> Option<i64> {
    let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

impl PackageManagerPin {
    pub fn parse(field: &str) -> Option<Self> {
        let at = field.find('@')?;
        if at == 0 {
            return None;
        }
        let mut parts = field[at + 1..].split('.');
        let major = int_prefix(parts.next()?)?;
        Some(Self {
            name: field[..at].to_string(),
            major,
            minor: parts.next().and_then(int_prefix).unwrap_or(0),
            patch: parts.next().and_then(int_prefix).unwrap_or(0),
        })
    }

    /// True when this pin is at least `major.minor`.
    #[must_use]
    pub const fn at_least(&self, major: i64, minor: i64) -> bool {
        self.major > major || (self.major == major && self.minor >= minor)
    }

    /// Unpinned (or a pin for a different manager) is treated as a current
    /// release — `pm.unpinned` already covers the missing pin itself.
    #[must_use]
    pub fn at_least_or_unknown(pin: Option<&Self>, major: i64, minor: i64) -> bool {
        pin.is_none_or(|p| p.at_least(major, minor))
    }

    #[must_use]
    pub const fn at_least_patch(&self, major: i64, minor: i64, patch: i64) -> bool {
        if self.major != major {
            return self.major > major;
        }
        if self.minor != minor {
            return self.minor > minor;
        }
        self.patch >= patch
    }

    #[must_use]
    pub fn at_least_patch_or_unknown(
        pin: Option<&Self>,
        major: i64,
        minor: i64,
        patch: i64,
    ) -> bool {
        pin.is_none_or(|p| p.at_least_patch(major, minor, patch))
    }

    pub fn from_manifest(dir: &std::path::Path) -> Option<Self> {
        let raw = std::fs::read_to_string(dir.join("package.json")).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
        parsed
            .get("packageManager")
            .and_then(|v| v.as_str())
            .and_then(Self::parse)
    }

    #[must_use]
    pub fn manager(&self) -> Option<Manager> {
        Manager::from_name(&self.name)
    }
}

impl Manager {
    pub const ALL: [Self; 11] = [
        Self::Npm,
        Self::Pnpm,
        Self::Yarn,
        Self::Bun,
        Self::Uv,
        Self::Cargo,
        Self::Composer,
        Self::Poetry,
        Self::Pip,
        Self::Pipenv,
        Self::Bundler,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
            Self::Uv => "uv",
            Self::Cargo => "cargo",
            Self::Composer => "composer",
            Self::Poetry => "poetry",
            Self::Pip => "pip",
            Self::Pipenv => "pipenv",
            Self::Bundler => "bundler",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == name)
    }

    /// poetry / pip / pipenv only ever produce a `python.not-uv` finding.
    #[must_use]
    pub const fn is_legacy_python(self) -> bool {
        matches!(self, Self::Poetry | Self::Pip | Self::Pipenv)
    }

    /// Binary checked at preflight; for bundler this is the audit tool itself.
    #[must_use]
    pub const fn binary(self) -> Option<&'static str> {
        match self {
            Self::Npm => Some("npm"),
            Self::Pnpm => Some("pnpm"),
            Self::Yarn => Some("yarn"),
            Self::Bun => Some("bun"),
            Self::Uv => Some("uv"),
            Self::Cargo => Some("cargo"),
            Self::Composer => Some("composer"),
            Self::Bundler => Some("bundle-audit"),
            Self::Poetry | Self::Pip | Self::Pipenv => None,
        }
    }

    #[must_use]
    pub fn audit_argv(self) -> Option<Vec<&'static str>> {
        match self {
            Self::Npm => Some(vec!["npm", "audit", "--json"]),
            Self::Pnpm => Some(vec!["pnpm", "audit", "--json"]),
            Self::Yarn => Some(vec!["yarn", "npm", "audit", "--json"]),
            Self::Bun => Some(vec!["bun", "audit", "--json"]),
            Self::Uv => Some(vec!["uv", "audit", "--output-format", "json", "--frozen"]),
            Self::Cargo => Some(vec!["cargo", "audit", "--json"]),
            Self::Bundler => Some(vec!["bundle-audit", "check", "--format", "json"]),
            Self::Composer => Some(vec!["composer", "audit", "--format", "json", "--locked"]),
            Self::Poetry | Self::Pip | Self::Pipenv => None,
        }
    }

    #[must_use]
    pub const fn lockfile_names(self) -> &'static [&'static str] {
        match self {
            Self::Npm => &["package-lock.json"],
            Self::Pnpm => &["pnpm-lock.yaml"],
            Self::Yarn => &["yarn.lock"],
            Self::Bun => &["bun.lock", "bun.lockb"],
            Self::Uv => &["uv.lock"],
            Self::Cargo => &["Cargo.lock"],
            Self::Composer => &["composer.lock"],
            Self::Bundler => &["Gemfile.lock"],
            Self::Poetry | Self::Pip | Self::Pipenv => &[],
        }
    }

    #[must_use]
    pub const fn config_names(self) -> &'static [&'static str] {
        match self {
            Self::Npm => &[".npmrc"],
            Self::Pnpm => &["pnpm-workspace.yaml"],
            Self::Yarn => &[".yarnrc.yml"],
            Self::Bun => &["bunfig.toml"],
            Self::Uv => &["uv.toml", "pyproject.toml"],
            Self::Cargo => &[".cargo/config.toml", ".cargo/config"],
            Self::Composer => &["composer.json"],
            Self::Bundler => &[".bundle/config"],
            Self::Poetry | Self::Pip | Self::Pipenv => &[],
        }
    }

    /// True once this manager's settings checks and advisory parser are ported
    /// from the TS build. Must track the matches in
    /// `settings::audit_manager_settings` and `advisories::parse_output`;
    /// `dump-catalog` reads it so the docs site cannot claim support the
    /// binary does not have.
    #[must_use]
    pub const fn ported(self) -> bool {
        matches!(
            self,
            Self::Npm
                | Self::Pnpm
                | Self::Yarn
                | Self::Bun
                | Self::Uv
                | Self::Cargo
                | Self::Composer
                | Self::Bundler
        )
    }

    /// The config format `--fix` writes for this manager. Exactly one format
    /// per manager, stated here and nowhere else, so no check module has to
    /// decide (or re-decide) that e.g. yarn is YAML.
    #[must_use]
    pub const fn config_format(self) -> Option<ConfigFormat> {
        match self {
            Self::Npm => Some(ConfigFormat::Npmrc),
            Self::Pnpm | Self::Yarn => Some(ConfigFormat::Yaml),
            Self::Bun | Self::Uv | Self::Cargo => Some(ConfigFormat::Toml),
            Self::Composer => Some(ConfigFormat::Json),
            Self::Bundler => Some(ConfigFormat::BundleConfig),
            Self::Poetry | Self::Pip | Self::Pipenv => None,
        }
    }

    /// Where this manager's config sits when discovery found none.
    #[must_use]
    pub fn default_config_path(self, project_root: &Path) -> Option<PathBuf> {
        self.write_config_name().map(|name| project_root.join(name))
    }

    /// Where this manager's lockfile sits when discovery found none: the first
    /// accepted name.
    #[must_use]
    pub fn default_lockfile_path(self, project_root: &Path) -> Option<PathBuf> {
        self.lockfile_names()
            .first()
            .map(|name| project_root.join(name))
    }

    /// Names every lockfile this manager accepts, so the message cannot drift
    /// from `lockfile_names`.
    #[must_use]
    pub fn lockfile_required_message(self) -> Option<String> {
        let names = self.lockfile_names();
        if names.is_empty() {
            return None;
        }
        Some(format!("{} is required", names.join(" or ")))
    }

    #[must_use]
    pub const fn write_config_name(self) -> Option<&'static str> {
        match self {
            Self::Npm => Some(".npmrc"),
            Self::Pnpm => Some("pnpm-workspace.yaml"),
            Self::Yarn => Some(".yarnrc.yml"),
            Self::Bun => Some("bunfig.toml"),
            Self::Cargo => Some(".cargo/config.toml"),
            Self::Composer => Some("composer.json"),
            Self::Bundler => Some(".bundle/config"),
            // uv's write target depends on which config exists; see write_target
            Self::Uv => None,
            Self::Poetry | Self::Pip | Self::Pipenv => None,
        }
    }

    /// File `--fix` writes for this manager. uv prefers `uv.toml` when that
    /// file is already present; otherwise it writes `[tool.uv]` in
    /// `pyproject.toml`. Every other manager writes its `write_config_name`.
    ///
    /// The format half always comes from `config_format`, so the path and the
    /// format cannot disagree.
    #[must_use]
    pub fn write_target(self, project_root: &Path) -> Option<(PathBuf, ConfigFormat)> {
        let format = self.config_format()?;
        let path = match self {
            Self::Uv => {
                let uv_toml = project_root.join("uv.toml");
                if uv_toml.is_file() {
                    uv_toml
                } else {
                    project_root.join("pyproject.toml")
                }
            }
            other => other.default_config_path(project_root)?,
        };
        Some((path, format))
    }

    /// Dotted-key prefix for uv settings. `pyproject.toml` stores them under
    /// `[tool.uv]`; `uv.toml` is a bare uv config.
    #[must_use]
    pub fn uv_key_prefix(write_file: &Path) -> &'static str {
        if write_file
            .file_name()
            .is_some_and(|name| name == "pyproject.toml")
        {
            "tool.uv."
        } else {
            ""
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
        assert_eq!(pin.minor, 12);
        assert_eq!(pin.patch, 1);
        assert!(pin.at_least(9, 12));
        assert!(!pin.at_least(9, 13));
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
        let (file, format) = Manager::Npm
            .write_target(std::path::Path::new("/p"))
            .unwrap();
        assert_eq!(file, std::path::PathBuf::from("/p/.npmrc"));
        assert_eq!(format, crate::fix::ConfigFormat::Npmrc);
    }

    #[test]
    fn write_target_format_always_matches_config_format() {
        for m in Manager::ALL {
            match (
                m.write_target(std::path::Path::new("/p")),
                m.config_format(),
            ) {
                (Some((_, target_format)), Some(format)) => assert_eq!(
                    target_format,
                    format,
                    "{} write_target disagrees with config_format",
                    m.name()
                ),
                (None, None) => {}
                (target, format) => panic!(
                    "{} has write_target {target:?} but config_format {format:?}",
                    m.name()
                ),
            }
        }
    }

    #[test]
    fn every_writable_manager_has_a_default_config_and_lockfile() {
        for m in Manager::ALL
            .into_iter()
            .filter(|m| m.config_format().is_some())
        {
            assert!(
                m.default_lockfile_path(std::path::Path::new("/p"))
                    .is_some(),
                "{} has no default lockfile path",
                m.name()
            );
            assert!(
                m.lockfile_required_message().is_some(),
                "{} has no lockfile message",
                m.name()
            );
        }
        // uv is the one manager whose write target depends on what exists on
        // disk, so it deliberately has no static `write_config_name`.
        assert_eq!(
            Manager::Uv.default_config_path(std::path::Path::new("/p")),
            None
        );
    }

    #[test]
    fn lockfile_messages_name_every_accepted_lockfile() {
        assert_eq!(
            Manager::Npm.lockfile_required_message().unwrap(),
            "package-lock.json is required"
        );
        assert_eq!(
            Manager::Bun.lockfile_required_message().unwrap(),
            "bun.lock or bun.lockb is required"
        );
        assert_eq!(Manager::Pip.lockfile_required_message(), None);
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
