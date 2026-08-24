use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Moderate,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Moderate => "moderate",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    Settings,
    Advisory,
    LeftoverLockfile,
    UnsupportedPm,
    MissingBinary,
    NotUsingUv,
    Deprecated,
    Quarantine,
}

impl FindingKind {
    pub fn is_advisory(self) -> bool {
        matches!(
            self,
            FindingKind::Advisory | FindingKind::Deprecated | FindingKind::Quarantine
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub kind: FindingKind,
    pub code: String,
    pub message: String,
    pub severity: Severity,
    pub path: String,
    pub fixable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<crate::manager::Manager>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_version: Option<String>,
    /// How `--fix` repairs this finding. `None` whenever `fixable` is false;
    /// `settings::checks` keeps the two in step (see the consistency test).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<crate::fix::SettingsFix>,
}

pub mod codes {
    /// Frozen semantic contract shared with the TS version; advisory findings
    /// additionally use their upstream advisory id as the code.
    pub const STATIC_FINDING_CODES: [&str; 41] = [
        "advisory.unknown",
        "agentic.cache-disabled",
        "audit.blocking-disabled",
        "audit.disabled",
        "audit.malware-disabled",
        "cache.path-committed",
        "integrity.checksum-relaxed",
        "integrity.hardened-mode",
        "integrity.strict-ssl",
        "layout.pnp",
        "layout.shamefully-hoist",
        "lockfile.leftover",
        "lockfile.missing",
        "lockfile.run-verify",
        "lockfile.trust-bypass",
        "min-age.disabled",
        "min-age.exclude-all",
        "min-age.missing-time",
        "min-age.non-strict",
        "overrides.legacy-location",
        "overrides.present",
        "pm.missing-binary",
        "pm.multiple-node",
        "pm.multiple-python",
        "pm.unpinned",
        "pm.unsupported",
        "provenance.ignore-after",
        "provenance.no-downgrade",
        "python.not-uv",
        "registry.mismatch",
        "registry.unpinned",
        "scripts.allowlist-advisory",
        "scripts.allowlist-masked",
        "scripts.bypass-enabled",
        "scripts.legacy-config",
        "scripts.non-strict",
        "scripts.pin-missing",
        "scripts.unrestricted",
        "source-fallback.enabled",
        "source.git-unrestricted",
        "source.non-registry",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_from_info_to_critical() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Moderate);
        assert!(Severity::Moderate > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"high\"");
        assert_eq!(
            serde_json::from_str::<Severity>("\"moderate\"").unwrap(),
            Severity::Moderate
        );
    }

    // The finding codes are a frozen semantic contract with the TS version
    // (CI pipelines and SARIF consumers key on them). Extracted from
    // src/settings.ts, src/agentic.ts, src/discover.ts, src/advisory-report.ts.
    #[test]
    fn static_finding_codes_are_frozen() {
        let expected = [
            "advisory.unknown",
            "agentic.cache-disabled",
            "audit.blocking-disabled",
            "audit.disabled",
            "audit.malware-disabled",
            "cache.path-committed",
            "integrity.checksum-relaxed",
            "integrity.hardened-mode",
            "integrity.strict-ssl",
            "layout.pnp",
            "layout.shamefully-hoist",
            "lockfile.leftover",
            "lockfile.missing",
            "lockfile.run-verify",
            "lockfile.trust-bypass",
            "min-age.disabled",
            "min-age.exclude-all",
            "min-age.missing-time",
            "min-age.non-strict",
            "overrides.legacy-location",
            "overrides.present",
            "pm.missing-binary",
            "pm.multiple-node",
            "pm.multiple-python",
            "pm.unpinned",
            "pm.unsupported",
            "provenance.ignore-after",
            "provenance.no-downgrade",
            "python.not-uv",
            "registry.mismatch",
            "registry.unpinned",
            "scripts.allowlist-advisory",
            "scripts.allowlist-masked",
            "scripts.bypass-enabled",
            "scripts.legacy-config",
            "scripts.non-strict",
            "scripts.pin-missing",
            "scripts.unrestricted",
            "source-fallback.enabled",
            "source.git-unrestricted",
            "source.non-registry",
        ];
        assert_eq!(codes::STATIC_FINDING_CODES, expected);
    }

    #[test]
    fn finding_kind_serializes_kebab_case() {
        assert_eq!(
            serde_json::to_string(&FindingKind::MissingBinary).unwrap(),
            "\"missing-binary\""
        );
        assert_eq!(
            serde_json::to_string(&FindingKind::LeftoverLockfile).unwrap(),
            "\"leftover-lockfile\""
        );
    }

    #[test]
    fn advisory_kinds_are_advisory_deprecated_quarantine() {
        assert!(FindingKind::Advisory.is_advisory());
        assert!(FindingKind::Deprecated.is_advisory());
        assert!(FindingKind::Quarantine.is_advisory());
        assert!(!FindingKind::Settings.is_advisory());
        assert!(!FindingKind::MissingBinary.is_advisory());
    }
}
