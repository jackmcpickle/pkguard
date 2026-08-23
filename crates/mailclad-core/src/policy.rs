use crate::findings::{FindingKind, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Relaxed,
    Standard,
    Strict,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Relaxed => "relaxed",
            Preset::Standard => "standard",
            Preset::Strict => "strict",
        }
    }

    /// Findings at or above this severity fail the run (exit 1).
    pub fn gate(self) -> Severity {
        match self {
            Preset::Relaxed => Severity::Critical,
            Preset::Standard => Severity::High,
            Preset::Strict => Severity::Moderate,
        }
    }
}

impl std::fmt::Display for Preset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn fails_gate(kind: FindingKind, severity: Severity, gate: Severity) -> bool {
    match kind {
        FindingKind::MissingBinary => false,
        FindingKind::Deprecated | FindingKind::Quarantine => true,
        _ => severity >= gate,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Clean,
    PolicyFailure,
    Incomplete,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        match self {
            ExitCode::Clean => 0,
            ExitCode::PolicyFailure => 1,
            ExitCode::Incomplete => 2,
        }
    }
}

pub fn exit_code_for(
    project_count: usize,
    incomplete: bool,
    skipped_dirty: bool,
    policy_failure: bool,
) -> ExitCode {
    if project_count == 0 || incomplete || skipped_dirty {
        ExitCode::Incomplete
    } else if policy_failure {
        ExitCode::PolicyFailure
    } else {
        ExitCode::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{FindingKind, Severity};

    #[test]
    fn gate_severity_per_preset() {
        assert_eq!(Preset::Relaxed.gate(), Severity::Critical);
        assert_eq!(Preset::Standard.gate(), Severity::High);
        assert_eq!(Preset::Strict.gate(), Severity::Moderate);
    }

    #[test]
    fn missing_binary_never_fails_gate() {
        assert!(!fails_gate(
            FindingKind::MissingBinary,
            Severity::Critical,
            Severity::Info
        ));
    }

    #[test]
    fn deprecated_and_quarantine_always_fail_gate() {
        assert!(fails_gate(
            FindingKind::Deprecated,
            Severity::Info,
            Severity::Critical
        ));
        assert!(fails_gate(
            FindingKind::Quarantine,
            Severity::Info,
            Severity::Critical
        ));
    }

    #[test]
    fn other_kinds_fail_gate_at_or_above_severity() {
        assert!(fails_gate(
            FindingKind::Settings,
            Severity::High,
            Severity::High
        ));
        assert!(!fails_gate(
            FindingKind::Settings,
            Severity::Moderate,
            Severity::High
        ));
        assert!(fails_gate(
            FindingKind::Advisory,
            Severity::Critical,
            Severity::High
        ));
    }

    #[test]
    fn exit_code_semantics() {
        // no projects, incomplete audit, or skipped-dirty => 2
        assert_eq!(exit_code_for(0, false, false, false), ExitCode::Incomplete);
        assert_eq!(exit_code_for(3, true, false, true), ExitCode::Incomplete);
        assert_eq!(exit_code_for(3, false, true, false), ExitCode::Incomplete);
        // policy failure => 1
        assert_eq!(
            exit_code_for(3, false, false, true),
            ExitCode::PolicyFailure
        );
        // clean => 0
        assert_eq!(exit_code_for(3, false, false, false), ExitCode::Clean);
    }

    #[test]
    fn exit_codes_map_to_process_codes() {
        assert_eq!(ExitCode::Clean.code(), 0);
        assert_eq!(ExitCode::PolicyFailure.code(), 1);
        assert_eq!(ExitCode::Incomplete.code(), 2);
    }
}
