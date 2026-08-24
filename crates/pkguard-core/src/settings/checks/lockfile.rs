use super::{fix_for, fixable_finding, setting_finding};
use crate::findings::{Finding, FindingKind, Severity};
use crate::fix::ConfigEdit;
use crate::format::yaml::{self, Yaml};
use crate::manager::{Manager, PackageManagerPin};
use std::path::Path;

/// The message names every lockfile the manager accepts, derived from
/// `Manager::lockfile_required_message` rather than restated per caller.
#[must_use]
pub fn check(required: bool, present: bool, path: &Path, manager: Manager) -> Vec<Finding> {
    if !required || present {
        return Vec::new();
    }
    let Some(message) = manager.lockfile_required_message() else {
        return Vec::new();
    };
    vec![setting_finding(
        "lockfile.missing",
        message,
        Severity::High,
        path,
        manager,
    )]
}

#[must_use]
pub fn leftover(path: &Path, manager: Manager) -> Finding {
    Finding {
        kind: FindingKind::LeftoverLockfile,
        code: "lockfile.leftover".into(),
        message: format!(
            "Leftover {} lockfile is not an apply target",
            manager.name()
        ),
        severity: Severity::High,
        path: path.to_string_lossy().into_owned(),
        fixable: false,
        manager: Some(manager),
        package: None,
        current_version: None,
        fix_version: None,
        fix: None,
    }
}

#[must_use]
pub fn unsupported(path: &Path, manager: Manager) -> Finding {
    Finding {
        kind: FindingKind::UnsupportedPm,
        code: "pm.unsupported".into(),
        message: format!("{} is unsupported", manager.name()),
        severity: Severity::High,
        path: path.to_string_lossy().into_owned(),
        fixable: false,
        manager: Some(manager),
        package: None,
        current_version: None,
        fix_version: None,
        fix: None,
    }
}

#[must_use]
pub fn pnpm_trust_bypass(yaml: &Yaml, yaml_path: &Path) -> Vec<Finding> {
    if yaml::is_true(yaml::first(yaml, &["trustLockfile", "trust-lockfile"])) {
        vec![fixable_finding(
            "lockfile.trust-bypass",
            "pnpm trustLockfile must not be true",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            fix_for(
                Manager::Pnpm,
                yaml_path,
                vec![ConfigEdit::set("trustLockfile", false)],
            ),
        )]
    } else {
        Vec::new()
    }
}

pub fn pnpm_run_verify(
    yaml: &Yaml,
    yaml_path: &Path,
    pin: Option<&PackageManagerPin>,
) -> Vec<Finding> {
    if !PackageManagerPin::at_least_or_unknown(pin, 10, 12) {
        return Vec::new();
    }
    let verify = yaml::first(yaml, &["verifyDepsBeforeRun", "verify-deps-before-run"])
        .and_then(yaml::as_str);
    if verify.is_some_and(|value| value.eq_ignore_ascii_case("error")) {
        Vec::new()
    } else {
        vec![fixable_finding(
            "lockfile.run-verify",
            "pnpm verifyDepsBeforeRun must be error",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            fix_for(
                Manager::Pnpm,
                yaml_path,
                vec![ConfigEdit::set("verifyDepsBeforeRun", "error")],
            ),
        )]
    }
}
