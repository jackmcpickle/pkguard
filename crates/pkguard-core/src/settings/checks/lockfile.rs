use super::{fixable_finding, setting_finding, yaml_fix};
use crate::findings::{Finding, FindingKind, Severity};
use crate::fix::ConfigEdit;
use crate::format::yaml::{self, Yaml};
use crate::manager::{Manager, PackageManagerPin};
use std::path::Path;

pub fn check(
    required: bool,
    present: bool,
    path: &Path,
    message: &str,
    manager: Manager,
) -> Vec<Finding> {
    if required && !present {
        vec![setting_finding(
            "lockfile.missing",
            message,
            Severity::High,
            path,
            manager,
        )]
    } else {
        Vec::new()
    }
}

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

pub fn pnpm_trust_bypass(yaml: &Yaml, yaml_path: &Path) -> Vec<Finding> {
    if yaml::is_true(yaml::first(yaml, &["trustLockfile", "trust-lockfile"])) {
        vec![fixable_finding(
            "lockfile.trust-bypass",
            "pnpm trustLockfile must not be true",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            yaml_fix(yaml_path, vec![ConfigEdit::set("trustLockfile", false)]),
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
            yaml_fix(
                yaml_path,
                vec![ConfigEdit::set("verifyDepsBeforeRun", "error")],
            ),
        )]
    }
}
