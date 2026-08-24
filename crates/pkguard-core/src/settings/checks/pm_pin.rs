use super::{fixable_finding, pin_severity, setting_finding};
use crate::findings::Finding;
use crate::fix::SettingsFix;
use crate::manager::{Manager, PackageManagerPin};
use crate::policy::Preset;
use std::path::Path;

/// Does `package.json#packageManager` pin this manager acceptably?
///
/// The rule varies: most managers just need the matching name, but yarn must
/// additionally be major 2 or later (yarn 1 is classic and unsupported). That
/// variation lives here so no caller has to know it.
fn is_pinned(pin: Option<&PackageManagerPin>, manager: Manager) -> bool {
    let Some(pin) = pin else {
        return false;
    };
    if pin.name != manager.name() {
        return false;
    }
    match manager {
        Manager::Yarn => pin.major >= 2,
        _ => true,
    }
}

/// The requirement, phrased for the user.
fn requirement(manager: Manager) -> String {
    match manager {
        Manager::Yarn => "package.json packageManager must be yarn@ major >= 2".to_string(),
        other => format!(
            "package.json packageManager must start with {}@",
            other.name()
        ),
    }
}

/// `pm.unpinned` for a manager whose `packageManager` pin is missing or wrong.
///
/// Takes the parsed pin rather than a pre-computed boolean, so the pin rule and
/// the message it produces stay in one place.
///
/// `fix` is `None` when the caller could not determine which version to pin;
/// the finding is then reported but not repairable.
#[must_use]
pub fn check(
    required: bool,
    pin: Option<&PackageManagerPin>,
    manager: Manager,
    preset: Preset,
    project_root: &Path,
    fix: Option<SettingsFix>,
) -> Vec<Finding> {
    if !required || is_pinned(pin, manager) {
        return Vec::new();
    }
    let manifest = project_root.join("package.json");
    let severity = pin_severity(preset);
    vec![match fix {
        Some(fix) => fixable_finding(
            "pm.unpinned",
            requirement(manager),
            severity,
            &manifest,
            manager,
            fix,
        ),
        None => setting_finding(
            "pm.unpinned",
            requirement(manager),
            severity,
            &manifest,
            manager,
        ),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(field: &str) -> PackageManagerPin {
        PackageManagerPin::parse(field).unwrap()
    }

    #[test]
    fn a_matching_name_pins_most_managers() {
        assert!(is_pinned(Some(&pin("npm@10.2.0")), Manager::Npm));
        assert!(is_pinned(Some(&pin("pnpm@9.0.0")), Manager::Pnpm));
        assert!(is_pinned(Some(&pin("bun@1.1.0")), Manager::Bun));
    }

    #[test]
    fn a_pin_for_another_manager_does_not_count() {
        assert!(!is_pinned(Some(&pin("pnpm@9.0.0")), Manager::Npm));
        assert!(!is_pinned(Some(&pin("npm@10.0.0")), Manager::Pnpm));
        assert!(!is_pinned(None, Manager::Npm));
    }

    #[test]
    fn yarn_classic_is_not_an_acceptable_pin() {
        assert!(!is_pinned(Some(&pin("yarn@1.22.19")), Manager::Yarn));
        assert!(is_pinned(Some(&pin("yarn@2.0.0")), Manager::Yarn));
        assert!(is_pinned(Some(&pin("yarn@4.1.0")), Manager::Yarn));
    }

    #[test]
    fn messages_name_the_manager() {
        assert_eq!(
            requirement(Manager::Npm),
            "package.json packageManager must start with npm@"
        );
        assert_eq!(
            requirement(Manager::Yarn),
            "package.json packageManager must be yarn@ major >= 2"
        );
    }

    #[test]
    fn nothing_is_reported_when_the_pin_is_not_required() {
        assert!(check(
            false,
            None,
            Manager::Npm,
            Preset::Strict,
            Path::new("/p"),
            None
        )
        .is_empty());
    }

    #[test]
    fn the_finding_points_at_the_manifest() {
        let findings = check(
            true,
            None,
            Manager::Npm,
            Preset::Standard,
            Path::new("/p"),
            None,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "pm.unpinned");
        assert!(findings[0].path.ends_with("package.json"));
    }

    /// Without a version to pin there is nothing to write, so the finding must
    /// not claim to be fixable.
    #[test]
    fn an_unfixable_pin_is_reported_but_not_marked_fixable() {
        let findings = check(
            true,
            None,
            Manager::Bun,
            Preset::Standard,
            Path::new("/p"),
            None,
        );
        assert!(!findings[0].fixable);
        assert!(findings[0].fix.is_none());
    }

    #[test]
    fn a_supplied_fix_makes_the_pin_repairable() {
        let fix = SettingsFix::new(
            Path::new("/p/package.json"),
            crate::fix::ConfigFormat::Json,
            vec![crate::fix::ConfigEdit::set("packageManager", "bun@1.3.13")],
        );
        let findings = check(
            true,
            None,
            Manager::Bun,
            Preset::Standard,
            Path::new("/p"),
            Some(fix.clone()),
        );
        assert!(findings[0].fixable);
        assert_eq!(findings[0].fix.as_ref(), Some(&fix));
    }
}
