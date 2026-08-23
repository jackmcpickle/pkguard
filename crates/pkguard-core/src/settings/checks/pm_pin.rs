use super::{pin_severity, setting_finding};
use crate::findings::Finding;
use crate::manager::Manager;
use crate::policy::Preset;
use std::path::Path;

pub fn check(
    required: bool,
    pinned: bool,
    message: &str,
    preset: Preset,
    path: &Path,
    manager: Manager,
) -> Vec<Finding> {
    if required && !pinned {
        vec![setting_finding(
            "pm.unpinned",
            message,
            pin_severity(preset),
            path,
            manager,
        )]
    } else {
        Vec::new()
    }
}
