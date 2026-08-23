use super::setting_finding;
use crate::findings::{Finding, Severity};
use crate::manager::Manager;
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
