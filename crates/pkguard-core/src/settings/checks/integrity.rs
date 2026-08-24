use super::{fix_for, fixable_finding};
use crate::findings::{Finding, Severity};
use crate::fix::ConfigEdit;
use crate::format::yaml::{self, Yaml};
use crate::manager::Manager;
use std::path::Path;

pub fn yarn_checks(yarnrc: &Yaml, yarnrc_path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(behavior) = yaml::get(yarnrc, "checksumBehavior").and_then(yaml::as_str) {
        if behavior != "throw" {
            findings.push(fixable_finding(
                "integrity.checksum-relaxed",
                "yarn checksumBehavior must be \"throw\"",
                Severity::High,
                yarnrc_path,
                Manager::Yarn,
                fix_for(
                    Manager::Yarn,
                    yarnrc_path,
                    vec![ConfigEdit::set("checksumBehavior", "throw")],
                ),
            ));
        }
    }
    if yaml::is_false(yaml::get(yarnrc, "enableStrictSsl")) {
        findings.push(fixable_finding(
            "integrity.strict-ssl",
            "yarn enableStrictSsl must not be false",
            Severity::High,
            yarnrc_path,
            Manager::Yarn,
            fix_for(
                Manager::Yarn,
                yarnrc_path,
                vec![ConfigEdit::set("enableStrictSsl", true)],
            ),
        ));
    }
    if yaml::is_false(yaml::get(yarnrc, "enableHardenedMode")) {
        findings.push(fixable_finding(
            "integrity.hardened-mode",
            "yarn enableHardenedMode must not be false",
            Severity::Moderate,
            yarnrc_path,
            Manager::Yarn,
            fix_for(
                Manager::Yarn,
                yarnrc_path,
                vec![ConfigEdit::set("enableHardenedMode", true)],
            ),
        ));
    }
    findings
}
