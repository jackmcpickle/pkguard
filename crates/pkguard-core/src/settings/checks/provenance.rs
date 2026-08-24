use super::{fix_for, fixable_finding};
use crate::findings::{Finding, Severity};
use crate::fix::ConfigEdit;
use crate::format::yaml::{self, Yaml};
use crate::manager::{Manager, PackageManagerPin};
use std::path::Path;

/// 90 days. Held as an integer so both the comparison and the written value
/// derive from it losslessly.
const TRUST_POLICY_IGNORE_AFTER_MINUTES: i32 = 90 * 24 * 60;

pub fn pnpm_checks(yaml: &Yaml, yaml_path: &Path, pin: Option<&PackageManagerPin>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if PackageManagerPin::at_least_or_unknown(pin, 10, 27) {
        let minutes = yaml::first(
            yaml,
            &["trustPolicyIgnoreAfter", "trust-policy-ignore-after"],
        )
        .and_then(yaml::as_f64);
        if !minutes.is_some_and(|m| m >= f64::from(TRUST_POLICY_IGNORE_AFTER_MINUTES)) {
            findings.push(fixable_finding(
                "provenance.ignore-after",
                format!(
                    "pnpm trustPolicyIgnoreAfter must be at least {TRUST_POLICY_IGNORE_AFTER_MINUTES} minutes (90 days)"
                ),
                Severity::High,
                yaml_path,
                Manager::Pnpm,
                fix_for(Manager::Pnpm,
                    yaml_path,
                    vec![ConfigEdit::set(
                        "trustPolicyIgnoreAfter",
                        i64::from(TRUST_POLICY_IGNORE_AFTER_MINUTES),
                    )],
                ),
            ));
        }
    }
    if PackageManagerPin::at_least_or_unknown(pin, 10, 21) {
        let policy = yaml::first(yaml, &["trustPolicy", "trust-policy"]).and_then(yaml::as_str);
        if policy != Some("no-downgrade") {
            findings.push(fixable_finding(
                "provenance.no-downgrade",
                "pnpm trustPolicy must be no-downgrade",
                Severity::High,
                yaml_path,
                Manager::Pnpm,
                fix_for(
                    Manager::Pnpm,
                    yaml_path,
                    vec![ConfigEdit::set("trustPolicy", "no-downgrade")],
                ),
            ));
        }
    }
    findings
}
