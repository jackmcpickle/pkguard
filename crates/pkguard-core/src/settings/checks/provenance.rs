use super::{fixable_finding, yaml_fix};
use crate::findings::{Finding, Severity};
use crate::fix::ConfigEdit;
use crate::format::yaml::{self, Yaml};
use crate::manager::{Manager, PackageManagerPin};
use std::path::Path;

const TRUST_POLICY_IGNORE_AFTER_MINUTES: f64 = 90.0 * 24.0 * 60.0;

pub fn pnpm_checks(yaml: &Yaml, yaml_path: &Path, pin: Option<&PackageManagerPin>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if PackageManagerPin::at_least_or_unknown(pin, 10, 27) {
        let minutes = yaml::first(
            yaml,
            &["trustPolicyIgnoreAfter", "trust-policy-ignore-after"],
        )
        .and_then(yaml::as_f64);
        if !minutes.is_some_and(|m| m >= TRUST_POLICY_IGNORE_AFTER_MINUTES) {
            findings.push(fixable_finding(
                "provenance.ignore-after",
                format!(
                    "pnpm trustPolicyIgnoreAfter must be at least {TRUST_POLICY_IGNORE_AFTER_MINUTES} minutes (90 days)"
                ),
                Severity::High,
                yaml_path,
                Manager::Pnpm,
                yaml_fix(
                    yaml_path,
                    vec![ConfigEdit::set(
                        "trustPolicyIgnoreAfter",
                        TRUST_POLICY_IGNORE_AFTER_MINUTES as i64,
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
                yaml_fix(
                    yaml_path,
                    vec![ConfigEdit::set("trustPolicy", "no-downgrade")],
                ),
            ));
        }
    }
    findings
}
