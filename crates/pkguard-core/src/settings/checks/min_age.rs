use super::{bundle_fix, fixable_finding, npmrc_fix, setting_finding, toml_fix, yaml_fix};
use crate::config::ResolvedSettings;
use crate::findings::{Finding, Severity};
use crate::fix::ConfigEdit;
use crate::format::yaml::{self, Yaml};
use crate::manager::{Manager, PackageManagerPin};
use crate::policy::Preset;
use std::collections::BTreeMap;
use std::path::Path;

pub fn npm_check(
    settings: &ResolvedSettings,
    npmrc: &BTreeMap<String, String>,
    npmrc_path: &Path,
) -> Vec<Finding> {
    if settings.min_release_age_days == 0 {
        return Vec::new();
    }
    let days: Option<f64> = npmrc
        .get("min-release-age")
        .and_then(|raw| raw.trim().parse().ok());
    if days.is_some_and(|d| d >= f64::from(settings.min_release_age_days)) {
        return Vec::new();
    }
    vec![fixable_finding(
        "min-age.disabled",
        format!(
            "min-release-age must be at least {} days",
            settings.min_release_age_days
        ),
        Severity::High,
        npmrc_path,
        Manager::Npm,
        npmrc_fix(
            npmrc_path,
            vec![ConfigEdit::set(
                "min-release-age",
                settings.min_release_age_days.to_string(),
            )],
        ),
    )]
}

fn unit_to_hours(amount: f64, unit: &str) -> f64 {
    if unit.starts_with('w') {
        amount * 24.0 * 7.0
    } else if unit.starts_with('d') {
        amount * 24.0
    } else if unit.starts_with('m') {
        amount / 60.0
    } else {
        amount
    }
}

pub(super) fn parse_age_hours_str(input: &str) -> Option<f64> {
    let trimmed = input.trim();
    let split = trimmed.find(|c: char| c.is_ascii_alphabetic());
    let (num, unit) = match split {
        Some(index) => (trimmed[..index].trim(), trimmed[index..].trim()),
        None => (trimmed, "m"),
    };
    let amount: f64 = num.parse().ok()?;
    Some(unit_to_hours(amount, unit))
}

pub(super) fn parse_pnpm_age_hours(value: &Yaml) -> Option<f64> {
    if let Some(number) = yaml::as_f64(value) {
        return Some(number / 60.0);
    }
    parse_age_hours_str(yaml::as_str(value)?)
}

pub fn pnpm_checks(
    settings: &ResolvedSettings,
    yaml: &Yaml,
    yaml_path: &Path,
    uses_allow_builds: bool,
) -> Vec<Finding> {
    if settings.min_release_age_days == 0 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let required_hours = f64::from(settings.min_release_age_days) * 24.0;
    let default_hours = if uses_allow_builds { 24.0 } else { 0.0 };
    let hours = match yaml::get(yaml, "minimumReleaseAge") {
        None => Some(default_hours),
        Some(raw) => parse_pnpm_age_hours(raw),
    };
    if !hours.is_some_and(|h| h >= required_hours) {
        findings.push(fixable_finding(
            "min-age.disabled",
            format!(
                "minimumReleaseAge must be at least {} minutes",
                required_hours * 60.0
            ),
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            yaml_fix(
                yaml_path,
                vec![ConfigEdit::set(
                    "minimumReleaseAge",
                    i64::from(settings.min_release_age_days) * 1_440,
                )],
            ),
        ));
    }
    if yaml::is_false(yaml::get(yaml, "minimumReleaseAgeStrict")) {
        findings.push(fixable_finding(
            "min-age.non-strict",
            "pnpm minimumReleaseAgeStrict must not be false",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
            yaml_fix(
                yaml_path,
                vec![ConfigEdit::set("minimumReleaseAgeStrict", true)],
            ),
        ));
    }
    if yaml::is_blanket_exclude(yaml::get(yaml, "minimumReleaseAgeExclude")) {
        findings.push(setting_finding(
            "min-age.exclude-all",
            "minimumReleaseAgeExclude must not exempt every package",
            Severity::High,
            yaml_path,
            Manager::Pnpm,
        ));
    }
    if settings.preset == Preset::Strict
        && !yaml::is_false(yaml::get(yaml, "minimumReleaseAgeIgnoreMissingTime"))
    {
        findings.push(fixable_finding(
            "min-age.missing-time",
            "minimumReleaseAgeIgnoreMissingTime must be false to fail closed",
            Severity::Moderate,
            yaml_path,
            Manager::Pnpm,
            yaml_fix(
                yaml_path,
                vec![ConfigEdit::set("minimumReleaseAgeIgnoreMissingTime", false)],
            ),
        ));
    }
    findings
}

pub fn yarn_checks(
    settings: &ResolvedSettings,
    yarnrc: &Yaml,
    yarnrc_path: &Path,
    pin: Option<&PackageManagerPin>,
) -> Vec<Finding> {
    if settings.min_release_age_days == 0 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let required_hours = f64::from(settings.min_release_age_days) * 24.0;
    let default_hours = if PackageManagerPin::at_least_or_unknown(pin, 4, 12) {
        24.0 * 7.0
    } else {
        0.0
    };
    let hours = match yaml::get(yarnrc, "npmMinimalAgeGate") {
        None => Some(default_hours),
        Some(raw) => parse_pnpm_age_hours(raw),
    };
    if !hours.is_some_and(|h| h >= required_hours) {
        findings.push(fixable_finding(
            "min-age.disabled",
            format!(
                "npmMinimalAgeGate must be at least {} minutes",
                required_hours * 60.0
            ),
            Severity::High,
            yarnrc_path,
            Manager::Yarn,
            yaml_fix(
                yarnrc_path,
                vec![ConfigEdit::set(
                    "npmMinimalAgeGate",
                    i64::from(settings.min_release_age_days) * 1_440,
                )],
            ),
        ));
    }
    if yaml::is_blanket_exclude(yaml::get(yarnrc, "npmPreapprovedPackages")) {
        findings.push(setting_finding(
            "min-age.exclude-all",
            "npmPreapprovedPackages must not exempt every package",
            Severity::High,
            yarnrc_path,
            Manager::Yarn,
        ));
    }
    findings
}

pub fn bun_checks(
    settings: &ResolvedSettings,
    install: Option<&toml::Table>,
    bunfig_path: &Path,
) -> Vec<Finding> {
    if settings.min_release_age_days == 0 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let required_seconds = f64::from(settings.min_release_age_days) * 86_400.0;
    let seconds = install
        .and_then(|t| t.get("minimumReleaseAge"))
        .and_then(|v| v.as_float().or_else(|| v.as_integer().map(|n| n as f64)));
    if !seconds.is_some_and(|s| s >= required_seconds) {
        findings.push(fixable_finding(
            "min-age.disabled",
            format!("install.minimumReleaseAge must be at least {required_seconds} seconds"),
            Severity::High,
            bunfig_path,
            Manager::Bun,
            toml_fix(
                bunfig_path,
                vec![ConfigEdit::set(
                    "install.minimumReleaseAge",
                    i64::from(settings.min_release_age_days) * 86_400,
                )],
            ),
        ));
    }
    let excludes = install.and_then(|t| t.get("minimumReleaseAgeExcludes"));
    if toml_is_blanket(excludes) {
        findings.push(setting_finding(
            "min-age.exclude-all",
            "minimumReleaseAgeExcludes must not exempt every package",
            Severity::High,
            bunfig_path,
            Manager::Bun,
        ));
    }
    findings
}

fn toml_is_blanket(value: Option<&toml::Value>) -> bool {
    match value {
        Some(toml::Value::String(s)) if s == "*" => true,
        Some(toml::Value::Array(items)) => items.iter().any(|item| item.as_str() == Some("*")),
        Some(toml::Value::Table(table)) => table.contains_key("*"),
        _ => false,
    }
}

fn days_since_ymd(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = i64::from(if month <= 2 { year - 1 } else { year });
    let month = i64::from(if month <= 2 { month + 9 } else { month - 3 });
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * month + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn uv_date_meets(trimmed: &str, min_days: u32) -> Option<bool> {
    if !trimmed.contains(['T', 't', '-']) {
        return None;
    }
    let date = trimmed.split(['T', 't']).next()?;
    let mut parts = date.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let then = days_since_ymd(year, month, day)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64
        / 86_400;
    Some(now.saturating_sub(then) >= i64::from(min_days))
}

fn uv_exclude_newer_meets(value: Option<&toml::Value>, min_days: u32) -> bool {
    let min = f64::from(min_days);
    match value {
        Some(toml::Value::Integer(n)) => *n as f64 >= min,
        Some(toml::Value::Float(n)) => *n >= min,
        Some(toml::Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return false;
            }
            if let Ok(number) = trimmed.parse::<f64>() {
                if trimmed == number.to_string() {
                    return number >= min;
                }
            }
            if let Some(meets) = uv_date_meets(trimmed, min_days) {
                return meets;
            }
            parse_age_hours_str(trimmed).is_some_and(|hours| hours / 24.0 >= min)
        }
        _ => false,
    }
}

pub fn uv_checks(
    settings: &ResolvedSettings,
    cfg: &toml::Value,
    config_path: &Path,
    key_prefix: &str,
) -> Vec<Finding> {
    if settings.min_release_age_days == 0 {
        return Vec::new();
    }
    let mut findings = Vec::new();
    if !uv_exclude_newer_meets(cfg.get("exclude-newer"), settings.min_release_age_days) {
        findings.push(fixable_finding(
            "min-age.disabled",
            format!(
                "exclude-newer must meet {} days",
                settings.min_release_age_days
            ),
            Severity::High,
            config_path,
            Manager::Uv,
            toml_fix(
                config_path,
                vec![ConfigEdit::set(
                    format!("{key_prefix}exclude-newer"),
                    i64::from(settings.min_release_age_days),
                )],
            ),
        ));
    }
    if toml_is_blanket(cfg.get("exclude-newer-package")) {
        findings.push(setting_finding(
            "min-age.exclude-all",
            "exclude-newer-package must not exempt every package",
            Severity::High,
            config_path,
            Manager::Uv,
        ));
    }
    findings
}

fn cargo_duration(days: u32) -> String {
    if days.is_multiple_of(7) {
        format!("{}w", days / 7)
    } else {
        format!("{days}d")
    }
}

pub fn cargo_check(
    settings: &ResolvedSettings,
    install: Option<&toml::Table>,
    config_path: &Path,
) -> Vec<Finding> {
    if settings.min_release_age_days == 0 {
        return Vec::new();
    }
    let hours = install
        .and_then(|t| t.get("minimum-release-age"))
        .and_then(|v| {
            v.as_float()
                .or_else(|| v.as_integer().map(|n| n as f64))
                .map(|minutes| minutes / 60.0)
                .or_else(|| v.as_str().and_then(parse_age_hours_str))
        });
    if hours.is_some_and(|h| h / 24.0 >= f64::from(settings.min_release_age_days)) {
        Vec::new()
    } else {
        vec![fixable_finding(
            "min-age.disabled",
            format!(
                "install.minimum-release-age must meet {} days",
                settings.min_release_age_days
            ),
            Severity::High,
            config_path,
            Manager::Cargo,
            toml_fix(
                config_path,
                vec![ConfigEdit::set(
                    "install.minimum-release-age",
                    cargo_duration(settings.min_release_age_days),
                )],
            ),
        )]
    }
}

pub fn bundler_check(
    settings: &ResolvedSettings,
    cooldown: Option<f64>,
    config_path: &Path,
) -> Vec<Finding> {
    if settings.min_release_age_days == 0 {
        return Vec::new();
    }
    if cooldown.is_some_and(|days| days >= f64::from(settings.min_release_age_days)) {
        Vec::new()
    } else {
        vec![fixable_finding(
            "min-age.disabled",
            format!(
                "BUNDLE_COOLDOWN must be at least {} days",
                settings.min_release_age_days
            ),
            Severity::High,
            config_path,
            Manager::Bundler,
            bundle_fix(
                config_path,
                vec![ConfigEdit::set(
                    "BUNDLE_COOLDOWN",
                    settings.min_release_age_days.to_string(),
                )],
            ),
        )]
    }
}
