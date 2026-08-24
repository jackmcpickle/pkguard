use owo_colors::{OwoColorize, Style};
use pkguard_core::findings::{Finding, Severity};
use pkguard_core::pipeline::ScanSummary;
use pkguard_core::policy::Preset;
use std::path::{Path, PathBuf};

pub struct RenderOptions {
    pub color: bool,
}

fn paint(text: &str, style: Style, opts: &RenderOptions) -> String {
    if opts.color {
        format!("{}", text.style(style))
    } else {
        text.to_string()
    }
}

fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::new().red().bold(),
        Severity::High => Style::new().red(),
        Severity::Moderate => Style::new().yellow(),
        Severity::Low => Style::new().cyan(),
        Severity::Info => Style::new().dimmed(),
    }
}

fn display_name(root: &Path) -> String {
    root.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.display().to_string())
}

fn package_cell(finding: &Finding) -> String {
    let Some(package) = &finding.package else {
        return "-".to_string();
    };
    let mut cell = package.clone();
    if let Some(version) = &finding.current_version {
        cell.push('@');
        cell.push_str(version);
    }
    if let Some(fix) = &finding.fix_version {
        cell.push_str(" -> ");
        cell.push_str(fix);
    }
    cell
}

fn config_line(preset: Preset, config_sources: &[PathBuf], opts: &RenderOptions) -> String {
    let mut line = format!("preset {}", preset.as_str());
    if !config_sources.is_empty() {
        let names: Vec<String> = config_sources
            .iter()
            .map(|p| display_name(p.as_path()))
            .collect();
        line.push_str(" · config ");
        line.push_str(&names.join(", "));
    }
    format!("  {}\n", paint(&line, Style::new().dimmed(), opts))
}

/// One project's result block: header, dim config provenance, and a
/// severity-sorted findings table with stable column alignment.
pub fn project_block(
    root: &Path,
    findings: &[Finding],
    incomplete: bool,
    preset: Preset,
    config_sources: &[PathBuf],
    opts: &RenderOptions,
) -> String {
    let name = display_name(root);
    if findings.is_empty() && !incomplete {
        return format!(
            "{} {}  {}\n",
            paint("ok", Style::new().green(), opts),
            paint(&name, Style::new().bold(), opts),
            paint(
                &format!("preset {}", preset.as_str()),
                Style::new().dimmed(),
                opts
            ),
        );
    }

    let mut out = String::new();
    if incomplete {
        out.push_str(&paint("incomplete", Style::new().red().bold(), opts));
        out.push(' ');
    }
    out.push_str(&paint(&name, Style::new().bold(), opts));
    out.push_str(&format!(
        "  {} finding{}\n",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    ));
    out.push_str(&config_line(preset, config_sources, opts));

    let mut rows: Vec<&Finding> = findings.iter().collect();
    rows.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.code.cmp(&b.code)));

    let cells: Vec<(String, String, String, String, String)> = rows
        .iter()
        .map(|f| {
            (
                f.severity.as_str().to_string(),
                f.manager.map(|m| m.name()).unwrap_or("-").to_string(),
                f.code.clone(),
                package_cell(f),
                f.message.clone(),
            )
        })
        .collect();
    let width = |pick: fn(&(String, String, String, String, String)) -> usize| {
        cells.iter().map(pick).max().unwrap_or(0)
    };
    let widths = (
        width(|c| c.0.len()),
        width(|c| c.1.len()),
        width(|c| c.2.len()),
        width(|c| c.3.len()),
    );

    for (row, finding) in cells.iter().zip(rows.iter()) {
        let severity = paint(
            &format!("{:<w$}", row.0, w = widths.0),
            severity_style(finding.severity),
            opts,
        );
        let manager = format!("{:<w$}", row.1, w = widths.1);
        let code = format!("{:<w$}", row.2, w = widths.2);
        let package = format!("{:<w$}", row.3, w = widths.3);
        out.push_str(&format!(
            "  {severity}  {manager}  {code}  {package}  {}\n",
            row.4
        ));
    }
    out
}

#[derive(Default)]
pub struct SeverityCounts {
    critical: usize,
    high: usize,
    moderate: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    pub fn add(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Moderate => self.moderate += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    fn parts(&self, opts: &RenderOptions) -> Vec<String> {
        [
            (self.critical, Severity::Critical),
            (self.high, Severity::High),
            (self.moderate, Severity::Moderate),
            (self.low, Severity::Low),
            (self.info, Severity::Info),
        ]
        .into_iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, severity)| {
            paint(
                &format!("{count} {}", severity.as_str()),
                severity_style(severity),
                opts,
            )
        })
        .collect()
    }
}

pub fn summary_block(
    summary: &ScanSummary,
    counts: &SeverityCounts,
    opts: &RenderOptions,
) -> String {
    let findings_part = {
        let parts = counts.parts(opts);
        if parts.is_empty() {
            paint("no findings", Style::new().green(), opts)
        } else {
            parts.join(", ")
        }
    };
    let policy = if summary.policy_failure {
        paint("policy failed", Style::new().red().bold(), opts)
    } else {
        paint("policy passed", Style::new().green(), opts)
    };
    let mut line = format!(
        "\n{} project{} · {} · {}",
        summary.projects,
        if summary.projects == 1 { "" } else { "s" },
        findings_part,
        policy,
    );
    if summary.incomplete {
        line.push_str(" · ");
        line.push_str(&paint("audit incomplete", Style::new().red(), opts));
    }
    line.push_str(&format!(" · exit {}\n", summary.exit.code()));
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkguard_core::findings::{Finding, FindingKind, Severity};
    use pkguard_core::manager::Manager;
    use pkguard_core::pipeline::ScanSummary;
    use pkguard_core::policy::{ExitCode, Preset};
    use std::path::{Path, PathBuf};

    fn finding(
        code: &str,
        severity: Severity,
        package: Option<&str>,
        fix: Option<&str>,
    ) -> Finding {
        Finding {
            kind: FindingKind::Advisory,
            code: code.into(),
            message: format!("{code} message"),
            severity,
            path: "/p/package-lock.json".into(),
            fixable: fix.is_some(),
            manager: Some(Manager::Npm),
            package: package.map(str::to_string),
            current_version: package.map(|_| "1.0.0".into()),
            fix_version: fix.map(str::to_string),
            fix: None,
        }
    }

    fn plain() -> RenderOptions {
        RenderOptions { color: false }
    }

    #[test]
    fn project_block_renders_header_config_line_and_aligned_columns() {
        let findings = vec![
            finding("GHSA-v7", Severity::High, Some("left-pad"), Some("1.3.0")),
            finding("scripts.pin-missing", Severity::Info, None, None),
        ];
        let block = project_block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[PathBuf::from("/scan/app/.pkguard.toml")],
            &plain(),
        );
        let lines: Vec<&str> = block.lines().collect();
        assert_eq!(lines[0], "app  2 findings");
        assert_eq!(lines[1], "  preset standard · config .pkguard.toml");
        // columns: severity, manager, code, package[@version -> fix], message
        assert_eq!(
            lines[2],
            "  high  npm  GHSA-v7              left-pad@1.0.0 -> 1.3.0  GHSA-v7 message"
        );
        assert_eq!(
            lines[3],
            "  info  npm  scripts.pin-missing  -                        scripts.pin-missing message"
        );
    }

    #[test]
    fn rows_sort_by_severity_descending_then_code() {
        let findings = vec![
            finding("b-low", Severity::Low, None, None),
            finding("a-crit", Severity::Critical, None, None),
            finding("a-low", Severity::Low, None, None),
        ];
        let block = project_block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[],
            &plain(),
        );
        let codes: Vec<usize> = ["a-crit", "a-low", "b-low"]
            .iter()
            .map(|c| block.find(c).unwrap())
            .collect();
        assert!(codes[0] < codes[1] && codes[1] < codes[2]);
    }

    #[test]
    fn clean_project_is_a_single_ok_line() {
        let block = project_block(
            Path::new("/scan/app"),
            &[],
            false,
            Preset::Standard,
            &[],
            &plain(),
        );
        assert_eq!(block, "ok app  preset standard\n");
    }

    #[test]
    fn incomplete_project_is_flagged() {
        let block = project_block(
            Path::new("/scan/app"),
            &[],
            true,
            Preset::Standard,
            &[],
            &plain(),
        );
        assert!(block.starts_with("incomplete app"));
    }

    #[test]
    fn color_mode_dims_config_and_colors_severities() {
        let findings = vec![finding("GHSA-v7", Severity::Critical, None, None)];
        let block = project_block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[PathBuf::from("/scan/app/.pkguard.toml")],
            &RenderOptions { color: true },
        );
        // dim gray config line, red+bold critical severity
        assert!(block.contains("\u{1b}[2m"), "expected dim: {block:?}");
        assert!(block.contains("\u{1b}[31"), "expected red: {block:?}");
        // color never leaks past line ends without a reset
        assert!(block.contains("\u{1b}[0m"));
    }

    #[test]
    fn summary_counts_by_severity_and_reports_exit() {
        let mut counts = SeverityCounts::default();
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::High,
            Severity::Info,
        ] {
            counts.add(severity);
        }
        let text = summary_block(
            &ScanSummary {
                projects: 3,
                incomplete: false,
                policy_failure: true,
                exit: ExitCode::PolicyFailure,
            },
            &counts,
            &plain(),
        );
        assert!(text.contains("3 projects"));
        assert!(text.contains("1 critical"));
        assert!(text.contains("2 high"));
        assert!(text.contains("1 info"));
        assert!(!text.contains("moderate"));
        assert!(text.contains("policy failed"));
        assert!(text.contains("exit 1"));
    }
}
