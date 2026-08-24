use crate::report::ProjectReport;
use owo_colors::{OwoColorize, Style};
use pkguard_core::findings::{Finding, Severity};
use pkguard_core::pipeline::ScanSummary;
use pkguard_core::policy::Preset;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Run-scoped output settings. Per-project data is an argument, not a field —
/// these values are true for the whole run.
#[derive(Default)]
pub struct RenderOptions {
    pub color: bool,
    pub audits_skipped: bool,
}

fn paint(text: &str, style: Style, opts: &RenderOptions) -> String {
    if opts.color {
        format!("{}", text.style(style))
    } else {
        text.to_string()
    }
}

const fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::new().red().bold(),
        Severity::High => Style::new().red(),
        Severity::Moderate => Style::new().yellow(),
        Severity::Low => Style::new().cyan(),
        Severity::Info => Style::new().dimmed(),
    }
}

fn display_name(root: &Path) -> String {
    root.file_name().map_or_else(
        || root.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
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

fn preset_label(preset: Preset, config_sources: &[PathBuf], opts: &RenderOptions) -> String {
    let mut line = format!("preset {}", preset.as_str());
    if !config_sources.is_empty() {
        let names: Vec<String> = config_sources
            .iter()
            .map(|p| display_name(p.as_path()))
            .collect();
        line.push_str(" · config ");
        line.push_str(&names.join(", "));
    }
    if opts.audits_skipped {
        line.push_str(" · audits skipped");
    }
    line
}

fn config_line(preset: Preset, config_sources: &[PathBuf], opts: &RenderOptions) -> String {
    format!(
        "  {}\n",
        paint(
            &preset_label(preset, config_sources, opts),
            Style::new().dimmed(),
            opts
        )
    )
}

/// One project's result block: header, dim config provenance, and a
/// severity-sorted findings table with stable column alignment.
pub fn project_block(report: &ProjectReport, opts: &RenderOptions) -> String {
    let root = report.root.as_path();
    let findings = report.findings.as_slice();
    let incomplete = report.incomplete;
    let preset = report.preset;
    let config_sources = report.config_sources.as_slice();
    let name = display_name(root);
    if findings.is_empty() && !incomplete {
        let mut out = format!(
            "{} {}  {}\n",
            paint("ok", Style::new().green(), opts),
            paint(&name, Style::new().bold(), opts),
            paint(
                &preset_label(preset, &[], opts),
                Style::new().dimmed(),
                opts
            ),
        );
        write_fixed_lines(&mut out, root, report, opts);
        return out;
    }

    let mut out = String::new();
    if incomplete {
        out.push_str(&paint("incomplete", Style::new().red().bold(), opts));
        out.push(' ');
    }
    out.push_str(&paint(&name, Style::new().bold(), opts));
    let _ = writeln!(
        out,
        "  {} finding{}",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );
    out.push_str(&config_line(preset, config_sources, opts));

    let mut settings: Vec<&Finding> = findings.iter().filter(|f| !f.kind.is_advisory()).collect();
    let mut advisories: Vec<&Finding> = findings.iter().filter(|f| f.kind.is_advisory()).collect();
    sort_findings(&mut settings);
    sort_findings(&mut advisories);

    let setting_cells: Vec<RowCells> = settings.iter().map(|f| row_cells(f)).collect();
    let advisory_cells: Vec<RowCells> = advisories.iter().map(|f| row_cells(f)).collect();
    let widths = column_widths(setting_cells.iter().chain(advisory_cells.iter()));
    let show_headers = !settings.is_empty() && !advisories.is_empty();

    write_group(
        &mut out,
        "settings",
        &settings,
        &setting_cells,
        widths,
        show_headers,
        opts,
    );
    write_group(
        &mut out,
        "advisories",
        &advisories,
        &advisory_cells,
        widths,
        show_headers,
        opts,
    );
    write_fixed_lines(&mut out, root, report, opts);
    out
}

fn sort_findings(rows: &mut [&Finding]) {
    rows.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.code.cmp(&b.code)));
}

type RowCells = (String, String, String, String, String);

fn row_cells(finding: &Finding) -> RowCells {
    (
        finding.severity.as_str().to_string(),
        finding
            .manager
            .map_or("-", pkguard_core::manager::Manager::name)
            .to_string(),
        finding.code.clone(),
        package_cell(finding),
        finding.message.clone(),
    )
}

fn column_widths<'a>(cells: impl Iterator<Item = &'a RowCells>) -> (usize, usize, usize, usize) {
    cells.fold((0, 0, 0, 0), |widths, cell| {
        (
            widths.0.max(cell.0.len()),
            widths.1.max(cell.1.len()),
            widths.2.max(cell.2.len()),
            widths.3.max(cell.3.len()),
        )
    })
}

fn write_group(
    out: &mut String,
    header: &str,
    findings: &[&Finding],
    cells: &[RowCells],
    widths: (usize, usize, usize, usize),
    show_header: bool,
    opts: &RenderOptions,
) {
    if findings.is_empty() {
        return;
    }
    if show_header {
        let _ = writeln!(out, "  {}", paint(header, Style::new().dimmed(), opts));
    }
    for (row, finding) in cells.iter().zip(findings.iter()) {
        let severity = paint(
            &format!("{:<w$}", row.0, w = widths.0),
            severity_style(finding.severity),
            opts,
        );
        let manager = format!("{:<w$}", row.1, w = widths.1);
        let code = format!("{:<w$}", row.2, w = widths.2);
        let package = format!("{:<w$}", row.3, w = widths.3);
        let _ = writeln!(out, "  {severity}  {manager}  {code}  {package}  {}", row.4);
    }
}

fn write_fixed_lines(out: &mut String, root: &Path, report: &ProjectReport, opts: &RenderOptions) {
    let Some(applied) = &report.applied else {
        return;
    };
    for (file, reason) in &applied.skipped {
        let path = file.strip_prefix(root).unwrap_or(file.as_path());
        let line = format!("skipped  {}: {}", path.display(), reason.as_str());
        let _ = writeln!(out, "  {}", paint(&line, Style::new().yellow(), opts));
    }
    for change in &applied.changes {
        let file = change
            .file
            .strip_prefix(&change.project_root)
            .or_else(|_| change.file.strip_prefix(root))
            .unwrap_or(change.file.as_path());
        let line = format!(
            "fixed  {}: {} {} -> {}",
            file.display(),
            change.setting,
            change.current,
            change.next
        );
        let _ = writeln!(out, "  {}", paint(&line, Style::new().dimmed(), opts));
    }
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
    pub const fn add(&mut self, severity: Severity) {
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
    settings_fixed: usize,
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
    if settings_fixed > 0 {
        line.push_str(" · ");
        line.push_str(&paint(
            &format!(
                "{settings_fixed} setting{} fixed",
                if settings_fixed == 1 { "" } else { "s" }
            ),
            Style::new().dimmed(),
            opts,
        ));
    }
    let _ = writeln!(line, " · exit {}", summary.exit.code());
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkguard_core::apply::{ApplyResult, PlannedChange};
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
        finding_kind(FindingKind::Advisory, code, severity, package, fix)
    }

    fn settings_finding(code: &str, severity: Severity) -> Finding {
        finding_kind(FindingKind::Settings, code, severity, None, None)
    }

    fn finding_kind(
        kind: FindingKind,
        code: &str,
        severity: Severity,
        package: Option<&str>,
        fix: Option<&str>,
    ) -> Finding {
        Finding {
            kind,
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
        RenderOptions {
            color: false,
            audits_skipped: false,
        }
    }

    /// Assemble a `ProjectReport` so each test still reads as "these findings,
    /// rendered this way".
    fn block(
        root: &Path,
        findings: &[Finding],
        incomplete: bool,
        preset: Preset,
        config_sources: &[PathBuf],
        opts: &RenderOptions,
    ) -> String {
        block_applied(
            root,
            findings,
            incomplete,
            preset,
            config_sources,
            None,
            opts,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn block_applied(
        root: &Path,
        findings: &[Finding],
        incomplete: bool,
        preset: Preset,
        config_sources: &[PathBuf],
        applied: Option<ApplyResult>,
        opts: &RenderOptions,
    ) -> String {
        project_block(
            &ProjectReport {
                root: root.to_path_buf(),
                findings: findings.to_vec(),
                incomplete,
                preset,
                config_sources: config_sources.to_vec(),
                applied,
            },
            opts,
        )
    }

    #[test]
    fn project_block_renders_header_config_line_and_aligned_columns() {
        let findings = vec![
            finding("GHSA-v7", Severity::High, Some("left-pad"), Some("1.3.0")),
            finding("scripts.pin-missing", Severity::Info, None, None),
        ];
        let block = block(
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
        let block = block(
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
        let block = block(
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
        let block = block(
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
        let block = block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[PathBuf::from("/scan/app/.pkguard.toml")],
            &RenderOptions {
                color: true,
                ..Default::default()
            },
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
            0,
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

    #[test]
    fn mixed_project_renders_settings_then_advisories_headers() {
        let findings = vec![
            finding("GHSA-v7", Severity::High, Some("left-pad"), Some("1.3.0")),
            settings_finding("scripts.pin-missing", Severity::Info),
        ];
        let block = block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[PathBuf::from("/scan/app/.pkguard.toml")],
            &plain(),
        );
        let lines: Vec<&str> = block.lines().collect();
        assert_eq!(
            lines,
            [
                "app  2 findings",
                "  preset standard · config .pkguard.toml",
                "  settings",
                "  info  npm  scripts.pin-missing  -                        scripts.pin-missing message",
                "  advisories",
                "  high  npm  GHSA-v7              left-pad@1.0.0 -> 1.3.0  GHSA-v7 message",
            ]
        );
    }

    #[test]
    fn settings_only_project_omits_group_headers() {
        let findings = vec![settings_finding("scripts.pin-missing", Severity::Info)];
        let block = block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[],
            &plain(),
        );
        let lines: Vec<&str> = block.lines().collect();
        assert_eq!(
            lines,
            [
                "app  1 finding",
                "  preset standard",
                "  info  npm  scripts.pin-missing  -  scripts.pin-missing message",
            ]
        );
    }

    #[test]
    fn advisories_only_project_omits_group_headers() {
        let findings = vec![finding(
            "GHSA-v7",
            Severity::High,
            Some("left-pad"),
            Some("1.3.0"),
        )];
        let block = block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[],
            &plain(),
        );
        let lines: Vec<&str> = block.lines().collect();
        assert_eq!(
            lines,
            [
                "app  1 finding",
                "  preset standard",
                "  high  npm  GHSA-v7  left-pad@1.0.0 -> 1.3.0  GHSA-v7 message",
            ]
        );
        assert!(!lines
            .iter()
            .any(|line| *line == "  settings" || *line == "  advisories"));
    }

    #[test]
    fn columns_align_across_settings_and_advisories_groups() {
        let findings = vec![
            finding("GHSA-v7", Severity::High, Some("left-pad"), Some("1.3.0")),
            settings_finding("scripts.pin-missing", Severity::Info),
        ];
        let block = block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[],
            &plain(),
        );
        let settings_msg = "scripts.pin-missing message";
        let advisory_msg = "GHSA-v7 message";
        let settings_line = block
            .lines()
            .find(|line| line.contains(settings_msg))
            .expect("settings row");
        let advisory_line = block
            .lines()
            .find(|line| line.contains(advisory_msg))
            .expect("advisory row");
        assert_eq!(
            settings_line.find(settings_msg),
            advisory_line.find(advisory_msg)
        );
    }

    #[test]
    fn fixed_lines_render_one_row_per_change() {
        let applied = ApplyResult {
            written: vec![PathBuf::from("/scan/app/.npmrc")],
            skipped: vec![],
            changes: vec![
                PlannedChange {
                    project_root: PathBuf::from("/scan/app"),
                    file: PathBuf::from("/scan/app/.npmrc"),
                    setting: "ignore-scripts".into(),
                    current: "false".into(),
                    next: "true".into(),
                },
                PlannedChange {
                    project_root: PathBuf::from("/scan/app"),
                    file: PathBuf::from("/scan/app/.npmrc"),
                    setting: "audit".into(),
                    current: "(unset)".into(),
                    next: "true".into(),
                },
            ],
            blocked: None,
        };
        let block = block_applied(
            Path::new("/scan/app"),
            &[],
            true,
            Preset::Standard,
            &[],
            Some(applied),
            &plain(),
        );
        let lines: Vec<&str> = block.lines().collect();
        assert!(
            lines.contains(&"  fixed  .npmrc: ignore-scripts false -> true"),
            "{block}"
        );
        assert!(
            lines.contains(&"  fixed  .npmrc: audit (unset) -> true"),
            "{block}"
        );
    }

    #[test]
    fn audits_skipped_marker_appears_on_config_line_only_when_skipped() {
        let findings = vec![settings_finding("scripts.pin-missing", Severity::Info)];
        let skipped = block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[PathBuf::from("/scan/app/.pkguard.toml")],
            &RenderOptions {
                audits_skipped: true,
                ..plain()
            },
        );
        assert_eq!(
            skipped.lines().nth(1),
            Some("  preset standard · config .pkguard.toml · audits skipped")
        );
        let live = block(
            Path::new("/scan/app"),
            &findings,
            false,
            Preset::Standard,
            &[PathBuf::from("/scan/app/.pkguard.toml")],
            &plain(),
        );
        assert_eq!(
            live.lines().nth(1),
            Some("  preset standard · config .pkguard.toml")
        );
        assert!(!live.contains("audits skipped"));
        let clean_offline = block(
            Path::new("/scan/app"),
            &[],
            false,
            Preset::Standard,
            &[],
            &RenderOptions {
                audits_skipped: true,
                ..plain()
            },
        );
        assert_eq!(clean_offline, "ok app  preset standard · audits skipped\n");
    }

    #[test]
    fn summary_includes_settings_fixed_count() {
        let text = summary_block(
            &ScanSummary {
                projects: 1,
                incomplete: false,
                policy_failure: false,
                exit: ExitCode::Clean,
            },
            &SeverityCounts::default(),
            2,
            &plain(),
        );
        assert!(text.contains("2 settings fixed"), "{text}");
        let none = summary_block(
            &ScanSummary {
                projects: 1,
                incomplete: false,
                policy_failure: false,
                exit: ExitCode::Clean,
            },
            &SeverityCounts::default(),
            0,
            &plain(),
        );
        assert!(!none.contains("settings fixed"), "{none}");
    }
}
