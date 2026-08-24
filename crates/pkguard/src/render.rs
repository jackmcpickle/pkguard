use crate::report::ProjectReport;
use owo_colors::{OwoColorize, Style};
use pkguard_core::findings::{Finding, Severity};
use pkguard_core::manager::Manager;
use pkguard_core::pipeline::{AuditStatus, ScanSummary};
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

    for bucket in buckets(report) {
        write_bucket(&mut out, &bucket, opts);
    }
    write_fixed_lines(&mut out, root, report, opts);
    out
}

/// One manager's slice of a project: its settings table and its advisory
/// table. Cross-manager findings (`pm.multiple-node` and friends) carry no
/// manager, so they get a bucket of their own at the top.
struct Bucket<'a> {
    label: &'a str,
    settings: Vec<&'a Finding>,
    advisories: Vec<&'a Finding>,
    /// `None` for the cross-manager bucket, which is never audited.
    audit: Option<AuditStatus>,
}

impl Bucket<'_> {
    const fn is_empty(&self) -> bool {
        self.settings.is_empty() && self.advisories.is_empty()
    }
}

/// Buckets in discovery order. A manager that somehow produced findings without
/// being in `report.managers` still gets a bucket appended, so no finding can
/// fall out of the report.
fn buckets(report: &ProjectReport) -> Vec<Bucket<'_>> {
    let mut named: Vec<Manager> = report.managers.iter().map(|m| m.manager).collect();
    for finding in &report.findings {
        if let Some(manager) = finding.manager {
            if !named.contains(&manager) {
                named.push(manager);
            }
        }
    }

    let cross = bucket_of(report, "project", None, None);
    let mut out: Vec<Bucket<'_>> = if cross.is_empty() {
        Vec::new()
    } else {
        vec![cross]
    };
    out.extend(named.into_iter().map(|manager| {
        let audit = report
            .managers
            .iter()
            .find(|m| m.manager == manager)
            .map_or(AuditStatus::Skipped, |m| m.audit);
        bucket_of(report, manager.name(), Some(manager), Some(audit))
    }));
    out
}

fn bucket_of<'a>(
    report: &'a ProjectReport,
    label: &'a str,
    manager: Option<Manager>,
    audit: Option<AuditStatus>,
) -> Bucket<'a> {
    let mine = report.findings.iter().filter(|f| f.manager == manager);
    let (mut advisories, mut settings): (Vec<&Finding>, Vec<&Finding>) =
        mine.partition(|f| f.kind.is_advisory());
    sort_findings(&mut settings);
    sort_findings(&mut advisories);
    Bucket {
        label,
        settings,
        advisories,
        audit,
    }
}

fn sort_findings(rows: &mut [&Finding]) {
    rows.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.code.cmp(&b.code)));
}

fn write_bucket(out: &mut String, bucket: &Bucket<'_>, opts: &RenderOptions) {
    // The cross-manager bucket has no advisories to speak of; printing an empty
    // advisory table under it would invite the reader to look for one.
    let Some(audit) = bucket.audit else {
        write_table(
            out,
            bucket.label,
            "settings",
            &bucket.settings,
            SETTINGS_COLUMNS,
            "none",
            opts,
        );
        return;
    };
    write_table(
        out,
        bucket.label,
        "settings",
        &bucket.settings,
        SETTINGS_COLUMNS,
        "none",
        opts,
    );
    write_table(
        out,
        bucket.label,
        "advisories",
        &bucket.advisories,
        ADVISORY_COLUMNS,
        audit.empty_label(),
        opts,
    );
}

/// Settings findings always target the config file named in the group header,
/// so they have no package column to fill.
const SETTINGS_COLUMNS: &[Column] = &[Column::Severity, Column::Code, Column::Detail];
const ADVISORY_COLUMNS: &[Column] = &[
    Column::Severity,
    Column::Code,
    Column::Package,
    Column::Detail,
];

#[derive(Clone, Copy)]
enum Column {
    Severity,
    Code,
    Package,
    Detail,
}

impl Column {
    const fn heading(self) -> &'static str {
        match self {
            Self::Severity => "SEVERITY",
            Self::Code => "CODE",
            Self::Package => "PACKAGE",
            Self::Detail => "DETAIL",
        }
    }

    fn cell(self, finding: &Finding) -> String {
        match self {
            Self::Severity => finding.severity.as_str().to_string(),
            Self::Code => finding.code.clone(),
            Self::Package => package_cell(finding),
            Self::Detail => finding.message.clone(),
        }
    }
}

/// A titled table with a header row, its own column widths, and an explicit
/// empty state. Widths are per-table so a column of long GHSA ids cannot
/// stretch the settings table sitting above it.
fn write_table(
    out: &mut String,
    label: &str,
    kind: &str,
    findings: &[&Finding],
    columns: &[Column],
    empty_label: &str,
    opts: &RenderOptions,
) {
    let title = format!("{label} · {kind} ({})", findings.len());
    let _ = writeln!(out, "\n  {}", paint(&title, Style::new().bold(), opts));
    if findings.is_empty() {
        let _ = writeln!(out, "  {}", paint(empty_label, Style::new().dimmed(), opts));
        return;
    }

    let rows: Vec<Vec<String>> = findings
        .iter()
        .map(|f| columns.iter().map(|c| c.cell(f)).collect())
        .collect();
    // The last column is never padded, so it is left out of the width scan.
    let widths: Vec<usize> = (0..columns.len().saturating_sub(1))
        .map(|i| {
            rows.iter()
                .map(|row| row[i].len())
                .chain(std::iter::once(columns[i].heading().len()))
                .max()
                .unwrap_or(0)
        })
        .collect();

    let headings: Vec<String> = columns
        .iter()
        .enumerate()
        .map(|(i, column)| pad(column.heading(), widths.get(i).copied()))
        .collect();
    let _ = writeln!(
        out,
        "  {}",
        paint(headings.join("  ").trim_end(), Style::new().dimmed(), opts)
    );

    for (row, finding) in rows.iter().zip(findings.iter()) {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            let padded = pad(cell, widths.get(i).copied());
            if i == 0 {
                line.push_str(&paint(&padded, severity_style(finding.severity), opts));
            } else {
                line.push_str(&padded);
            }
        }
        let _ = writeln!(out, "  {line}");
        write_detail_line(out, finding, &widths, opts);
    }
}

fn pad(cell: &str, width: Option<usize>) -> String {
    width.map_or_else(|| cell.to_string(), |w| format!("{cell:<w$}"))
}

/// The raw upstream detail, indented to line up under the final column so it
/// reads as a continuation of the row rather than a row of its own.
fn write_detail_line(out: &mut String, finding: &Finding, widths: &[usize], opts: &RenderOptions) {
    let Some(detail) = &finding.detail else {
        return;
    };
    // Two leading spaces, then each padded column plus its two-space gap.
    let indent = 2 + widths.iter().map(|w| w + 2).sum::<usize>();
    let _ = writeln!(
        out,
        "{:indent$}{}",
        "",
        paint(detail, Style::new().dimmed(), opts)
    );
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
    use pkguard_core::pipeline::{ManagerOutcome, ScanSummary};
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
            detail: None,
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
                managers: vec![audited(Manager::Npm)],
                incomplete,
                preset,
                config_sources: config_sources.to_vec(),
                applied,
            },
            opts,
        )
    }

    const fn audited(manager: Manager) -> ManagerOutcome {
        ManagerOutcome {
            manager,
            audit: AuditStatus::Audited,
        }
    }

    /// A block over an explicit manager list, for the multi-manager and
    /// empty-state cases.
    fn block_managers(findings: &[Finding], managers: Vec<ManagerOutcome>) -> String {
        project_block(
            &ProjectReport {
                root: PathBuf::from("/scan/app"),
                findings: findings.to_vec(),
                managers,
                incomplete: false,
                preset: Preset::Standard,
                config_sources: vec![],
                applied: None,
            },
            &plain(),
        )
    }

    fn for_manager(mut finding: Finding, manager: Manager) -> Finding {
        finding.manager = Some(manager);
        finding
    }

    #[test]
    fn project_block_renders_header_config_line_and_aligned_columns() {
        let findings = vec![
            finding("GHSA-v7", Severity::High, Some("left-pad"), Some("1.3.0")),
            finding("GHSA-zz", Severity::Info, None, None),
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
        assert!(
            lines.contains(&"  SEVERITY  CODE     PACKAGE                  DETAIL"),
            "{block}"
        );
        assert!(
            lines.contains(&"  high      GHSA-v7  left-pad@1.0.0 -> 1.3.0  GHSA-v7 message"),
            "{block}"
        );
        assert!(
            lines.contains(&"  info      GHSA-zz  -                        GHSA-zz message"),
            "{block}"
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
    fn a_manager_gets_a_settings_table_then_an_advisories_table() {
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
                "",
                "  npm · settings (1)",
                "  SEVERITY  CODE                 DETAIL",
                "  info      scripts.pin-missing  scripts.pin-missing message",
                "",
                "  npm · advisories (1)",
                "  SEVERITY  CODE     PACKAGE                  DETAIL",
                "  high      GHSA-v7  left-pad@1.0.0 -> 1.3.0  GHSA-v7 message",
            ]
        );
    }

    /// Both tables render even when one of them is empty, so "nothing found"
    /// can never be mistaken for "nothing looked at".
    #[test]
    fn an_empty_table_still_renders_with_a_count_and_an_empty_state() {
        let findings = vec![settings_finding("scripts.pin-missing", Severity::Info)];
        let block = block_managers(&findings, vec![audited(Manager::Npm)]);
        let lines: Vec<&str> = block.lines().collect();
        assert!(lines.contains(&"  npm · advisories (0)"), "{block}");
        assert!(lines.contains(&"  none"), "{block}");
    }

    #[test]
    fn an_unaudited_manager_says_so_instead_of_claiming_none() {
        let block = block_managers(
            &[settings_finding("scripts.pin-missing", Severity::Info)],
            vec![ManagerOutcome {
                manager: Manager::Npm,
                audit: AuditStatus::Skipped,
            }],
        );
        assert!(block.contains("  not audited"), "{block}");
        assert!(!block.contains("\n  none\n"), "{block}");
    }

    #[test]
    fn a_failed_audit_says_so_instead_of_claiming_none() {
        let block = block_managers(
            &[settings_finding("scripts.pin-missing", Severity::Info)],
            vec![ManagerOutcome {
                manager: Manager::Npm,
                audit: AuditStatus::Incomplete,
            }],
        );
        assert!(block.contains("  audit incomplete"), "{block}");
    }

    #[test]
    fn each_manager_in_a_project_gets_its_own_pair_of_tables() {
        let findings = vec![
            for_manager(
                settings_finding("registry.unpinned", Severity::Info),
                Manager::Npm,
            ),
            for_manager(
                finding("GHSA-v7", Severity::High, Some("left-pad"), None),
                Manager::Bun,
            ),
        ];
        let block = block_managers(
            &findings,
            vec![audited(Manager::Npm), audited(Manager::Bun)],
        );
        let lines: Vec<&str> = block.lines().collect();
        for expected in [
            "  npm · settings (1)",
            "  npm · advisories (0)",
            "  bun · settings (0)",
            "  bun · advisories (1)",
        ] {
            assert!(lines.contains(&expected), "missing {expected}: {block}");
        }
        // npm's tables come first because it was detected first.
        assert!(block.find("npm · settings").unwrap() < block.find("bun · settings").unwrap());
    }

    /// A cross-manager finding carries no manager, so it must not be filed
    /// under whichever manager happens to be listed first.
    #[test]
    fn cross_manager_findings_get_their_own_leading_table() {
        let mut multiple = settings_finding("pm.multiple-node", Severity::High);
        multiple.manager = None;
        let block = block_managers(&[multiple], vec![audited(Manager::Npm)]);
        let lines: Vec<&str> = block.lines().collect();
        assert!(lines.contains(&"  project · settings (1)"), "{block}");
        assert!(lines.contains(&"  npm · settings (0)"), "{block}");
        assert!(block.find("project · settings").unwrap() < block.find("npm · settings").unwrap());
    }

    #[test]
    fn the_raw_upstream_detail_renders_under_its_row() {
        let mut advisory = finding("GHSA-v7", Severity::High, Some("left-pad"), None);
        advisory.detail = Some("vulnerable <1.3.0".into());
        let block = block_managers(&[advisory], vec![audited(Manager::Npm)]);
        let row = block
            .lines()
            .find(|line| line.contains("GHSA-v7 message"))
            .unwrap();
        let detail = block
            .lines()
            .find(|line| line.contains("vulnerable <1.3.0"))
            .unwrap();
        // The continuation lines up under the final column of its row.
        assert_eq!(
            detail.find("vulnerable"),
            row.find("GHSA-v7 message"),
            "row: {row:?}, detail: {detail:?}"
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
