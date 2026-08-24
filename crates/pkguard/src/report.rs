//! The output seam. One finished project crosses it; two adapters render it.
//!
//! Human output streams a block per project and a summary at the end; JSON
//! accumulates every project and emits one document. Both read the same
//! `ProjectReport`, so a new field is wired in one place rather than two.

use crate::render::{self, RenderOptions, SeverityCounts};
use pkguard_core::apply::{ApplyResult, Blocked};
use pkguard_core::findings::Finding;
use pkguard_core::pipeline::ScanSummary;
use pkguard_core::policy::Preset;
use serde_json::{json, Value};
use std::path::PathBuf;

/// One project's finished audit, exactly as both formats consume it.
pub struct ProjectReport {
    pub root: PathBuf,
    pub findings: Vec<Finding>,
    pub incomplete: bool,
    pub preset: Preset,
    pub config_sources: Vec<PathBuf>,
    pub applied: Option<ApplyResult>,
}

/// Renders finished projects in one output format.
///
/// `project` returns text to emit now for formats that stream, or `None` for
/// formats that can only be written once the run is complete.
pub trait Reporter {
    fn project(&mut self, report: &ProjectReport) -> Option<String>;
    fn finish(&mut self, summary: &ScanSummary) -> String;
}

/// Streams a block per project, then a one-line summary.
pub struct HumanReporter {
    opts: RenderOptions,
    counts: SeverityCounts,
    settings_fixed: usize,
}

impl HumanReporter {
    pub fn new(color: bool, audits_skipped: bool) -> Self {
        Self {
            opts: RenderOptions {
                color,
                audits_skipped,
            },
            counts: SeverityCounts::default(),
            settings_fixed: 0,
        }
    }
}

impl Reporter for HumanReporter {
    fn project(&mut self, report: &ProjectReport) -> Option<String> {
        for finding in &report.findings {
            self.counts.add(finding.severity);
        }
        if let Some(applied) = &report.applied {
            self.settings_fixed += applied.changes.len();
        }
        Some(render::project_block(report, &self.opts))
    }

    fn finish(&mut self, summary: &ScanSummary) -> String {
        render::summary_block(summary, &self.counts, self.settings_fixed, &self.opts)
    }
}

/// Accumulates every project and emits one document at the end.
#[derive(Default)]
pub struct JsonReporter {
    projects: Vec<Value>,
}

impl JsonReporter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Reporter for JsonReporter {
    fn project(&mut self, report: &ProjectReport) -> Option<String> {
        self.projects.push(project_json(report));
        None
    }

    fn finish(&mut self, summary: &ScanSummary) -> String {
        let doc = json!({
            "schemaVersion": 2,
            "exitCode": summary.exit.code(),
            "incomplete": summary.incomplete,
            "policyFailure": summary.policy_failure,
            "projects": std::mem::take(&mut self.projects),
        });
        format!("{}\n", serde_json::to_string_pretty(&doc).unwrap())
    }
}

fn project_json(report: &ProjectReport) -> Value {
    let mut project = json!({
        "root": report.root,
        "incomplete": report.incomplete,
        "preset": report.preset,
        "configSources": report.config_sources,
        "findings": report.findings,
    });
    if let Some(applied) = &report.applied {
        project["applied"] = applied_json(applied);
    }
    project
}

fn applied_json(applied: &ApplyResult) -> Value {
    json!({
        "written": applied.written,
        "changes": applied.changes.iter().map(|change| {
            json!({
                "file": change.file,
                "setting": change.setting,
                "current": change.current,
                "next": change.next,
            })
        }).collect::<Vec<_>>(),
        "blocked": match &applied.blocked {
            Some(Blocked::DirtyGit(path)) => json!({"dirtyGit": path}),
            Some(Blocked::Nothing) => json!("nothing"),
            None => Value::Null,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkguard_core::apply::PlannedChange;
    use pkguard_core::findings::{Finding, FindingKind, Severity};
    use pkguard_core::manager::Manager;
    use pkguard_core::policy::ExitCode;
    use std::path::Path;

    fn finding(code: &str, severity: Severity) -> Finding {
        Finding {
            kind: FindingKind::Settings,
            code: code.into(),
            message: format!("{code} message"),
            severity,
            path: "/p/.npmrc".into(),
            fixable: false,
            manager: Some(Manager::Npm),
            package: None,
            current_version: None,
            fix_version: None,
            fix: None,
        }
    }

    fn report(applied: Option<ApplyResult>) -> ProjectReport {
        ProjectReport {
            root: PathBuf::from("/scan/app"),
            findings: vec![finding("scripts.enabled", Severity::High)],
            incomplete: false,
            preset: Preset::Standard,
            config_sources: vec![],
            applied,
        }
    }

    fn summary() -> ScanSummary {
        ScanSummary {
            projects: 1,
            incomplete: false,
            policy_failure: true,
            exit: ExitCode::PolicyFailure,
        }
    }

    fn change() -> PlannedChange {
        PlannedChange {
            project_root: PathBuf::from("/scan/app"),
            file: PathBuf::from("/scan/app/.npmrc"),
            setting: "ignore-scripts".into(),
            current: "(unset)".into(),
            next: "true".into(),
        }
    }

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn json_accumulates_projects_and_emits_one_document() {
        let mut reporter = JsonReporter::new();
        assert!(reporter.project(&report(None)).is_none());
        assert!(reporter.project(&report(None)).is_none());
        let doc = parse(&reporter.finish(&summary()));
        assert_eq!(doc["schemaVersion"], 2);
        assert_eq!(doc["exitCode"], 1);
        assert_eq!(doc["policyFailure"], true);
        assert_eq!(doc["projects"].as_array().unwrap().len(), 2);
        assert_eq!(doc["projects"][0]["findings"][0]["code"], "scripts.enabled");
    }

    #[test]
    fn a_project_without_a_fix_run_has_no_applied_block() {
        let mut reporter = JsonReporter::new();
        reporter.project(&report(None));
        let doc = parse(&reporter.finish(&summary()));
        assert!(doc["projects"][0].get("applied").is_none());
    }

    #[test]
    fn applied_changes_are_reported_field_by_field() {
        let applied = ApplyResult {
            written: vec![PathBuf::from("/scan/app/.npmrc")],
            skipped: vec![],
            changes: vec![change()],
            blocked: None,
        };
        let mut reporter = JsonReporter::new();
        reporter.project(&report(Some(applied)));
        let doc = parse(&reporter.finish(&summary()));
        let applied = &doc["projects"][0]["applied"];
        assert_eq!(applied["written"][0], "/scan/app/.npmrc");
        assert_eq!(applied["changes"][0]["setting"], "ignore-scripts");
        assert_eq!(applied["changes"][0]["current"], "(unset)");
        assert_eq!(applied["changes"][0]["next"], "true");
        assert_eq!(applied["blocked"], Value::Null);
    }

    #[test]
    fn each_blocked_reason_has_its_own_encoding() {
        let cases = [
            (None, Value::Null),
            (Some(Blocked::Nothing), json!("nothing")),
            (
                Some(Blocked::DirtyGit(PathBuf::from("/scan"))),
                json!({"dirtyGit": "/scan"}),
            ),
        ];
        for (blocked, expected) in cases {
            let applied = ApplyResult {
                written: vec![],
                skipped: vec![],
                changes: vec![],
                blocked,
            };
            let mut reporter = JsonReporter::new();
            reporter.project(&report(Some(applied)));
            let doc = parse(&reporter.finish(&summary()));
            assert_eq!(doc["projects"][0]["applied"]["blocked"], expected);
        }
    }

    #[test]
    fn the_document_is_reset_between_runs() {
        let mut reporter = JsonReporter::new();
        reporter.project(&report(None));
        reporter.finish(&summary());
        let doc = parse(&reporter.finish(&summary()));
        assert_eq!(doc["projects"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn human_streams_a_block_per_project() {
        let mut reporter = HumanReporter::new(false, false);
        let block = reporter.project(&report(None)).unwrap();
        assert!(block.starts_with("app  1 finding\n"), "{block}");
    }

    #[test]
    fn human_counts_severities_and_fixes_across_projects() {
        let applied = ApplyResult {
            written: vec![PathBuf::from("/scan/app/.npmrc")],
            skipped: vec![],
            changes: vec![change()],
            blocked: None,
        };
        let mut reporter = HumanReporter::new(false, false);
        reporter.project(&report(Some(applied)));
        reporter.project(&report(None));
        let line = reporter.finish(&summary());
        assert!(line.contains("2 high"), "{line}");
        assert!(line.contains("1 setting fixed"), "{line}");
        assert!(line.contains("exit 1"), "{line}");
    }

    #[test]
    fn the_root_is_only_named_once_per_project() {
        let mut reporter = HumanReporter::new(false, false);
        let block = reporter
            .project(&ProjectReport {
                findings: vec![],
                ..report(None)
            })
            .unwrap();
        assert_eq!(block, "ok app  preset standard\n");
        let _ = Path::new("/scan/app");
    }
}
