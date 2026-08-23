use crate::cli::{Format, PresetArg, ScanArgs};
use mailclad_core::exec::TokioRunner;
use mailclad_core::findings::Finding;
use mailclad_core::pipeline::{scan, AuditEvent, ScanOptions, ScanSummary};
use mailclad_core::policy::Preset;
use serde_json::json;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MAILCLAD_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    directories::ProjectDirs::from("dev", "mailclad", "mailclad")
        .map(|dirs| dirs.cache_dir().to_path_buf())
        .unwrap_or_else(|| std::env::temp_dir().join("mailclad-cache"))
}

fn user_config_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "mailclad", "mailclad")
        .map(|dirs| dirs.config_dir().join("config.toml"))
        .filter(|p| p.is_file())
}

fn preset_of(arg: PresetArg) -> Preset {
    match arg {
        PresetArg::Relaxed => Preset::Relaxed,
        PresetArg::Standard => Preset::Standard,
        PresetArg::Strict => Preset::Strict,
    }
}

fn finding_line(finding: &Finding) -> String {
    let manager = finding.manager.map(|m| m.name()).unwrap_or("-");
    let package = match (&finding.package, &finding.current_version) {
        (Some(p), Some(v)) => format!("{p}@{v}"),
        (Some(p), None) => p.clone(),
        _ => String::new(),
    };
    let fix = finding
        .fix_version
        .as_deref()
        .map(|v| format!(" -> {v}"))
        .unwrap_or_default();
    let severity = format!("{:?}", finding.severity).to_lowercase();
    format!(
        "  {manager:8} {severity:9} {code:28} {package}{fix}  {message}",
        code = finding.code,
        message = finding.message
    )
}

fn print_project(root: &std::path::Path, findings: &[Finding], incomplete: bool) {
    if findings.is_empty() && !incomplete {
        println!("ok {}", root.display());
        return;
    }
    let status = if incomplete { "incomplete" } else { "issues" };
    println!("{status} {}", root.display());
    for finding in findings {
        println!("{}", finding_line(finding));
    }
}

fn print_summary(summary: &ScanSummary) {
    println!(
        "\n{} project(s) scanned · policy {} · exit {}",
        summary.projects,
        if summary.policy_failure {
            "failed"
        } else {
            "passed"
        },
        summary.exit.code()
    );
}

pub async fn run(args: ScanArgs) -> i32 {
    let root = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let opts = ScanOptions {
        preset_override: args.preset.map(preset_of),
        jobs: args.jobs.unwrap_or(0),
        refresh: args.refresh,
        no_cache: args.no_cache,
        cache_dir: cache_dir(),
        user_config: user_config_path(),
    };

    let mut rx = scan(root, Arc::new(TokioRunner), opts);
    let human = args.format == Format::Human;
    let show_progress = human && !args.quiet && std::io::stdout().is_terminal();

    let progress = if show_progress {
        let bar = indicatif::ProgressBar::new_spinner();
        bar.set_style(indicatif::ProgressStyle::with_template("{spinner} {msg}").unwrap());
        bar.enable_steady_tick(std::time::Duration::from_millis(120));
        Some(bar)
    } else {
        None
    };

    let mut discovered = 0usize;
    let mut finished = 0usize;
    let mut projects_json = Vec::new();
    let mut exit = 0i32;

    while let Some(event) = rx.recv().await {
        match event {
            AuditEvent::ProjectDiscovered { .. } => {
                discovered += 1;
                if let Some(bar) = &progress {
                    bar.set_message(format!("auditing {finished}/{discovered} projects"));
                }
            }
            AuditEvent::ManagerFinished { .. } => {}
            AuditEvent::ProjectFinished {
                root,
                findings,
                incomplete,
            } => {
                finished += 1;
                if human {
                    if let Some(bar) = &progress {
                        bar.suspend(|| print_project(&root, &findings, incomplete));
                        bar.set_message(format!("auditing {finished}/{discovered} projects"));
                    } else {
                        print_project(&root, &findings, incomplete);
                    }
                } else {
                    projects_json.push(json!({
                        "root": root,
                        "incomplete": incomplete,
                        "findings": findings,
                    }));
                }
            }
            AuditEvent::Done(summary) => {
                exit = summary.exit.code();
                if let Some(bar) = &progress {
                    bar.finish_and_clear();
                }
                if human {
                    print_summary(&summary);
                } else {
                    let doc = json!({
                        "schemaVersion": 2,
                        "exitCode": summary.exit.code(),
                        "incomplete": summary.incomplete,
                        "policyFailure": summary.policy_failure,
                        "projects": projects_json,
                    });
                    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
                    projects_json = Vec::new();
                }
            }
        }
    }
    exit
}
