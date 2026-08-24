use crate::cli::{Format, PresetArg, ScanArgs};
use pkguard_core::apply::{ApplyResult, Blocked};
use pkguard_core::exec::TokioRunner;
use pkguard_core::pipeline::{scan, AuditEvent, ScanOptions};
use pkguard_core::policy::Preset;
use serde_json::{json, Value};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PKGUARD_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    directories::ProjectDirs::from("dev", "pkguard", "pkguard")
        .map(|dirs| dirs.cache_dir().to_path_buf())
        .unwrap_or_else(|| std::env::temp_dir().join("pkguard-cache"))
}

fn user_config_path() -> Option<PathBuf> {
    crate::paths::user_config_if_present()
}

fn preset_of(arg: PresetArg) -> Preset {
    match arg {
        PresetArg::Relaxed => Preset::Relaxed,
        PresetArg::Standard => Preset::Standard,
        PresetArg::Strict => Preset::Strict,
    }
}

fn color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
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
        no_audit: args.no_audit,
        fix: args.fix,
        force: args.force,
        dry_run: args.dry_run,
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

    let mut render_opts = crate::render::RenderOptions {
        color: color_enabled(),
        audits_skipped: args.no_audit,
        ..Default::default()
    };
    let mut counts = crate::render::SeverityCounts::default();
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
                preset,
                config_sources,
                applied,
            } => {
                finished += 1;
                for finding in &findings {
                    counts.add(finding.severity);
                }
                if let Some(applied) = &applied {
                    render_opts.settings_fixed += applied.changes.len();
                    if matches!(applied.blocked, Some(Blocked::DirtyGit(_))) {
                        eprintln!("refusing to write: dirty git tree (use --force)");
                    }
                }
                if human {
                    render_opts.applied = applied;
                    let block = crate::render::project_block(
                        &root,
                        &findings,
                        incomplete,
                        preset,
                        &config_sources,
                        &render_opts,
                    );
                    if let Some(bar) = &progress {
                        bar.suspend(|| print!("{block}"));
                        bar.set_message(format!("auditing {finished}/{discovered} projects"));
                    } else {
                        print!("{block}");
                    }
                } else {
                    let mut project = json!({
                        "root": root,
                        "incomplete": incomplete,
                        "preset": preset,
                        "configSources": config_sources,
                        "findings": findings,
                    });
                    if let Some(applied) = &applied {
                        project["applied"] = applied_json(applied);
                    }
                    projects_json.push(project);
                }
            }
            AuditEvent::Done(summary) => {
                exit = summary.exit.code();
                if let Some(bar) = &progress {
                    bar.finish_and_clear();
                }
                if human {
                    print!(
                        "{}",
                        crate::render::summary_block(&summary, &counts, &render_opts)
                    );
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
