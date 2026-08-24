use crate::cli::{Format, PresetArg, ScanArgs};
use crate::report::{HumanReporter, JsonReporter, ProjectReport, Reporter};
use pkguard_core::apply::Blocked;
use pkguard_core::exec::TokioRunner;
use pkguard_core::pipeline::{scan, AuditEvent, ScanOptions};
use pkguard_core::policy::Preset;
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

    let mut reporter: Box<dyn Reporter> = if human {
        Box::new(HumanReporter::new(color_enabled(), args.no_audit))
    } else {
        Box::new(JsonReporter::new())
    };
    let mut discovered = 0usize;
    let mut finished = 0usize;
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
                if let Some(applied) = &applied {
                    if matches!(applied.blocked, Some(Blocked::DirtyGit(_))) {
                        eprintln!("refusing to write: dirty git tree (use --force)");
                    }
                }
                let report = ProjectReport {
                    root,
                    findings,
                    incomplete,
                    preset,
                    config_sources,
                    applied,
                };
                if let Some(text) = reporter.project(&report) {
                    if let Some(bar) = &progress {
                        bar.suspend(|| print!("{text}"));
                        bar.set_message(format!("auditing {finished}/{discovered} projects"));
                    } else {
                        print!("{text}");
                    }
                }
            }
            AuditEvent::Done(summary) => {
                exit = summary.exit.code();
                if let Some(bar) = &progress {
                    bar.finish_and_clear();
                }
                print!("{}", reporter.finish(&summary));
            }
        }
    }
    exit
}
