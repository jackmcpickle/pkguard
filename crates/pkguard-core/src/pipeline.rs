use crate::advisories::{run_manager_advisories, AdvisoryOptions};
use crate::apply::ApplyResult;
use crate::cache::AdvisoryCache;
use crate::clock::{Clock, SystemClock};
use crate::config::{layer_configs, parse_config, resolve_settings, ConfigFile};
use crate::discover::{discover_projects, Project, Role};
use crate::exec::CommandRunner;
use crate::findings::{Finding, FindingKind, Severity};
use crate::manager::Manager;
use crate::policy::{exit_code_for, fails_gate, ExitCode, Preset};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};

#[derive(Debug, Clone)]
pub enum AuditEvent {
    ProjectDiscovered {
        root: PathBuf,
    },
    ManagerFinished {
        root: PathBuf,
        manager: Manager,
        findings: Vec<Finding>,
        from_cache: bool,
        incomplete: bool,
    },
    ProjectFinished {
        root: PathBuf,
        findings: Vec<Finding>,
        incomplete: bool,
        preset: Preset,
        /// Config files that were actually layered for this project, in
        /// application order (user < scan-root < per-repo).
        config_sources: Vec<PathBuf>,
        applied: Option<ApplyResult>,
    },
    Done(ScanSummary),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    pub projects: usize,
    pub incomplete: bool,
    pub policy_failure: bool,
    pub exit: ExitCode,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub preset_override: Option<Preset>,
    pub jobs: usize,
    pub refresh: bool,
    pub no_cache: bool,
    pub cache_dir: PathBuf,
    pub user_config: Option<PathBuf>,
    pub no_audit: bool,
    pub fix: bool,
    pub force: bool,
    pub dry_run: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            preset_override: None,
            jobs: 0,
            refresh: false,
            no_cache: false,
            cache_dir: std::env::temp_dir().join("pkguard-cache"),
            user_config: None,
            no_audit: false,
            fix: false,
            force: false,
            dry_run: false,
        }
    }
}

pub fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() * 2).min(16))
        .unwrap_or(8)
}

fn read_config(path: &Path) -> Option<ConfigFile> {
    let raw = std::fs::read_to_string(path).ok()?;
    parse_config(&raw).ok()
}

fn missing_binary_finding(project_root: &Path, manager: Manager, binary: &str) -> Finding {
    Finding {
        kind: FindingKind::MissingBinary,
        code: "pm.missing-binary".into(),
        message: format!("{binary} binary not found on PATH; live audit skipped"),
        severity: Severity::Info,
        path: project_root.to_string_lossy().into_owned(),
        fixable: false,
        manager: Some(manager),
        package: None,
        current_version: None,
        fix_version: None,
        fix: None,
    }
}

struct ProjectResult {
    findings: Vec<Finding>,
    incomplete: bool,
    preset: Preset,
    config_sources: Vec<PathBuf>,
    applied: Option<ApplyResult>,
}

/// Everything a project audit needs that is the same for every project in the
/// run. Threading these one by one made the call an eight-argument list.
struct RunContext<'a> {
    base_config: &'a ConfigFile,
    base_sources: &'a [PathBuf],
    runner: &'a dyn CommandRunner,
    cache: &'a AdvisoryCache,
    opts: &'a ScanOptions,
    clock: &'a dyn Clock,
}

async fn audit_project(
    project: &Project,
    ctx: &RunContext<'_>,
    events: &mpsc::UnboundedSender<AuditEvent>,
) -> ProjectResult {
    let RunContext {
        base_config,
        base_sources,
        runner,
        cache,
        opts,
        clock,
    } = *ctx;
    let mut config_sources = base_sources.to_vec();
    let mut layers: Vec<ConfigFile> = vec![base_config.clone()];
    let repo_config_path = project.root.join(".pkguard.toml");
    if let Some(repo_cfg) = read_config(&repo_config_path) {
        layers.push(repo_cfg);
        config_sources.push(repo_config_path);
    }
    let mut config = layer_configs(layers.iter());
    if let Some(preset) = opts.preset_override {
        config.preset = Some(preset);
    }

    let mut findings = collect_settings_findings(project, &config, clock);
    let mut incomplete = false;
    let advisory_opts = AdvisoryOptions {
        refresh: opts.refresh,
        no_cache: opts.no_cache,
    };

    let applied = if opts.fix {
        let plan = crate::apply::plan_fixes(project, &findings);
        let mode = if opts.dry_run {
            crate::apply::ApplyMode::DryRun
        } else {
            crate::apply::ApplyMode::Write
        };
        let result = crate::apply::apply_fixes(project, &plan, runner, opts.force, mode).await;
        if !opts.dry_run {
            // Fixed settings must stop being reported, so re-read them.
            findings = collect_settings_findings(project, &config, clock);
        }
        Some(result)
    } else {
        None
    };

    let audits_on = !opts.no_audit && config.audit.unwrap_or(true);
    if audits_on {
        for manager in &project.managers {
            // Live advisory audits run for ported primaries only. Leftover and
            // unsupported managers still contribute the settings finding above.
            if manager.role != Role::Primary || !manager.manager.ported() {
                continue;
            }
            let binary = manager.manager.binary().unwrap_or_default();
            if !runner.which(binary) {
                let finding = missing_binary_finding(&project.root, manager.manager, binary);
                findings.push(finding.clone());
                let _ = events.send(AuditEvent::ManagerFinished {
                    root: project.root.clone(),
                    manager: manager.manager,
                    findings: vec![finding],
                    from_cache: false,
                    incomplete: false,
                });
                continue;
            }
            match run_manager_advisories(&project.root, manager, runner, cache, &advisory_opts)
                .await
            {
                Ok(outcome) => {
                    findings.extend(outcome.findings.clone());
                    let _ = events.send(AuditEvent::ManagerFinished {
                        root: project.root.clone(),
                        manager: manager.manager,
                        findings: outcome.findings,
                        from_cache: outcome.from_cache,
                        incomplete: false,
                    });
                }
                Err(_) => {
                    incomplete = true;
                    let _ = events.send(AuditEvent::ManagerFinished {
                        root: project.root.clone(),
                        manager: manager.manager,
                        findings: Vec::new(),
                        from_cache: false,
                        incomplete: true,
                    });
                }
            }
        }
    }

    ProjectResult {
        findings,
        incomplete,
        preset: config.preset.unwrap_or(Preset::Standard),
        config_sources,
        applied,
    }
}

fn collect_settings_findings(
    project: &Project,
    config: &ConfigFile,
    clock: &dyn Clock,
) -> Vec<Finding> {
    let mut findings = crate::settings::checks::multiple_pm_findings(project);
    for manager in &project.managers {
        let settings = resolve_settings(config, manager.manager.name());
        findings.extend(crate::settings::audit_manager_settings(
            &project.root,
            manager,
            &settings,
            clock,
        ));
    }
    findings
}

/// Streams `AuditEvent`s for a scan of `root`; the channel closes after `Done`.
pub fn scan(
    root: PathBuf,
    runner: Arc<dyn CommandRunner>,
    opts: ScanOptions,
) -> mpsc::UnboundedReceiver<AuditEvent> {
    scan_with_clock(root, runner, opts, Arc::new(SystemClock))
}

/// `scan` against a chosen clock. Only uv's `exclude-newer` date check and the
/// advisory cache TTL consult it.
pub fn scan_with_clock(
    root: PathBuf,
    runner: Arc<dyn CommandRunner>,
    opts: ScanOptions,
    clock: Arc<dyn Clock>,
) -> mpsc::UnboundedReceiver<AuditEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut base_layers = Vec::new();
        let mut base_sources: Vec<PathBuf> = Vec::new();
        if let Some(user_path) = opts.user_config.as_deref() {
            if let Some(user) = read_config(user_path) {
                base_layers.push(user);
                base_sources.push(user_path.to_path_buf());
            }
        }
        let scan_root_path = root.join(".pkguard.toml");
        if let Some(scan_root) = read_config(&scan_root_path) {
            base_layers.push(scan_root);
            base_sources.push(scan_root_path);
        }
        let base_config = layer_configs(base_layers.iter());

        let discovery_root = root.clone();
        let projects = tokio::task::spawn_blocking(move || {
            let mut projects = Vec::new();
            discover_projects(&discovery_root, &mut |p| projects.push(p));
            projects
        })
        .await
        .unwrap_or_default();

        let jobs = if opts.jobs == 0 {
            default_jobs()
        } else {
            opts.jobs
        };
        let semaphore = Arc::new(Semaphore::new(jobs));
        let cache =
            Arc::new(AdvisoryCache::new(opts.cache_dir.clone()).with_clock(Arc::clone(&clock)));
        let opts = Arc::new(opts);
        let base_config = Arc::new(base_config);
        let base_sources = Arc::new(base_sources);

        let mut handles = Vec::new();
        for project in projects {
            let _ = tx.send(AuditEvent::ProjectDiscovered {
                root: project.root.clone(),
            });
            let tx = tx.clone();
            let runner = Arc::clone(&runner);
            let cache = Arc::clone(&cache);
            let opts = Arc::clone(&opts);
            let base_config = Arc::clone(&base_config);
            let base_sources = Arc::clone(&base_sources);
            let semaphore = Arc::clone(&semaphore);
            let clock = Arc::clone(&clock);
            handles.push(tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await.unwrap();
                let ctx = RunContext {
                    base_config: &base_config,
                    base_sources: &base_sources,
                    runner: runner.as_ref(),
                    cache: &cache,
                    opts: &opts,
                    clock: clock.as_ref(),
                };
                let result = audit_project(&project, &ctx, &tx).await;
                let _ = tx.send(AuditEvent::ProjectFinished {
                    root: project.root.clone(),
                    findings: result.findings.clone(),
                    incomplete: result.incomplete,
                    preset: result.preset,
                    config_sources: result.config_sources.clone(),
                    applied: result.applied.clone(),
                });
                result
            }));
        }

        let mut projects_count = 0usize;
        let mut incomplete = false;
        let mut policy_failure = false;
        for handle in handles {
            if let Ok(result) = handle.await {
                projects_count += 1;
                incomplete |= result.incomplete;
                let gate = result.preset.gate();
                policy_failure |= result
                    .findings
                    .iter()
                    .any(|f| fails_gate(f.kind, f.severity, gate));
            }
        }

        let exit = exit_code_for(projects_count, incomplete, false, policy_failure);
        let _ = tx.send(AuditEvent::Done(ScanSummary {
            projects: projects_count,
            incomplete,
            policy_failure,
            exit,
        }));
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{CannedRunner, CommandOutput};
    use crate::policy::ExitCode;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    const NPM_HIGH: &str = r#"{
        "auditReportVersion": 2,
        "vulnerabilities": {
            "left-pad": {
                "name": "left-pad",
                "severity": "high",
                "fixAvailable": {"name": "left-pad", "version": "1.3.0"},
                "via": [{"github_advisory_id": "GHSA-v7", "severity": "high", "title": "t", "version": "1.0.0"}]
            }
        }
    }"#;

    const NPM_CLEAN: &str = r#"{"auditReportVersion": 2, "vulnerabilities": {}}"#;

    fn npm_repo(root: &Path, name: &str) {
        let dir = root.join(name);
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join("package.json"), "{}").unwrap();
        fs::write(dir.join("package-lock.json"), format!("lock-{name}")).unwrap();
    }

    /// Settings-compliant npm repo: no settings findings under standard preset.
    fn compliant_npm_repo(root: &Path, name: &str) {
        npm_repo(root, name);
        let dir = root.join(name);
        fs::write(
            dir.join("package.json"),
            r#"{"packageManager": "npm@11.0.0"}"#,
        )
        .unwrap();
        fs::write(
            dir.join(".npmrc"),
            "ignore-scripts=true\nallow-scripts-pin=true\naudit=true\nmin-release-age=1\nregistry=https://registry.npmjs.org/\n",
        )
        .unwrap();
    }

    async fn run_scan(root: &Path, runner: CannedRunner) -> Vec<AuditEvent> {
        let opts = ScanOptions {
            cache_dir: root.join(".cache-test"),
            ..ScanOptions::default()
        };
        let mut events = Vec::new();
        let mut rx = scan(root.to_path_buf(), Arc::new(runner), opts);
        while let Some(event) = rx.recv().await {
            events.push(event);
        }
        events
    }

    fn summary(events: &[AuditEvent]) -> &ScanSummary {
        match events.last().unwrap() {
            AuditEvent::Done(s) => s,
            other => panic!("expected Done last, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn scans_two_repos_and_streams_events() {
        let tmp = tempfile::tempdir().unwrap();
        compliant_npm_repo(tmp.path(), "a");
        compliant_npm_repo(tmp.path(), "b");
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 1,
                stdout: NPM_HIGH.into(),
                stderr: String::new(),
            },
        );

        let events = run_scan(tmp.path(), runner).await;
        let finished: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { root, findings, .. } => {
                    Some((root.clone(), findings.len()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(finished.len(), 2);
        assert!(finished.iter().all(|(_, n)| *n == 1));

        let s = summary(&events);
        assert_eq!(s.projects, 2);
        // high finding vs standard preset (gate = high) => policy failure
        assert_eq!(s.exit, ExitCode::PolicyFailure);
    }

    #[tokio::test]
    async fn bare_repo_settings_findings_fail_the_standard_gate() {
        let tmp = tempfile::tempdir().unwrap();
        npm_repo(tmp.path(), "a");
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 0,
                stdout: NPM_CLEAN.into(),
                stderr: String::new(),
            },
        );
        let events = run_scan(tmp.path(), runner).await;
        // scripts.unrestricted (high) trips the standard gate
        assert_eq!(summary(&events).exit, ExitCode::PolicyFailure);
        let findings: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { findings, .. } => {
                    Some(findings.iter().map(|f| f.code.clone()).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert!(findings.contains(&"scripts.unrestricted".to_string()));
        assert!(findings.contains(&"audit.disabled".to_string()));
    }

    #[tokio::test]
    async fn clean_scan_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        compliant_npm_repo(tmp.path(), "a");
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 0,
                stdout: NPM_CLEAN.into(),
                stderr: String::new(),
            },
        );
        let events = run_scan(tmp.path(), runner).await;
        assert_eq!(summary(&events).exit, ExitCode::Clean);
    }

    #[tokio::test]
    async fn no_projects_exits_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let events = run_scan(tmp.path(), CannedRunner::new()).await;
        let s = summary(&events);
        assert_eq!(s.projects, 0);
        assert_eq!(s.exit, ExitCode::Incomplete);
    }

    #[tokio::test]
    async fn missing_binary_yields_info_finding_and_settings_still_run() {
        let tmp = tempfile::tempdir().unwrap();
        compliant_npm_repo(tmp.path(), "a");
        // CannedRunner "which" knows only binaries with canned argvs: none here
        let events = run_scan(tmp.path(), CannedRunner::new()).await;
        let s = summary(&events);
        // missing-binary never fails the gate; compliant settings are clean
        assert_eq!(s.exit, ExitCode::Clean);
        let findings: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { findings, .. } => Some(findings.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "pm.missing-binary");
    }

    #[tokio::test]
    async fn per_repo_config_overrides_preset() {
        let tmp = tempfile::tempdir().unwrap();
        npm_repo(tmp.path(), "a");
        // relax repo "a" so its high finding no longer fails the gate
        fs::write(tmp.path().join("a/.pkguard.toml"), "preset = \"relaxed\"").unwrap();
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 1,
                stdout: NPM_HIGH.into(),
                stderr: String::new(),
            },
        );
        let events = run_scan(tmp.path(), runner).await;
        assert_eq!(summary(&events).exit, ExitCode::Clean);
    }

    #[tokio::test]
    async fn project_finished_reports_preset_and_config_sources() {
        let tmp = tempfile::tempdir().unwrap();
        npm_repo(tmp.path(), "a");
        fs::write(tmp.path().join("a/.pkguard.toml"), "preset = \"relaxed\"").unwrap();
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 0,
                stdout: NPM_CLEAN.into(),
                stderr: String::new(),
            },
        );
        let events = run_scan(tmp.path(), runner).await;
        let (preset, sources) = events
            .iter()
            .find_map(|e| match e {
                AuditEvent::ProjectFinished {
                    preset,
                    config_sources,
                    ..
                } => Some((*preset, config_sources.clone())),
                _ => None,
            })
            .unwrap();
        assert_eq!(preset, Preset::Relaxed);
        assert_eq!(sources, vec![tmp.path().join("a/.pkguard.toml")]);
    }

    fn compliant_pnpm_repo(root: &Path, name: &str) {
        let dir = root.join(name);
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{"packageManager": "pnpm@11.7.0"}"#,
        )
        .unwrap();
        fs::write(dir.join("pnpm-lock.yaml"), format!("lock-{name}")).unwrap();
        fs::write(
            dir.join("pnpm-workspace.yaml"),
            "allowBuilds:\n  esbuild: false\nminimumReleaseAge: 1440\nminimumReleaseAgeStrict: true\nminimumReleaseAgeIgnoreMissingTime: false\nblockExoticSubdeps: true\nstrictDepBuilds: true\naudit:\n  level: high\ntrustPolicyIgnoreAfter: 129600\ntrustPolicy: no-downgrade\nverifyDepsBeforeRun: error\nregistry: https://registry.npmjs.org/\n",
        )
        .unwrap();
    }

    const PNPM_HIGH: &str = r#"{
        "advisories": {
            "1": {
                "findings": [{"version": "1.0.0"}],
                "fixAvailable": {"name": "left-pad", "version": "1.3.0"},
                "github_advisory_id": "GHSA-pnpm",
                "module_name": "left-pad",
                "severity": "high",
                "title": "pnpm high advisory"
            }
        }
    }"#;

    #[tokio::test]
    async fn scans_pnpm_settings_and_live_audit() {
        let tmp = tempfile::tempdir().unwrap();
        compliant_pnpm_repo(tmp.path(), "app");
        let runner = CannedRunner::new().with(
            &["pnpm", "audit", "--json"],
            CommandOutput {
                code: 1,
                stdout: PNPM_HIGH.into(),
                stderr: String::new(),
            },
        );
        let events = run_scan(tmp.path(), runner).await;
        let findings: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { findings, .. } => {
                    Some(findings.iter().map(|f| f.code.clone()).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            findings.contains(&"GHSA-pnpm".to_string()),
            "findings: {findings:?}"
        );
        assert_eq!(summary(&events).exit, ExitCode::PolicyFailure);
    }

    #[tokio::test]
    async fn leftover_npm_beside_pnpm_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        compliant_pnpm_repo(tmp.path(), "app");
        fs::write(tmp.path().join("app/package-lock.json"), "leftover").unwrap();
        let runner = CannedRunner::new().with(
            &["pnpm", "audit", "--json"],
            CommandOutput {
                code: 0,
                stdout: r#"{"advisories":{}}"#.into(),
                stderr: String::new(),
            },
        );
        let events = run_scan(tmp.path(), runner).await;
        let findings: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { findings, .. } => {
                    Some(findings.iter().map(|f| f.code.clone()).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            findings.contains(&"lockfile.leftover".to_string()),
            "findings: {findings:?}"
        );
        assert_eq!(summary(&events).exit, ExitCode::PolicyFailure);
    }

    fn compliant_yarn_repo(root: &Path, name: &str) {
        let dir = root.join(name);
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{"packageManager": "yarn@4.14.0"}"#,
        )
        .unwrap();
        fs::write(dir.join("yarn.lock"), format!("lock-{name}")).unwrap();
        fs::write(
            dir.join(".yarnrc.yml"),
            "enableScripts: false\napprovedGitRepositories: []\nnpmRegistryServer: https://registry.npmjs.org/\n",
        )
        .unwrap();
    }

    const YARN_HIGH: &str = r#"{"value":"left-pad","children":{"ID":"GHSA-yarn","Severity":"high","Issue":"yarn high advisory","Tree Versions":["1.0.0"]}}"#;

    #[tokio::test]
    async fn scans_yarn_settings_and_live_audit() {
        let tmp = tempfile::tempdir().unwrap();
        compliant_yarn_repo(tmp.path(), "app");
        let runner = CannedRunner::new().with(
            &["yarn", "npm", "audit", "--json"],
            CommandOutput {
                code: 1,
                stdout: YARN_HIGH.into(),
                stderr: String::new(),
            },
        );
        let events = run_scan(tmp.path(), runner).await;
        let findings: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { findings, .. } => {
                    Some(findings.iter().map(|f| f.code.clone()).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            findings.contains(&"GHSA-yarn".to_string()),
            "findings: {findings:?}"
        );
        assert_eq!(summary(&events).exit, ExitCode::PolicyFailure);
    }

    fn compliant_cargo_repo(root: &Path, name: &str) {
        let dir = root.join(name);
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::create_dir_all(dir.join(".cargo")).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(dir.join("Cargo.lock"), format!("lock-{name}")).unwrap();
        fs::write(
            dir.join(".cargo/config.toml"),
            "[install]\nminimum-release-age = 1440\n",
        )
        .unwrap();
    }

    const CARGO_HIGH: &str = r#"{"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-2024-0001","title":"cargo issue","package":"foo"},"severity":"high"}]}}"#;

    #[tokio::test]
    async fn scans_cargo_settings_and_live_audit() {
        let tmp = tempfile::tempdir().unwrap();
        compliant_cargo_repo(tmp.path(), "app");
        let runner = CannedRunner::new().with(
            &["cargo", "audit", "--json"],
            CommandOutput {
                code: 1,
                stdout: CARGO_HIGH.into(),
                stderr: String::new(),
            },
        );
        let events = run_scan(tmp.path(), runner).await;
        let findings: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { findings, .. } => {
                    Some(findings.iter().map(|f| f.code.clone()).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            findings.contains(&"RUSTSEC-2024-0001".to_string()),
            "findings: {findings:?}"
        );
        assert_eq!(summary(&events).exit, ExitCode::PolicyFailure);
    }

    #[tokio::test]
    async fn poetry_reports_python_not_uv() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("app");
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(
            dir.join("pyproject.toml"),
            "[tool.poetry]\nname = \"app\"\n",
        )
        .unwrap();
        fs::write(dir.join("poetry.lock"), "").unwrap();
        let events = run_scan(tmp.path(), CannedRunner::new()).await;
        let findings: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { findings, .. } => {
                    Some(findings.iter().map(|f| f.code.clone()).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            findings.contains(&"python.not-uv".to_string()),
            "findings: {findings:?}"
        );
        assert_eq!(summary(&events).exit, ExitCode::PolicyFailure);
    }

    async fn run_scan_opts(
        root: &Path,
        runner: CannedRunner,
        opts: ScanOptions,
    ) -> Vec<AuditEvent> {
        let mut events = Vec::new();
        let mut rx = scan(root.to_path_buf(), Arc::new(runner), opts);
        while let Some(event) = rx.recv().await {
            events.push(event);
        }
        events
    }

    fn scan_opts(root: &Path) -> ScanOptions {
        ScanOptions {
            cache_dir: root.join(".cache-test"),
            ..ScanOptions::default()
        }
    }

    fn finished_findings(events: &[AuditEvent]) -> Vec<Finding> {
        events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::ProjectFinished { findings, .. } => Some(findings.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn finished_codes(events: &[AuditEvent]) -> Vec<String> {
        finished_findings(events)
            .iter()
            .map(|f| f.code.clone())
            .collect()
    }

    fn finished_applied(events: &[AuditEvent]) -> Option<crate::apply::ApplyResult> {
        events.iter().find_map(|e| match e {
            AuditEvent::ProjectFinished { applied, .. } => applied.clone(),
            _ => None,
        })
    }

    /// Lockfile + script/audit/min-age pins, but no registry and no packageManager.
    /// Settings findings are info-only under standard, so a clean offline scan exits 0.
    fn info_settings_npm_repo(root: &Path, name: &str) {
        npm_repo(root, name);
        fs::write(
            root.join(name).join(".npmrc"),
            "ignore-scripts=true\nallow-scripts-pin=true\naudit=true\nmin-release-age=1\n",
        )
        .unwrap();
    }

    fn high_audit_runner() -> CannedRunner {
        CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 1,
                stdout: NPM_HIGH.into(),
                stderr: String::new(),
            },
        )
    }

    #[tokio::test]
    async fn no_audit_skips_advisories_and_keeps_settings() {
        let tmp = tempfile::tempdir().unwrap();
        info_settings_npm_repo(tmp.path(), "a");
        let events = run_scan_opts(
            tmp.path(),
            high_audit_runner(),
            ScanOptions {
                no_audit: true,
                ..scan_opts(tmp.path())
            },
        )
        .await;
        let codes = finished_codes(&events);
        assert!(
            codes
                .iter()
                .any(|c| c == "registry.unpinned" || c == "pm.unpinned"),
            "settings findings present: {codes:?}"
        );
        assert!(
            !codes.iter().any(|c| c.starts_with("GHSA-")),
            "advisory leaked into an offline scan: {codes:?}"
        );
        assert!(!summary(&events).incomplete);
        assert_eq!(summary(&events).exit, ExitCode::Clean);
    }

    #[tokio::test]
    async fn no_audit_does_not_emit_missing_binary_or_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        compliant_npm_repo(tmp.path(), "a");
        let events = run_scan_opts(
            tmp.path(),
            CannedRunner::new(),
            ScanOptions {
                no_audit: true,
                ..scan_opts(tmp.path())
            },
        )
        .await;
        let codes = finished_codes(&events);
        assert!(
            !codes.iter().any(|c| c == "pm.missing-binary"),
            "offline scan must not require the binary: {codes:?}"
        );
        assert!(!summary(&events).incomplete);
        assert_eq!(summary(&events).exit, ExitCode::Clean);
    }

    #[tokio::test]
    async fn no_audit_never_invokes_the_runner() {
        let tmp = tempfile::tempdir().unwrap();
        info_settings_npm_repo(tmp.path(), "a");
        let runner = high_audit_runner();
        let probe = runner.clone();
        run_scan_opts(
            tmp.path(),
            runner,
            ScanOptions {
                no_audit: true,
                ..scan_opts(tmp.path())
            },
        )
        .await;
        assert_eq!(probe.run_calls(), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn audit_false_in_repo_config_skips_live_audits() {
        let tmp = tempfile::tempdir().unwrap();
        info_settings_npm_repo(tmp.path(), "a");
        fs::write(tmp.path().join("a/.pkguard.toml"), "audit = false\n").unwrap();
        let events = run_scan_opts(tmp.path(), high_audit_runner(), scan_opts(tmp.path())).await;
        let codes = finished_codes(&events);
        assert!(
            !codes.iter().any(|c| c.starts_with("GHSA-")),
            "config audit=false still ran an audit: {codes:?}"
        );
        assert_eq!(summary(&events).exit, ExitCode::Clean);
    }

    #[tokio::test]
    async fn no_audit_flag_overrides_audit_true_in_config() {
        let tmp = tempfile::tempdir().unwrap();
        info_settings_npm_repo(tmp.path(), "a");
        fs::write(tmp.path().join("a/.pkguard.toml"), "audit = true\n").unwrap();
        let events = run_scan_opts(
            tmp.path(),
            high_audit_runner(),
            ScanOptions {
                no_audit: true,
                ..scan_opts(tmp.path())
            },
        )
        .await;
        let codes = finished_codes(&events);
        assert!(
            !codes.iter().any(|c| c.starts_with("GHSA-")),
            "flag must win over audit=true: {codes:?}"
        );
        assert_eq!(summary(&events).exit, ExitCode::Clean);
    }

    #[tokio::test]
    async fn fix_rewrites_npmrc_and_drops_fixed_codes() {
        let tmp = tempfile::tempdir().unwrap();
        npm_repo(tmp.path(), "a");
        let npmrc = tmp.path().join("a/.npmrc");
        fs::write(&npmrc, "ignore-scripts=false\n").unwrap();
        let before = fs::read(&npmrc).unwrap();
        let events = run_scan_opts(
            tmp.path(),
            CannedRunner::new().with(
                &["npm", "audit", "--json"],
                CommandOutput {
                    code: 0,
                    stdout: NPM_CLEAN.into(),
                    stderr: String::new(),
                },
            ),
            ScanOptions {
                fix: true,
                ..scan_opts(tmp.path())
            },
        )
        .await;
        let after = fs::read(&npmrc).unwrap();
        assert_ne!(before, after, "--fix must rewrite .npmrc");
        let body = String::from_utf8(after).unwrap();
        assert!(body.contains("ignore-scripts=true"), "{body}");
        let codes = finished_codes(&events);
        assert!(
            !codes.iter().any(|c| c == "scripts.unrestricted"),
            "reported findings still include the fixed code: {codes:?}"
        );
        assert!(finished_applied(&events).is_some());
    }

    #[tokio::test]
    async fn fix_on_a_dirty_tree_without_force_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        npm_repo(tmp.path(), "a");
        let npmrc = tmp.path().join("a/.npmrc");
        fs::write(&npmrc, "ignore-scripts=false\n").unwrap();
        let before = fs::read(&npmrc).unwrap();
        let runner = CannedRunner::new()
            .with(
                &["git", "status", "--porcelain"],
                CommandOutput {
                    code: 0,
                    stdout: " M .npmrc\n".into(),
                    stderr: String::new(),
                },
            )
            .with(
                &["npm", "audit", "--json"],
                CommandOutput {
                    code: 0,
                    stdout: NPM_CLEAN.into(),
                    stderr: String::new(),
                },
            );
        let events = run_scan_opts(
            tmp.path(),
            runner,
            ScanOptions {
                fix: true,
                ..scan_opts(tmp.path())
            },
        )
        .await;
        assert_eq!(fs::read(&npmrc).unwrap(), before);
        let applied = finished_applied(&events).expect("applied result");
        assert!(matches!(
            applied.blocked,
            Some(crate::apply::Blocked::DirtyGit(_))
        ));
    }

    #[tokio::test]
    async fn scan_without_fix_is_read_only() {
        let tmp = tempfile::tempdir().unwrap();
        npm_repo(tmp.path(), "a");
        let npmrc = tmp.path().join("a/.npmrc");
        fs::write(&npmrc, "ignore-scripts=false\n").unwrap();
        let before = fs::read(&npmrc).unwrap();
        run_scan_opts(
            tmp.path(),
            CannedRunner::new().with(
                &["npm", "audit", "--json"],
                CommandOutput {
                    code: 0,
                    stdout: NPM_CLEAN.into(),
                    stderr: String::new(),
                },
            ),
            scan_opts(tmp.path()),
        )
        .await;
        assert_eq!(fs::read(&npmrc).unwrap(), before);
        // default path must not even produce an apply result
        let events = run_scan_opts(
            tmp.path(),
            CannedRunner::new().with(
                &["npm", "audit", "--json"],
                CommandOutput {
                    code: 0,
                    stdout: NPM_CLEAN.into(),
                    stderr: String::new(),
                },
            ),
            scan_opts(tmp.path()),
        )
        .await;
        assert!(finished_applied(&events).is_none());
    }
}
