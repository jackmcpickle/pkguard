pub mod parse;

use crate::cache::{lockfile_digest, AdvisoryCache, DEFAULT_TTL_SECS};
use crate::discover::DetectedManager;
use crate::exec::CommandRunner;
use crate::findings::Finding;
use crate::manager::Manager;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct AdvisoryOptions {
    pub refresh: bool,
    pub no_cache: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryOutcome {
    pub findings: Vec<Finding>,
    pub from_cache: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AdvisoryError {
    /// The audit could not produce a trustworthy result; the run exits 2.
    #[error("advisory audit incomplete")]
    Incomplete,
}

fn parse_output(
    manager: Manager,
    stdout: &str,
    file_path: &str,
) -> Result<Vec<Finding>, AdvisoryError> {
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    match manager {
        Manager::Npm => parse::npm::parse_npm_audit(stdout, file_path)
            .map_err(|_| AdvisoryError::Incomplete),
        // Remaining manager dialects arrive with M2.
        _ => Err(AdvisoryError::Incomplete),
    }
}

pub async fn run_manager_advisories(
    project_root: &Path,
    manager: &DetectedManager,
    runner: &dyn CommandRunner,
    cache: &AdvisoryCache,
    opts: &AdvisoryOptions,
) -> Result<AdvisoryOutcome, AdvisoryError> {
    let file_path = manager
        .lockfile_path
        .as_deref()
        .unwrap_or(project_root)
        .to_string_lossy()
        .into_owned();

    let digest = manager
        .lockfile_path
        .as_deref()
        .and_then(|p| std::fs::read(p).ok())
        .map(|bytes| lockfile_digest(&bytes));

    if let Some(key) = digest.as_deref() {
        if !opts.refresh && !opts.no_cache {
            if let Some(mut findings) = cache.get(key, DEFAULT_TTL_SECS) {
                for finding in &mut findings {
                    finding.path = file_path.clone();
                }
                return Ok(AdvisoryOutcome { findings, from_cache: true });
            }
        }
    }

    let Some(argv) = manager.manager.audit_argv() else {
        return Ok(AdvisoryOutcome { findings: Vec::new(), from_cache: false });
    };
    let argv: Vec<String> = argv.into_iter().map(str::to_string).collect();
    let output = runner
        .run(&argv, project_root)
        .await
        .map_err(|_| AdvisoryError::Incomplete)?;
    if output.code != 0 && output.code != 1 {
        return Err(AdvisoryError::Incomplete);
    }
    let findings = parse_output(manager.manager, &output.stdout, &file_path)?;
    if let Some(key) = digest.as_deref() {
        if !opts.no_cache {
            let _ = cache.put(key, &findings);
        }
    }
    Ok(AdvisoryOutcome { findings, from_cache: false })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::AdvisoryCache;
    use crate::discover::{DetectedManager, Role};
    use crate::exec::{CannedRunner, CommandOutput};
    use crate::manager::Manager;
    use std::fs;
    use std::path::Path;

    const NPM_AUDIT_JSON: &str = r#"{
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

    fn npm_manager(root: &Path) -> DetectedManager {
        DetectedManager {
            manager: Manager::Npm,
            role: Role::Primary,
            lockfile_path: Some(root.join("package-lock.json")),
            config_path: None,
        }
    }

    fn setup(root: &Path) -> (DetectedManager, AdvisoryCache) {
        fs::write(root.join("package-lock.json"), "lock-bytes").unwrap();
        (npm_manager(root), AdvisoryCache::new(root.join("cache")))
    }

    #[tokio::test]
    async fn live_audit_parses_and_caches() {
        let tmp = tempfile::tempdir().unwrap();
        let (manager, cache) = setup(tmp.path());
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput { code: 1, stdout: NPM_AUDIT_JSON.into(), stderr: String::new() },
        );

        let opts = AdvisoryOptions::default();
        let out = run_manager_advisories(tmp.path(), &manager, &runner, &cache, &opts)
            .await
            .unwrap();
        assert!(!out.from_cache);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].code, "GHSA-v7");

        // second run hits the cache: no canned response needed
        let empty_runner = CannedRunner::new();
        let cached = run_manager_advisories(tmp.path(), &manager, &empty_runner, &cache, &opts)
            .await
            .unwrap();
        assert!(cached.from_cache);
        assert_eq!(cached.findings, out.findings);
    }

    #[tokio::test]
    async fn unexpected_exit_code_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let (manager, cache) = setup(tmp.path());
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput { code: 2, stdout: String::new(), stderr: "boom".into() },
        );
        let out = run_manager_advisories(
            tmp.path(), &manager, &runner, &cache, &AdvisoryOptions::default(),
        )
        .await;
        assert!(matches!(out, Err(AdvisoryError::Incomplete)));
    }

    #[tokio::test]
    async fn spawn_failure_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let (manager, cache) = setup(tmp.path());
        let out = run_manager_advisories(
            tmp.path(), &manager, &CannedRunner::new(), &cache, &AdvisoryOptions::default(),
        )
        .await;
        assert!(matches!(out, Err(AdvisoryError::Incomplete)));
    }

    #[tokio::test]
    async fn empty_stdout_is_clean() {
        let tmp = tempfile::tempdir().unwrap();
        let (manager, cache) = setup(tmp.path());
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput { code: 0, stdout: "  \n".into(), stderr: String::new() },
        );
        let out = run_manager_advisories(
            tmp.path(), &manager, &runner, &cache, &AdvisoryOptions::default(),
        )
        .await
        .unwrap();
        assert!(out.findings.is_empty());
    }

    #[tokio::test]
    async fn refresh_bypasses_cache_read_but_still_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let (manager, cache) = setup(tmp.path());
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput { code: 0, stdout: NPM_AUDIT_JSON.into(), stderr: String::new() },
        );
        let opts = AdvisoryOptions::default();
        run_manager_advisories(tmp.path(), &manager, &runner, &cache, &opts)
            .await
            .unwrap();
        let refresh = AdvisoryOptions { refresh: true, ..AdvisoryOptions::default() };
        let out = run_manager_advisories(tmp.path(), &manager, &runner, &cache, &refresh)
            .await
            .unwrap();
        assert!(!out.from_cache);
    }
}
