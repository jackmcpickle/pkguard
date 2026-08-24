// The parsers are crate-internal: `parse_output` below is the only place a
// parser is chosen, and reaching one directly bypasses that choice. A caller
// outside the crate wants `run_manager_advisories`.
pub(crate) mod parse;

use crate::cache::{lockfile_digest, AdvisoryCache};
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
    // A "successful" audit that produced no report is not evidence of a clean
    // project; treat it as incomplete rather than silently passing.
    if stdout.trim().is_empty() {
        return Err(AdvisoryError::Incomplete);
    }
    // The only place a parser is chosen. `generic` used to sniff the payload
    // and delegate back to `npm`, which meant two dispatchers disagreeing
    // about who decides.
    match manager {
        Manager::Npm | Manager::Pnpm => parse::npm::parse_npm_audit(stdout, file_path, manager)
            .map_err(|_| AdvisoryError::Incomplete),
        Manager::Poetry | Manager::Pip | Manager::Pipenv => Ok(Vec::new()),
        other => {
            let parsed =
                parse::generic::parse_stdout(stdout).map_err(|_| AdvisoryError::Incomplete)?;
            if parse::generic::looks_like_npm_report(&parsed) {
                parse::npm::parse_npm_audit(stdout, file_path, other)
            } else {
                parse::generic::parse_value(parsed, file_path, other)
            }
            .map_err(|_| AdvisoryError::Incomplete)
        }
    }
}

/// Run a manager's own audit command and turn its output into advisories,
/// serving a cached result when the lockfile digest still matches.
///
/// # Errors
///
/// Returns [`AdvisoryError::Incomplete`] when the audit could not produce a
/// trustworthy result — an empty or unparseable report. An audit that ran and
/// found nothing is a success with no findings, not an error.
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
            if let Some(mut findings) = cache.get(key) {
                for finding in &mut findings {
                    finding.path.clone_from(&file_path);
                }
                return Ok(AdvisoryOutcome {
                    findings,
                    from_cache: true,
                });
            }
        }
    }

    let Some(argv) = manager.manager.audit_argv() else {
        return Ok(AdvisoryOutcome {
            findings: Vec::new(),
            from_cache: false,
        });
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
    Ok(AdvisoryOutcome {
        findings,
        from_cache: false,
    })
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
            CommandOutput {
                code: 1,
                stdout: NPM_AUDIT_JSON.into(),
                stderr: String::new(),
            },
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
            CommandOutput {
                code: 2,
                stdout: String::new(),
                stderr: "boom".into(),
            },
        );
        let out = run_manager_advisories(
            tmp.path(),
            &manager,
            &runner,
            &cache,
            &AdvisoryOptions::default(),
        )
        .await;
        assert!(matches!(out, Err(AdvisoryError::Incomplete)));
    }

    #[tokio::test]
    async fn spawn_failure_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let (manager, cache) = setup(tmp.path());
        let out = run_manager_advisories(
            tmp.path(),
            &manager,
            &CannedRunner::new(),
            &cache,
            &AdvisoryOptions::default(),
        )
        .await;
        assert!(matches!(out, Err(AdvisoryError::Incomplete)));
    }

    #[tokio::test]
    async fn empty_stdout_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let (manager, cache) = setup(tmp.path());
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 0,
                stdout: "  \n".into(),
                stderr: String::new(),
            },
        );
        let out = run_manager_advisories(
            tmp.path(),
            &manager,
            &runner,
            &cache,
            &AdvisoryOptions::default(),
        )
        .await;
        assert!(matches!(out, Err(AdvisoryError::Incomplete)));
    }

    #[tokio::test]
    async fn refresh_bypasses_cache_read_but_still_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let (manager, cache) = setup(tmp.path());
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 0,
                stdout: NPM_AUDIT_JSON.into(),
                stderr: String::new(),
            },
        );
        let opts = AdvisoryOptions::default();
        run_manager_advisories(tmp.path(), &manager, &runner, &cache, &opts)
            .await
            .unwrap();
        let refresh = AdvisoryOptions {
            refresh: true,
            ..AdvisoryOptions::default()
        };
        let out = run_manager_advisories(tmp.path(), &manager, &runner, &cache, &refresh)
            .await
            .unwrap();
        assert!(!out.from_cache);
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;

    /// npm v7 shape, but reported by a manager that normally uses the generic
    /// walker.
    const NPM_SHAPED: &str = r#"{
        "auditReportVersion": 2,
        "vulnerabilities": {
            "left-pad": {
                "name": "left-pad",
                "severity": "high",
                "via": [{
                    "source": 1234,
                    "name": "left-pad",
                    "title": "Prototype pollution",
                    "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                    "severity": "high",
                    "range": "<1.3.0"
                }],
                "range": "<1.3.0",
                "fixAvailable": {"name": "left-pad", "version": "1.3.0"}
            }
        }
    }"#;

    #[test]
    fn an_npm_shaped_payload_reaches_the_npm_parser_whatever_the_manager() {
        // The generic walker would flatten this to a package-level
        // `advisory.unknown`; the npm parser keeps the advisory id and fix.
        for manager in [Manager::Yarn, Manager::Bun, Manager::Composer] {
            let findings = parse_output(manager, NPM_SHAPED, "/p/yarn.lock").unwrap();
            assert!(
                findings.iter().any(|f| f.code == "GHSA-aaaa-bbbb-cccc"),
                "{manager:?} lost the advisory id: {:?}",
                findings.iter().map(|f| &f.code).collect::<Vec<_>>()
            );
            assert!(
                findings
                    .iter()
                    .any(|f| f.fix_version.as_deref() == Some("1.3.0")),
                "{manager:?} lost the fix version"
            );
        }
    }

    #[test]
    fn cargos_vulnerabilities_list_still_uses_the_generic_walker() {
        // `{vulnerabilities: {list: [...]}}` is not npm v7 and must not be
        // mistaken for it.
        let stdout = r#"{"vulnerabilities":{"list":[{"advisory":{
            "id":"RUSTSEC-2024-0001","title":"bad","url":"https://x"},
            "package":{"name":"foo","version":"0.1.0"}}]}}"#;
        let findings = parse_output(Manager::Cargo, stdout, "/p/Cargo.lock").unwrap();
        assert!(
            findings.iter().any(|f| f.code == "RUSTSEC-2024-0001"),
            "{findings:?}"
        );
    }

    #[test]
    fn npm_and_pnpm_never_reach_the_generic_walker() {
        for manager in [Manager::Npm, Manager::Pnpm] {
            let findings = parse_output(manager, NPM_SHAPED, "/p/package-lock.json").unwrap();
            assert!(findings.iter().any(|f| f.code == "GHSA-aaaa-bbbb-cccc"));
        }
    }

    #[test]
    fn an_empty_report_is_incomplete_rather_than_clean() {
        assert!(matches!(
            parse_output(Manager::Yarn, "   ", "/p/yarn.lock"),
            Err(AdvisoryError::Incomplete)
        ));
    }
}
