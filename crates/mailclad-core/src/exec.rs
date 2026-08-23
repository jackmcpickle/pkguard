use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// The only injection seam in the core: everything that spawns a subprocess
/// (package-manager audits, git) goes through this trait.
#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, argv: &[String], cwd: &Path) -> std::io::Result<CommandOutput>;

    /// Preflight check: is this binary invocable? Missing binaries become a
    /// `pm.missing-binary` info finding rather than a failed audit.
    fn which(&self, binary: &str) -> bool;
}

pub struct TokioRunner;

#[async_trait]
impl CommandRunner for TokioRunner {
    async fn run(&self, argv: &[String], cwd: &Path) -> std::io::Result<CommandOutput> {
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty argv"))?;
        let output = tokio::process::Command::new(program)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .await?;
        Ok(CommandOutput {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn which(&self, binary: &str) -> bool {
        let Some(paths) = std::env::var_os("PATH") else {
            return false;
        };
        std::env::split_paths(&paths).any(|dir| dir.join(binary).is_file())
    }
}

/// Test double: replays canned output keyed by argv; unknown argv errors like
/// a missing binary would.
#[derive(Default)]
pub struct CannedRunner {
    responses: Mutex<HashMap<Vec<String>, CommandOutput>>,
}

impl CannedRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(self, argv: &[&str], output: CommandOutput) -> Self {
        self.responses
            .lock()
            .unwrap()
            .insert(argv.iter().map(|s| s.to_string()).collect(), output);
        self
    }
}

#[async_trait]
impl CommandRunner for CannedRunner {
    async fn run(&self, argv: &[String], _cwd: &Path) -> std::io::Result<CommandOutput> {
        self.responses
            .lock()
            .unwrap()
            .get(argv)
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no canned response for {argv:?}"),
                )
            })
    }

    /// A binary "exists" iff some canned argv invokes it.
    fn which(&self, binary: &str) -> bool {
        self.responses
            .lock()
            .unwrap()
            .keys()
            .any(|argv| argv.first().is_some_and(|b| b == binary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn tokio_runner_captures_stdout_and_exit_code() {
        let runner = TokioRunner;
        let out = runner
            .run(
                &["sh".into(), "-c".into(), "printf hi; exit 1".into()],
                Path::new("."),
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, "hi");
        assert_eq!(out.code, 1);
    }

    #[tokio::test]
    async fn tokio_runner_reports_missing_binary_as_error() {
        let runner = TokioRunner;
        let result = runner
            .run(&["definitely-not-a-real-binary-xyz".into()], Path::new("."))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn canned_runner_replays_programmed_output() {
        let runner = CannedRunner::new().with(
            &["npm", "audit", "--json"],
            CommandOutput {
                code: 0,
                stdout: "{}".into(),
                stderr: String::new(),
            },
        );
        let out = runner
            .run(
                &["npm".into(), "audit".into(), "--json".into()],
                Path::new("/repo"),
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, "{}");
        let missing = runner.run(&["pnpm".into()], Path::new("/repo")).await;
        assert!(missing.is_err());
    }
}
