use assert_cmd::Command;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const NPM_HIGH: &str = r#"{"auditReportVersion":2,"vulnerabilities":{"left-pad":{"name":"left-pad","severity":"high","fixAvailable":{"name":"left-pad","version":"1.3.0"},"via":[{"github_advisory_id":"GHSA-v7","severity":"high","title":"left-pad advisory","version":"1.0.0"}]}}}"#;

fn npm_repo(root: &Path, name: &str) {
    let dir = root.join(name);
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join("package.json"), "{}").unwrap();
    fs::write(dir.join("package-lock.json"), format!("lock-{name}")).unwrap();
}

/// Installs a fake `npm` that prints the given audit JSON, returns the PATH dir.
fn fake_npm(root: &Path, audit_json: &str) -> std::path::PathBuf {
    let bin = root.join("fakebin");
    fs::create_dir_all(&bin).unwrap();
    let script = bin.join("npm");
    fs::write(
        &script,
        format!("#!/bin/sh\ncat <<'EOF'\n{audit_json}\nEOF\n"),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn scan_cmd(root: &Path, path_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("pkguard").unwrap();
    // fakebin first so our npm wins; /usr/bin:/bin so the script's `cat` works
    cmd.arg("scan")
        .arg(root)
        .env("PATH", format!("{}:/usr/bin:/bin", path_dir.display()))
        .env("PKGUARD_CACHE_DIR", root.join(".cache"))
        .env("NO_COLOR", "1");
    cmd
}

#[test]
fn scan_reports_findings_and_exits_one_on_policy_failure() {
    let tmp = tempfile::tempdir().unwrap();
    npm_repo(tmp.path(), "app");
    let bin = fake_npm(tmp.path(), NPM_HIGH);

    let assert = scan_cmd(tmp.path(), &bin).assert().code(1);
    let output = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(output.contains("GHSA-v7"), "stdout was: {output}");
    assert!(output.contains("left-pad"), "stdout was: {output}");
    assert!(output.contains("high"), "stdout was: {output}");
}

#[test]
fn scan_clean_repo_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    npm_repo(tmp.path(), "app");
    // settings-compliant so no settings findings trip the gate
    let dir = tmp.path().join("app");
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
    let bin = fake_npm(
        tmp.path(),
        r#"{"auditReportVersion":2,"vulnerabilities":{}}"#,
    );
    scan_cmd(tmp.path(), &bin).assert().code(0);
}

#[test]
fn scan_empty_dir_exits_two() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = fake_npm(tmp.path(), "{}");
    scan_cmd(tmp.path(), &bin).assert().code(2);
}

#[test]
fn scan_json_format_emits_machine_output() {
    let tmp = tempfile::tempdir().unwrap();
    npm_repo(tmp.path(), "app");
    let bin = fake_npm(tmp.path(), NPM_HIGH);

    let assert = scan_cmd(tmp.path(), &bin)
        .arg("--format")
        .arg("json")
        .assert()
        .code(1);
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(parsed["schemaVersion"], 2);
    assert_eq!(parsed["exitCode"], 1);
    let codes: Vec<&str> = parsed["projects"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["code"].as_str())
        .collect();
    assert!(codes.contains(&"GHSA-v7"), "codes: {codes:?}");
    assert!(codes.contains(&"scripts.unrestricted"), "codes: {codes:?}");
}

fn fake_pnpm(root: &Path, audit_json: &str) -> std::path::PathBuf {
    let bin = root.join("fakebin");
    fs::create_dir_all(&bin).unwrap();
    let script = bin.join("pnpm");
    fs::write(
        &script,
        format!("#!/bin/sh\ncat <<'EOF'\n{audit_json}\nEOF\n"),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[test]
fn scan_site_style_pnpm_config_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("app");
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"packageManager": "pnpm@11.22.0"}"#,
    )
    .unwrap();
    fs::write(dir.join("pnpm-lock.yaml"), "lock-app").unwrap();
    fs::write(
        dir.join("pnpm-workspace.yaml"),
        "\
allowBuilds:
  esbuild: false
minimumReleaseAge: 1440
minimumReleaseAgeStrict: true
minimumReleaseAgeIgnoreMissingTime: false
blockExoticSubdeps: true
strictDepBuilds: true
audit:
  level: high
trustPolicy: no-downgrade
trustPolicyIgnoreAfter: 129600
verifyDepsBeforeRun: error
registry: https://registry.npmjs.org/
",
    )
    .unwrap();
    let bin = fake_pnpm(tmp.path(), r#"{"advisories":{}}"#);
    scan_cmd(tmp.path(), &bin).assert().code(0);
}

#[test]
fn scan_reports_pnpm_settings_and_advisories() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("app");
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join("package.json"), "{}").unwrap();
    fs::write(dir.join("pnpm-lock.yaml"), "lock-app").unwrap();
    let bin = fake_pnpm(
        tmp.path(),
        r#"{"advisories":{"1":{"findings":[{"version":"1.0.0"}],"github_advisory_id":"GHSA-pnpm","module_name":"left-pad","severity":"high","title":"pnpm high advisory"}}}"#,
    );

    let assert = scan_cmd(tmp.path(), &bin).assert().code(1);
    let output = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(output.contains("GHSA-pnpm"), "stdout was: {output}");
    assert!(output.contains("audit.disabled"), "stdout was: {output}");
    assert!(
        output.contains("scripts.unrestricted"),
        "stdout was: {output}"
    );
}

fn fake_yarn(root: &Path, audit_json: &str) -> std::path::PathBuf {
    let bin = root.join("fakebin");
    fs::create_dir_all(&bin).unwrap();
    let script = bin.join("yarn");
    fs::write(
        &script,
        format!("#!/bin/sh\ncat <<'EOF'\n{audit_json}\nEOF\n"),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[test]
fn scan_reports_yarn_settings_and_advisories() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("app");
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join("package.json"), "{}").unwrap();
    fs::write(dir.join("yarn.lock"), "lock-app").unwrap();
    fs::write(dir.join(".yarnrc.yml"), "").unwrap();
    let bin = fake_yarn(
        tmp.path(),
        r#"{"value":"left-pad","children":{"ID":"GHSA-yarn","Severity":"high","Issue":"yarn high advisory"}}"#,
    );

    let assert = scan_cmd(tmp.path(), &bin).assert().code(1);
    let output = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(output.contains("GHSA-yarn"), "stdout was: {output}");
    assert!(
        output.contains("source.git-unrestricted"),
        "stdout was: {output}"
    );
}

#[test]
fn version_flag_prints_version() {
    let mut cmd = Command::cargo_bin("pkguard").unwrap();
    let assert = cmd.arg("--version").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

/// Settings that `--fix` can actually close: packageManager + registry are
/// already pinned so the only findings are rewriteable `.npmrc` keys.
fn fixable_npm_repo(root: &Path) -> std::path::PathBuf {
    let dir = root.join("app");
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"packageManager": "npm@11.0.0"}"#,
    )
    .unwrap();
    fs::write(dir.join("package-lock.json"), "lock-app").unwrap();
    fs::write(
        dir.join(".npmrc"),
        "registry=https://registry.npmjs.org/\nignore-scripts=false\n",
    )
    .unwrap();
    dir
}

const fn clean_npm() -> &'static str {
    r#"{"auditReportVersion":2,"vulnerabilities":{}}"#
}

fn stdout_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn stderr_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stderr).into_owned()
}

fn git_init(dir: &Path) {
    let status = std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir)
        .status()
        .expect("git init");
    assert!(status.success(), "git init failed");
}

#[test]
fn audit_alias_matches_scan_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    npm_repo(tmp.path(), "app");
    let bin = fake_npm(tmp.path(), NPM_HIGH);

    let scan = stdout_of(&scan_cmd(tmp.path(), &bin).assert().code(1));
    let mut audit = Command::cargo_bin("pkguard").unwrap();
    let audit = stdout_of(
        &audit
            .arg("audit")
            .arg(tmp.path())
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("PKGUARD_CACHE_DIR", tmp.path().join(".cache"))
            .env("NO_COLOR", "1")
            .assert()
            .code(1),
    );
    assert_eq!(audit, scan);
}

#[test]
fn scan_and_audit_help_mention_fix() {
    for sub in ["scan", "audit"] {
        let mut cmd = Command::cargo_bin("pkguard").unwrap();
        let stdout = stdout_of(&cmd.arg(sub).arg("--help").assert().success());
        assert!(
            stdout.contains("--fix"),
            "{sub} --help missing --fix: {stdout}"
        );
    }
}

#[test]
fn scan_fix_rewrites_npmrc_and_exits_zero_when_that_was_the_only_finding() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = fixable_npm_repo(tmp.path());
    let npmrc = dir.join(".npmrc");
    let before = fs::read(&npmrc).unwrap();
    let bin = fake_npm(tmp.path(), clean_npm());

    scan_cmd(tmp.path(), &bin).arg("--fix").assert().code(0);
    let after = fs::read(&npmrc).unwrap();
    assert_ne!(before, after, "--fix must rewrite .npmrc");
    let body = String::from_utf8(after).unwrap();
    assert!(body.contains("ignore-scripts=true"), "{body}");
}

#[test]
fn scan_without_fix_leaves_npmrc_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = fixable_npm_repo(tmp.path());
    let npmrc = dir.join(".npmrc");
    let before = fs::read(&npmrc).unwrap();
    let bin = fake_npm(tmp.path(), clean_npm());

    scan_cmd(tmp.path(), &bin).assert().code(1);
    assert_eq!(fs::read(&npmrc).unwrap(), before);
}

#[test]
fn scan_fix_dry_run_prints_changes_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = fixable_npm_repo(tmp.path());
    let npmrc = dir.join(".npmrc");
    let before = fs::read(&npmrc).unwrap();
    let bin = fake_npm(tmp.path(), clean_npm());

    let stdout = stdout_of(
        &scan_cmd(tmp.path(), &bin)
            .arg("--fix")
            .arg("--dry-run")
            .assert()
            .code(1),
    );
    assert_eq!(fs::read(&npmrc).unwrap(), before);
    assert!(stdout.contains("fixed"), "stdout was: {stdout}");
    assert!(stdout.contains("->"), "stdout was: {stdout}");
}

#[test]
fn scan_force_without_fix_is_a_usage_error() {
    let mut cmd = Command::cargo_bin("pkguard").unwrap();
    let assert = cmd.arg("scan").arg("--force").assert().code(2);
    let err = format!("{}{}", stdout_of(&assert), stderr_of(&assert));
    assert!(
        err.to_lowercase().contains("usage") || err.contains("--fix"),
        "stderr/stdout was: {err}"
    );
}

#[test]
fn scan_dry_run_without_fix_is_a_usage_error() {
    let mut cmd = Command::cargo_bin("pkguard").unwrap();
    let assert = cmd.arg("scan").arg("--dry-run").assert().code(2);
    let err = format!("{}{}", stdout_of(&assert), stderr_of(&assert));
    assert!(
        err.to_lowercase().contains("usage") || err.contains("--fix"),
        "stderr/stdout was: {err}"
    );
}

#[test]
fn scan_no_audit_exits_zero_and_marks_audits_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    npm_repo(tmp.path(), "app");
    let dir = tmp.path().join("app");
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
    let empty = tmp.path().join("emptybin");
    fs::create_dir_all(&empty).unwrap();

    let stdout = stdout_of(
        &scan_cmd(tmp.path(), &empty)
            .arg("--no-audit")
            .assert()
            .code(0),
    );
    assert!(stdout.contains("audits skipped"), "stdout was: {stdout}");
}

#[test]
fn scan_fix_json_includes_schema_and_applied_block() {
    let tmp = tempfile::tempdir().unwrap();
    fixable_npm_repo(tmp.path());
    let bin = fake_npm(tmp.path(), clean_npm());

    let stdout = stdout_of(
        &scan_cmd(tmp.path(), &bin)
            .arg("--fix")
            .arg("--format")
            .arg("json")
            .assert()
            .code(0),
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(parsed["schemaVersion"], 2);
    assert!(
        parsed["projects"][0]["applied"].is_object(),
        "applied block missing: {parsed}"
    );
}

#[test]
fn scan_fix_on_dirty_git_writes_nothing_and_names_force() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = fixable_npm_repo(tmp.path());
    fs::remove_dir_all(dir.join(".git")).unwrap();
    git_init(&dir);
    let npmrc = dir.join(".npmrc");
    let before = fs::read(&npmrc).unwrap();
    let bin = fake_npm(tmp.path(), clean_npm());
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );

    let assert = scan_cmd(tmp.path(), &bin)
        .env("PATH", path)
        .arg("--fix")
        .assert()
        .code(1);
    assert_eq!(fs::read(&npmrc).unwrap(), before);
    let out = format!("{}{}", stdout_of(&assert), stderr_of(&assert));
    assert!(out.contains("--force"), "output was: {out}");
}
