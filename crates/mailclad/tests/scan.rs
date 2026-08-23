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
    let mut cmd = Command::cargo_bin("mailclad").unwrap();
    // fakebin first so our npm wins; /usr/bin:/bin so the script's `cat` works
    cmd.arg("scan")
        .arg(root)
        .env("PATH", format!("{}:/usr/bin:/bin", path_dir.display()))
        .env("MAILCLAD_CACHE_DIR", root.join(".cache"))
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
    fs::write(dir.join("package.json"), r#"{"packageManager": "npm@11.0.0"}"#).unwrap();
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

    let assert = scan_cmd(tmp.path(), &bin).arg("--format").arg("json").assert().code(1);
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

#[test]
fn version_flag_prints_version() {
    let mut cmd = Command::cargo_bin("mailclad").unwrap();
    let assert = cmd.arg("--version").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}
