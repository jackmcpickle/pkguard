use assert_cmd::Command;
use std::fs;
use std::path::Path;

fn init_cmd(cwd: &Path) -> Command {
    let mut cmd = Command::cargo_bin("pkguard").unwrap();
    cmd.arg("init").current_dir(cwd).env("NO_COLOR", "1");
    cmd
}

fn assert_starter_toml(raw: &str) {
    assert!(raw.contains("preset = \"standard\""), "starter was: {raw}");
    pkguard_core::config::parse_config(raw).expect("starter toml must parse");
}

#[test]
fn init_local_writes_pkguard_toml_in_cwd() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join(".pkguard.toml");

    let assert = init_cmd(tmp.path()).arg("--local").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        stdout.contains(&target.display().to_string()),
        "stdout was: {stdout}"
    );
    assert_starter_toml(&fs::read_to_string(&target).unwrap());
}

#[test]
fn init_local_refuses_to_overwrite_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join(".pkguard.toml");
    fs::write(&target, "preset = \"relaxed\"\n").unwrap();

    let assert = init_cmd(tmp.path()).arg("--local").assert().code(2);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains(&target.display().to_string()),
        "stderr was: {stderr}"
    );
    assert!(stderr.contains("--force"), "stderr was: {stderr}");
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "preset = \"relaxed\"\n"
    );
}

#[test]
fn init_local_force_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join(".pkguard.toml");
    fs::write(&target, "preset = \"relaxed\"\n").unwrap();

    init_cmd(tmp.path())
        .arg("--local")
        .arg("--force")
        .assert()
        .success();
    assert_starter_toml(&fs::read_to_string(&target).unwrap());
}

#[test]
fn init_writes_user_config_under_pkguard_config_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("xdg");
    let target = config_dir.join("config.toml");

    let assert = init_cmd(tmp.path())
        .env("PKGUARD_CONFIG_DIR", &config_dir)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        stdout.contains(&target.display().to_string()),
        "stdout was: {stdout}"
    );
    assert_starter_toml(&fs::read_to_string(&target).unwrap());
}
