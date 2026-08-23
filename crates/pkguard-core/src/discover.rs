use crate::manager::{Manager, PackageManagerPin};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Primary,
    Leftover,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetectedManager {
    pub manager: Manager,
    pub role: Role,
    pub lockfile_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Project {
    pub root: PathBuf,
    pub git_root: Option<PathBuf>,
    pub managers: Vec<DetectedManager>,
}

const SKIP_DIRS: [&str; 9] = [
    "node_modules",
    ".git",
    "dist",
    "build",
    "target",
    ".venv",
    "vendor",
    "__pycache__",
    ".pnpm-store",
];

const NESTED_CONFIGS: [&str; 8] = [
    ".npmrc",
    "pnpm-workspace.yaml",
    ".yarnrc.yml",
    "bunfig.toml",
    "uv.toml",
    "uv.lock",
    "Cargo.toml",
    "composer.json",
];

const NESTED_PM_MARKER_FILES: [&str; 9] = [
    "Cargo.lock",
    "Cargo.toml",
    "Gemfile",
    "Gemfile.lock",
    "Pipfile",
    "Pipfile.lock",
    "composer.json",
    "composer.lock",
    "poetry.lock",
];

const ROOT_PM_FILES: [&str; 20] = [
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    ".yarnrc.yml",
    "bun.lock",
    "bun.lockb",
    "bunfig.toml",
    "uv.lock",
    "uv.toml",
    "Cargo.toml",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
];

fn dir_names(dir: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            names.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names
}

fn has_git(dir: &Path) -> bool {
    dir.join(".git").exists()
}

fn has_requirements_txt(names: &BTreeSet<String>) -> bool {
    names.contains("requirements.txt")
        || names.iter().any(|n| {
            n.strip_prefix("requirements-")
                .and_then(|rest| rest.strip_suffix(".txt"))
                .is_some_and(|middle| !middle.is_empty())
        })
}

fn pyproject_table(dir: &Path) -> Option<toml::Table> {
    let raw = std::fs::read_to_string(dir.join("pyproject.toml")).ok()?;
    raw.parse::<toml::Table>().ok()
}

fn has_tool_table(dir: &Path, name: &str) -> bool {
    pyproject_table(dir)
        .and_then(|t| t.get("tool").and_then(|tool| tool.get(name)).cloned())
        .is_some_and(|v| v.is_table())
}

fn has_project_table(dir: &Path) -> bool {
    pyproject_table(dir).is_some_and(|t| t.get("project").is_some_and(toml::Value::is_table))
}

fn has_root_pm_markers(dir: &Path, names: &BTreeSet<String>) -> bool {
    ROOT_PM_FILES.iter().any(|f| names.contains(*f))
        || has_requirements_txt(names)
        || has_tool_table(dir, "uv")
        || has_tool_table(dir, "poetry")
        || has_project_table(dir)
}

fn has_nested_config(dir: &Path, names: &BTreeSet<String>) -> bool {
    NESTED_CONFIGS.iter().any(|f| names.contains(*f))
        || NESTED_PM_MARKER_FILES.iter().any(|f| names.contains(*f))
        || has_requirements_txt(names)
        || has_tool_table(dir, "poetry")
        || has_project_table(dir)
}

fn find_nested_git_repos(dir: &Path, found: &mut Vec<PathBuf>) {
    for name in dir_names(dir) {
        if SKIP_DIRS.contains(&name.as_str()) {
            continue;
        }
        let child = dir.join(&name);
        // Never follow directory symlinks: a repo-controlled link can form a cycle.
        if child.is_symlink() || !child.is_dir() {
            continue;
        }
        if has_git(&child) {
            found.push(child.clone());
        }
        find_nested_git_repos(&child, found);
    }
}

fn find_repo_trees(root: &Path) -> Vec<(PathBuf, bool)> {
    if has_git(root) {
        return vec![(root.to_path_buf(), true)];
    }
    let mut nested = Vec::new();
    find_nested_git_repos(root, &mut nested);
    if nested.is_empty() {
        return vec![(root.to_path_buf(), false)];
    }
    let mut trees: Vec<(PathBuf, bool)> = nested.into_iter().map(|p| (p, true)).collect();
    if has_root_pm_markers(root, &dir_names(root)) {
        trees.insert(0, (root.to_path_buf(), false));
    }
    trees
}

fn walk_pm_roots(dir: &Path, repo: &Path, is_repo_root: bool, roots: &mut Vec<PathBuf>) {
    let names = dir_names(dir);
    if is_repo_root {
        if has_root_pm_markers(dir, &names) {
            roots.push(dir.to_path_buf());
        }
    } else if has_nested_config(dir, &names) {
        roots.push(dir.to_path_buf());
    }
    for name in names {
        if SKIP_DIRS.contains(&name.as_str()) {
            continue;
        }
        let child = dir.join(&name);
        if child.is_symlink() || !child.is_dir() || (has_git(&child) && child != repo) {
            continue;
        }
        walk_pm_roots(&child, repo, false, roots);
    }
}

const JS_PRIMARY_ORDER: [Manager; 4] = [Manager::Pnpm, Manager::Yarn, Manager::Bun, Manager::Npm];

fn has_bun_lock(names: &BTreeSet<String>) -> bool {
    names.contains("bun.lock") || names.contains("bun.lockb")
}

fn has_other_js_lock(names: &BTreeSet<String>) -> bool {
    names.contains("pnpm-lock.yaml") || names.contains("yarn.lock") || has_bun_lock(names)
}

fn is_js_manager(name: &str) -> bool {
    matches!(name, "npm" | "pnpm" | "yarn" | "bun")
}

fn is_pinned_other_js(pin: Option<&PackageManagerPin>) -> bool {
    pin.is_some_and(|p| p.name != "npm" && is_js_manager(&p.name))
}

fn should_include_npm(names: &BTreeSet<String>, pin: Option<&PackageManagerPin>) -> bool {
    if names.contains("package-lock.json") {
        return true;
    }
    if !names.contains("package.json") {
        return false;
    }
    !has_other_js_lock(names) && !is_pinned_other_js(pin)
}

fn collect_js_candidates(
    names: &BTreeSet<String>,
    pin: Option<&PackageManagerPin>,
) -> Vec<Manager> {
    let mut candidates = Vec::new();
    if names.contains("pnpm-lock.yaml") || names.contains("pnpm-workspace.yaml") {
        candidates.push(Manager::Pnpm);
    }
    if names.contains("yarn.lock") {
        candidates.push(Manager::Yarn);
    }
    if has_bun_lock(names) || names.contains("bunfig.toml") {
        candidates.push(Manager::Bun);
    }
    if should_include_npm(names, pin) {
        candidates.push(Manager::Npm);
    }
    candidates
}

fn pick_js_primary(names: &BTreeSet<String>, pin: Option<&PackageManagerPin>) -> Option<Manager> {
    let candidates = collect_js_candidates(names, pin);
    if candidates.is_empty() {
        return None;
    }
    if let Some(p) = pin {
        if let Some(m) = p.manager() {
            if is_js_manager(&p.name) && candidates.contains(&m) {
                return Some(m);
            }
        }
    }
    JS_PRIMARY_ORDER
        .into_iter()
        .find(|m| candidates.contains(m))
        .or_else(|| candidates.first().copied())
}

fn existing(dir: &Path, names: &BTreeSet<String>, file: &str) -> Option<PathBuf> {
    names.contains(file).then(|| dir.join(file))
}

fn role_for(primary: Option<Manager>, manager: Manager) -> Role {
    if primary == Some(manager) {
        Role::Primary
    } else {
        Role::Leftover
    }
}

fn detect_pnpm(
    dir: &Path,
    names: &BTreeSet<String>,
    primary: Option<Manager>,
) -> Option<DetectedManager> {
    if !names.contains("pnpm-lock.yaml") && !names.contains("pnpm-workspace.yaml") {
        return None;
    }
    Some(DetectedManager {
        manager: Manager::Pnpm,
        role: role_for(primary, Manager::Pnpm),
        lockfile_path: existing(dir, names, "pnpm-lock.yaml"),
        config_path: existing(dir, names, "pnpm-workspace.yaml"),
    })
}

fn detect_yarn(
    dir: &Path,
    names: &BTreeSet<String>,
    pin: Option<&PackageManagerPin>,
    primary: Option<Manager>,
) -> Option<DetectedManager> {
    if !names.contains("yarn.lock") {
        return None;
    }
    let berry =
        names.contains(".yarnrc.yml") || pin.is_some_and(|p| p.name == "yarn" && p.major >= 2);
    let role = if primary.is_some() && primary != Some(Manager::Yarn) {
        Role::Leftover
    } else if berry {
        Role::Primary
    } else {
        Role::Unsupported
    };
    Some(DetectedManager {
        manager: Manager::Yarn,
        role,
        lockfile_path: existing(dir, names, "yarn.lock"),
        config_path: existing(dir, names, ".yarnrc.yml"),
    })
}

fn detect_bun(
    dir: &Path,
    names: &BTreeSet<String>,
    primary: Option<Manager>,
) -> Option<DetectedManager> {
    if !has_bun_lock(names) && !names.contains("bunfig.toml") {
        return None;
    }
    let lockfile = existing(dir, names, "bun.lock").or_else(|| existing(dir, names, "bun.lockb"));
    Some(DetectedManager {
        manager: Manager::Bun,
        role: role_for(primary, Manager::Bun),
        lockfile_path: lockfile,
        config_path: existing(dir, names, "bunfig.toml"),
    })
}

fn detect_npm(
    dir: &Path,
    names: &BTreeSet<String>,
    pin: Option<&PackageManagerPin>,
    primary: Option<Manager>,
) -> Option<DetectedManager> {
    let config_path = existing(dir, names, ".npmrc");
    if names.contains("package-lock.json") {
        return Some(DetectedManager {
            manager: Manager::Npm,
            role: role_for(primary, Manager::Npm),
            lockfile_path: existing(dir, names, "package-lock.json"),
            config_path,
        });
    }
    let bare_ok = names.contains("package.json")
        && !has_other_js_lock(names)
        && !is_pinned_other_js(pin)
        && (primary.is_none() || primary == Some(Manager::Npm));
    if !bare_ok {
        return None;
    }
    Some(DetectedManager {
        manager: Manager::Npm,
        role: Role::Primary,
        lockfile_path: None,
        config_path,
    })
}

fn cargo_config_path(dir: &Path) -> Option<PathBuf> {
    let toml = dir.join(".cargo/config.toml");
    if toml.is_file() {
        return Some(toml);
    }
    let legacy = dir.join(".cargo/config");
    legacy.is_file().then_some(legacy)
}

fn detect_uv(
    dir: &Path,
    names: &BTreeSet<String>,
    js_primary: Option<Manager>,
) -> Option<DetectedManager> {
    let tool_uv = has_tool_table(dir, "uv");
    if !names.contains("uv.lock") && !tool_uv {
        return None;
    }
    let python_project = tool_uv || has_project_table(dir);
    let role = if js_primary.is_some() && !python_project {
        Role::Leftover
    } else {
        Role::Primary
    };
    let config_path =
        existing(dir, names, "uv.toml").or_else(|| tool_uv.then(|| dir.join("pyproject.toml")));
    Some(DetectedManager {
        manager: Manager::Uv,
        role,
        lockfile_path: existing(dir, names, "uv.lock"),
        config_path,
    })
}

fn detect_poetry(
    dir: &Path,
    names: &BTreeSet<String>,
    uv_present: bool,
) -> Option<DetectedManager> {
    if !names.contains("poetry.lock") && !has_tool_table(dir, "poetry") {
        return None;
    }
    Some(DetectedManager {
        manager: Manager::Poetry,
        role: if uv_present {
            Role::Leftover
        } else {
            Role::Primary
        },
        lockfile_path: existing(dir, names, "poetry.lock"),
        config_path: dir
            .join("pyproject.toml")
            .is_file()
            .then(|| dir.join("pyproject.toml")),
    })
}

fn detect_pipenv(dir: &Path, names: &BTreeSet<String>) -> Option<DetectedManager> {
    if !names.contains("Pipfile") && !names.contains("Pipfile.lock") {
        return None;
    }
    Some(DetectedManager {
        manager: Manager::Pipenv,
        role: Role::Primary,
        lockfile_path: existing(dir, names, "Pipfile.lock"),
        config_path: existing(dir, names, "Pipfile"),
    })
}

fn detect_pip(
    dir: &Path,
    names: &BTreeSet<String>,
    uv_present: bool,
    poetry_present: bool,
    pipenv_present: bool,
) -> Option<DetectedManager> {
    if uv_present {
        return None;
    }
    let reqs: Vec<&String> = names
        .iter()
        .filter(|name| {
            *name == "requirements.txt"
                || name
                    .strip_prefix("requirements-")
                    .and_then(|rest| rest.strip_suffix(".txt"))
                    .is_some_and(|middle| !middle.is_empty())
        })
        .collect();
    let from_project =
        !poetry_present && !pipenv_present && !has_tool_table(dir, "uv") && has_project_table(dir);
    if reqs.is_empty() && !from_project {
        return None;
    }
    Some(DetectedManager {
        manager: Manager::Pip,
        role: Role::Primary,
        lockfile_path: None,
        config_path: None,
    })
}

fn detect_bundler(dir: &Path, names: &BTreeSet<String>) -> Option<DetectedManager> {
    if !names.contains("Gemfile") {
        return None;
    }
    let config = dir.join(".bundle/config");
    Some(DetectedManager {
        manager: Manager::Bundler,
        role: Role::Primary,
        lockfile_path: existing(dir, names, "Gemfile.lock"),
        config_path: config.is_file().then_some(config),
    })
}

fn detect_composer(
    dir: &Path,
    names: &BTreeSet<String>,
    js_primary: Option<Manager>,
) -> Option<DetectedManager> {
    let has_json = names.contains("composer.json");
    if !has_json && !names.contains("composer.lock") {
        return None;
    }
    let role = if has_json || js_primary.is_none() {
        Role::Primary
    } else {
        Role::Leftover
    };
    Some(DetectedManager {
        manager: Manager::Composer,
        role,
        lockfile_path: existing(dir, names, "composer.lock"),
        config_path: has_json.then(|| dir.join("composer.json")),
    })
}

fn detect_cargo(
    dir: &Path,
    names: &BTreeSet<String>,
    js_primary: Option<Manager>,
) -> Option<DetectedManager> {
    let has_toml = names.contains("Cargo.toml");
    if !has_toml && !names.contains("Cargo.lock") {
        return None;
    }
    let role = if has_toml || js_primary.is_none() {
        Role::Primary
    } else {
        Role::Leftover
    };
    Some(DetectedManager {
        manager: Manager::Cargo,
        role,
        lockfile_path: existing(dir, names, "Cargo.lock"),
        config_path: cargo_config_path(dir),
    })
}

fn detect_managers(dir: &Path) -> Vec<DetectedManager> {
    let names = dir_names(dir);
    let pin = PackageManagerPin::from_manifest(dir);
    let js_primary = pick_js_primary(&names, pin.as_ref());
    let mut managers = Vec::new();
    for detected in [
        detect_pnpm(dir, &names, js_primary),
        detect_yarn(dir, &names, pin.as_ref(), js_primary),
        detect_bun(dir, &names, js_primary),
        detect_npm(dir, &names, pin.as_ref(), js_primary),
    ]
    .into_iter()
    .flatten()
    {
        managers.push(detected);
    }
    let uv = detect_uv(dir, &names, js_primary);
    let uv_present = uv.is_some();
    if let Some(detected) = uv {
        managers.push(detected);
    }
    let poetry = detect_poetry(dir, &names, uv_present);
    let poetry_present = poetry.is_some();
    if let Some(detected) = poetry {
        managers.push(detected);
    }
    let pipenv = detect_pipenv(dir, &names);
    let pipenv_present = pipenv.is_some();
    if let Some(detected) = pipenv {
        managers.push(detected);
    }
    if let Some(detected) = detect_pip(dir, &names, uv_present, poetry_present, pipenv_present) {
        managers.push(detected);
    }
    if let Some(detected) = detect_bundler(dir, &names) {
        managers.push(detected);
    }
    if let Some(detected) = detect_composer(dir, &names, js_primary) {
        managers.push(detected);
    }
    if let Some(detected) = detect_cargo(dir, &names, js_primary) {
        managers.push(detected);
    }
    managers
}

/// Walks `root`, streaming each discovered project into `sink` as it is found.
pub fn discover_projects(root: &Path, sink: &mut dyn FnMut(Project)) {
    for (tree, is_git) in find_repo_trees(root) {
        let mut roots = Vec::new();
        walk_pm_roots(&tree, &tree, true, &mut roots);
        for pm_root in roots {
            sink(Project {
                managers: detect_managers(&pm_root),
                git_root: is_git.then(|| tree.clone()),
                root: pm_root,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::Manager;
    use std::fs;
    use std::path::Path;

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn discover(root: &Path) -> Vec<Project> {
        let mut projects = Vec::new();
        discover_projects(root, &mut |p| projects.push(p));
        projects.sort_by(|a, b| a.root.cmp(&b.root));
        projects
    }

    #[test]
    fn git_repo_with_package_lock_is_single_npm_project() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        write(tmp.path(), "package.json", "{}");
        write(tmp.path(), "package-lock.json", "{}");

        let projects = discover(tmp.path());
        assert_eq!(projects.len(), 1);
        let p = &projects[0];
        assert_eq!(p.root, tmp.path());
        assert_eq!(p.git_root.as_deref(), Some(tmp.path()));
        assert_eq!(p.managers.len(), 1);
        let m = &p.managers[0];
        assert_eq!(m.manager, Manager::Npm);
        assert_eq!(m.role, Role::Primary);
        assert_eq!(
            m.lockfile_path.as_deref(),
            Some(tmp.path().join("package-lock.json").as_path())
        );
    }

    #[test]
    fn folder_of_repos_finds_nested_git_repos() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("a/.git")).unwrap();
        write(tmp.path(), "a/package.json", "{}");
        fs::create_dir_all(tmp.path().join("b/.git")).unwrap();
        write(tmp.path(), "b/package.json", "{}");
        write(tmp.path(), "b/yarn.lock", "");
        write(tmp.path(), "b/.yarnrc.yml", "");

        let projects = discover(tmp.path());
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].root, tmp.path().join("a"));
        assert_eq!(projects[1].root, tmp.path().join("b"));
        assert_eq!(projects[1].managers[0].manager, Manager::Yarn);
        assert_eq!(projects[1].managers[0].role, Role::Primary);
    }

    #[test]
    fn skips_node_modules_but_finds_nested_config_roots() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        write(tmp.path(), "package.json", "{}");
        write(tmp.path(), "node_modules/dep/package.json", "{}");
        write(tmp.path(), "services/api/.npmrc", "");
        write(tmp.path(), "services/api/package.json", "{}");

        let projects = discover(tmp.path());
        let roots: Vec<_> = projects.iter().map(|p| p.root.clone()).collect();
        assert_eq!(
            roots,
            vec![tmp.path().to_path_buf(), tmp.path().join("services/api")]
        );
        // both belong to the same git tree
        assert_eq!(projects[1].git_root.as_deref(), Some(tmp.path()));
    }

    #[test]
    fn pnpm_pin_makes_pnpm_primary_and_yarn_leftover() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"packageManager": "pnpm@9.0.0"}"#,
        );
        write(tmp.path(), "pnpm-lock.yaml", "");
        write(tmp.path(), "yarn.lock", "");

        let projects = discover(tmp.path());
        let by_manager: Vec<_> = projects[0]
            .managers
            .iter()
            .map(|m| (m.manager, m.role))
            .collect();
        assert!(by_manager.contains(&(Manager::Pnpm, Role::Primary)));
        assert!(by_manager.contains(&(Manager::Yarn, Role::Leftover)));
        assert!(!by_manager.iter().any(|(m, _)| *m == Manager::Npm));
    }

    #[test]
    fn bare_package_json_is_npm_primary_without_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        write(tmp.path(), "package.json", "{}");

        let projects = discover(tmp.path());
        let m = &projects[0].managers[0];
        assert_eq!(m.manager, Manager::Npm);
        assert_eq!(m.role, Role::Primary);
        assert_eq!(m.lockfile_path, None);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_cycles_do_not_break_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("a/.git")).unwrap();
        write(tmp.path(), "a/package.json", "{}");
        // cycle back to the repo itself and to the scan root
        std::os::unix::fs::symlink(tmp.path().join("a"), tmp.path().join("a/self")).unwrap();
        std::os::unix::fs::symlink(tmp.path(), tmp.path().join("a/up")).unwrap();

        let projects = discover(tmp.path());
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].root, tmp.path().join("a"));
    }

    #[test]
    fn yarn_classic_is_unsupported() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        write(
            tmp.path(),
            "package.json",
            r#"{"packageManager": "yarn@1.22.0"}"#,
        );
        write(tmp.path(), "yarn.lock", "");

        let projects = discover(tmp.path());
        let m = &projects[0].managers[0];
        assert_eq!(m.manager, Manager::Yarn);
        assert_eq!(m.role, Role::Unsupported);
    }

    fn roles(projects: &[Project]) -> Vec<(Manager, Role)> {
        projects[0]
            .managers
            .iter()
            .map(|m| (m.manager, m.role))
            .collect()
    }

    #[test]
    fn cargo_toml_is_cargo_primary() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        write(tmp.path(), "Cargo.toml", "[package]\nname=\"x\"\n");
        write(tmp.path(), "Cargo.lock", "");
        let found = roles(&discover(tmp.path()));
        assert!(found.contains(&(Manager::Cargo, Role::Primary)));
    }

    #[test]
    fn uv_lock_is_uv_primary_and_poetry_is_leftover() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        write(tmp.path(), "uv.lock", "");
        write(
            tmp.path(),
            "pyproject.toml",
            "[tool.uv]\n\n[tool.poetry]\nname=\"x\"\n",
        );
        write(tmp.path(), "poetry.lock", "");
        let found = roles(&discover(tmp.path()));
        assert!(found.contains(&(Manager::Uv, Role::Primary)));
        assert!(found.contains(&(Manager::Poetry, Role::Leftover)));
    }

    #[test]
    fn composer_and_bundler_and_pip_are_detected() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        write(tmp.path(), "composer.json", "{}");
        write(tmp.path(), "Gemfile", "source 'https://rubygems.org'");
        write(tmp.path(), "requirements.txt", "requests\n");
        let found = roles(&discover(tmp.path()));
        assert!(found.contains(&(Manager::Composer, Role::Primary)));
        assert!(found.contains(&(Manager::Bundler, Role::Primary)));
        assert!(found.contains(&(Manager::Pip, Role::Primary)));
    }
}
