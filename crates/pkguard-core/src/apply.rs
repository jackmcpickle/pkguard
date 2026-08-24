//! Plan and apply settings fixes. Reads and writes config files; never
//! touches lockfiles or package versions.

use crate::discover::Project;
use crate::exec::CommandRunner;
use crate::findings::Finding;
use crate::fix::{ConfigEdit, ConfigFormat, ConfigValue};
use crate::format::{self, EditError};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

const UNSET: &str = "(unset)";
const REMOVED: &str = "(removed)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChange {
    pub project_root: PathBuf,
    pub file: PathBuf,
    pub setting: String,
    pub current: String,
    pub next: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocked {
    DirtyGit(PathBuf),
    Nothing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixPlan {
    pub files: Vec<(PathBuf, String)>,
    pub changes: Vec<PlannedChange>,
    pub skipped: Vec<(PathBuf, SkipReason)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    Forbidden,
    Unparseable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    pub written: Vec<PathBuf>,
    pub skipped: Vec<(PathBuf, SkipReason)>,
    pub changes: Vec<PlannedChange>,
    pub blocked: Option<Blocked>,
}

pub fn plan_fixes(project: &Project, findings: &[Finding]) -> FixPlan {
    let mut by_file: BTreeMap<PathBuf, (ConfigFormat, Vec<ConfigEdit>)> = BTreeMap::new();
    let mut skipped = Vec::new();
    for finding in findings {
        let Some(fix) = finding.fix.as_ref() else {
            continue;
        };
        if is_forbidden_write(&fix.file, &project.root) {
            skipped.push((fix.file.clone(), SkipReason::Forbidden));
            continue;
        }
        let entry = by_file
            .entry(fix.file.clone())
            .or_insert_with(|| (fix.format, Vec::new()));
        entry.1.extend(fix.edits.iter().cloned());
    }

    let mut files = Vec::new();
    let mut changes = Vec::new();
    for (file, (format, edits)) in by_file {
        let raw = std::fs::read_to_string(&file).unwrap_or_default();
        match format::edit(format, &raw, &edits) {
            Ok(next) if next == raw => {}
            Ok(next) => {
                changes.extend(changes_for(&project.root, &file, format, &raw, &edits));
                files.push((file, next));
            }
            Err(EditError::Unparseable(_)) => {
                skipped.push((file, SkipReason::Unparseable));
            }
        }
    }
    FixPlan {
        files,
        changes,
        skipped,
    }
}

pub async fn apply_fixes(
    project: &Project,
    plan: &FixPlan,
    runner: &dyn CommandRunner,
    force: bool,
) -> ApplyResult {
    if plan.files.is_empty() && plan.changes.is_empty() {
        return ApplyResult {
            written: Vec::new(),
            skipped: plan.skipped.clone(),
            changes: Vec::new(),
            blocked: Some(Blocked::Nothing),
        };
    }
    if let Some(dirty) = dirty_git_root(project, runner).await {
        if !force {
            return ApplyResult {
                written: Vec::new(),
                skipped: plan.skipped.clone(),
                changes: plan.changes.clone(),
                blocked: Some(Blocked::DirtyGit(dirty)),
            };
        }
    }

    let mut written = Vec::new();
    for (file, body) in &plan.files {
        if let Some(parent) = file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(file, body).is_ok() {
            written.push(file.clone());
        }
    }
    ApplyResult {
        written,
        skipped: plan.skipped.clone(),
        changes: plan.changes.clone(),
        blocked: None,
    }
}

async fn dirty_git_root(project: &Project, runner: &dyn CommandRunner) -> Option<PathBuf> {
    let root = project.git_root.as_deref()?;
    let output = runner
        .run(&["git".into(), "status".into(), "--porcelain".into()], root)
        .await
        .ok()?;
    if output.code == 0 && !output.stdout.trim().is_empty() {
        Some(root.to_path_buf())
    } else {
        None
    }
}

fn is_forbidden_write(file: &Path, root: &Path) -> bool {
    if file.as_os_str() == "~/.npmrc" || file.starts_with("~") {
        return true;
    }
    let absolute = if file.is_absolute() {
        file.to_path_buf()
    } else {
        root.join(file)
    };
    let lexical_root = normalize(root);
    if !is_inside(&normalize(&absolute), &lexical_root) {
        return true;
    }
    !is_inside(&resolve_path(&absolute), &resolve_path(root))
}

/// Resolve existing prefixes so a symlink inside the project that points
/// outside it is treated as an escape. Missing path tails stay lexical.
fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    let mut cur = path.to_path_buf();
    let mut suffix = Vec::new();
    while !cur.exists() {
        match cur.file_name() {
            Some(name) => {
                suffix.push(name.to_os_string());
                if !cur.pop() {
                    break;
                }
            }
            None => break,
        }
    }
    let mut base = std::fs::canonicalize(&cur).unwrap_or_else(|_| normalize(&cur));
    for part in suffix.into_iter().rev() {
        base.push(part);
    }
    base
}

fn is_inside(file: &Path, root: &Path) -> bool {
    file == root || file.starts_with(root)
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn changes_for(
    project_root: &Path,
    file: &Path,
    format: ConfigFormat,
    raw: &str,
    edits: &[ConfigEdit],
) -> Vec<PlannedChange> {
    edits
        .iter()
        .filter_map(|edit| {
            let current = current_display(format, raw, edit.key());
            let next = match edit {
                ConfigEdit::Unset { .. } => REMOVED.to_string(),
                ConfigEdit::Set { value, .. } => display_value(value),
            };
            if current == next {
                return None;
            }
            Some(PlannedChange {
                project_root: project_root.to_path_buf(),
                file: file.to_path_buf(),
                setting: edit.key().to_string(),
                current,
                next,
            })
        })
        .collect()
}

fn display_value(value: &ConfigValue) -> String {
    match value {
        ConfigValue::Str(s) => s.clone(),
        ConfigValue::Bool(b) => b.to_string(),
        ConfigValue::Int(n) => n.to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| UNSET.to_string()),
    }
}

fn current_display(format: ConfigFormat, raw: &str, key: &str) -> String {
    match format {
        ConfigFormat::Npmrc => format::npmrc::parse(raw)
            .get(key)
            .cloned()
            .unwrap_or_else(|| UNSET.to_string()),
        ConfigFormat::BundleConfig => format::bundle_config::parse(raw)
            .get(key)
            .cloned()
            .unwrap_or_else(|| UNSET.to_string()),
        ConfigFormat::Yaml | ConfigFormat::Toml | ConfigFormat::Json => {
            walk_dotted(parse_structured(format, raw), key)
        }
    }
}

fn parse_structured(format: ConfigFormat, raw: &str) -> serde_json::Value {
    if raw.trim().is_empty() {
        return serde_json::json!({});
    }
    match format {
        ConfigFormat::Json => serde_json::from_str(raw).unwrap_or(serde_json::json!({})),
        ConfigFormat::Yaml => {
            serde_json::to_value(format::yaml::parse(raw)).unwrap_or(serde_json::json!({}))
        }
        ConfigFormat::Toml => raw
            .parse::<toml::Value>()
            .ok()
            .and_then(|value| serde_json::to_value(value).ok())
            .unwrap_or(serde_json::json!({})),
        ConfigFormat::Npmrc | ConfigFormat::BundleConfig => serde_json::json!({}),
    }
}

fn walk_dotted(value: serde_json::Value, key: &str) -> String {
    let mut current = &value;
    for part in key.split('.') {
        current = match current.get(part) {
            Some(child) => child,
            None => return UNSET.to_string(),
        };
    }
    match current {
        serde_json::Value::Null => UNSET.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse_config, resolve_settings};
    use crate::discover::{DetectedManager, Role};
    use crate::exec::{CannedRunner, CommandOutput};
    use crate::findings::{FindingKind, Severity};
    use crate::fix::SettingsFix;
    use crate::manager::Manager;
    use crate::settings::audit_manager_settings;
    use std::fs;
    use std::time::UNIX_EPOCH;

    fn project(root: &Path, git_root: Option<&Path>) -> Project {
        Project {
            root: root.to_path_buf(),
            git_root: git_root.map(Path::to_path_buf),
            managers: Vec::new(),
        }
    }

    fn finding(_root: &Path, file: PathBuf, edits: Vec<ConfigEdit>) -> Finding {
        Finding {
            kind: FindingKind::Settings,
            code: "scripts.unrestricted".into(),
            message: "m".into(),
            severity: Severity::High,
            path: file.to_string_lossy().into_owned(),
            fixable: true,
            manager: Some(Manager::Npm),
            package: None,
            current_version: None,
            fix_version: None,
            fix: Some(SettingsFix::new(file, ConfigFormat::Npmrc, edits)),
        }
    }

    fn npm_finding(root: &Path, edits: Vec<ConfigEdit>) -> Finding {
        finding(root, root.join(".npmrc"), edits)
    }

    fn dirty_runner() -> CannedRunner {
        CannedRunner::new().with(
            &["git", "status", "--porcelain"],
            CommandOutput {
                code: 0,
                stdout: " M .npmrc\n".into(),
                stderr: String::new(),
            },
        )
    }

    #[test]
    fn two_findings_against_the_same_npmrc_merge_into_one_write() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let findings = [
            npm_finding(root, vec![ConfigEdit::set("ignore-scripts", true)]),
            npm_finding(root, vec![ConfigEdit::set("audit", true)]),
        ];
        let plan = plan_fixes(&project(root, None), &findings);
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].0, root.join(".npmrc"));
        assert!(plan.files[0].1.contains("ignore-scripts=true"));
        assert!(plan.files[0].1.contains("audit=true"));
        assert_eq!(plan.changes.len(), 2);
    }

    #[test]
    fn a_fix_escaping_the_project_root_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let escaped = root.join("../../etc/npmrc");
        let findings = [finding(
            root,
            escaped.clone(),
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(root, None), &findings);
        assert!(plan.files.is_empty());
        assert_eq!(plan.skipped, vec![(escaped, SkipReason::Forbidden)]);
    }

    #[test]
    #[test]
    fn a_symlink_escaping_the_project_root_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let outside = tmp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::write(&outside, "ignore-scripts=false\n").unwrap();
        let link = root.join(".npmrc");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let findings = [finding(
            &root,
            link.clone(),
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(&root, None), &findings);
        assert!(plan.files.is_empty(), "symlink escape must not be planned");
        assert_eq!(plan.skipped, vec![(link, SkipReason::Forbidden)]);
        assert_eq!(
            fs::read_to_string(&outside).unwrap(),
            "ignore-scripts=false\n"
        );
    }

    #[test]
    fn a_fix_pointing_at_home_npmrc_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let findings = [finding(
            root,
            PathBuf::from("~/.npmrc"),
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(root, None), &findings);
        assert!(plan.files.is_empty());
        assert_eq!(
            plan.skipped,
            vec![(PathBuf::from("~/.npmrc"), SkipReason::Forbidden)]
        );
    }

    #[tokio::test]
    async fn dirty_git_root_blocks_writes_but_keeps_the_change_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join(".npmrc"), "ignore-scripts=false\n").unwrap();
        let findings = [npm_finding(
            root,
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(root, Some(root)), &findings);
        assert!(!plan.changes.is_empty());
        let result = apply_fixes(&project(root, Some(root)), &plan, &dirty_runner(), false).await;
        assert_eq!(result.blocked, Some(Blocked::DirtyGit(root.to_path_buf())));
        assert!(result.written.is_empty());
        assert_eq!(result.changes, plan.changes);
        assert_eq!(
            fs::read_to_string(root.join(".npmrc")).unwrap(),
            "ignore-scripts=false\n"
        );
    }

    #[tokio::test]
    async fn dirty_git_root_with_force_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join(".npmrc"), "ignore-scripts=false\n").unwrap();
        let findings = [npm_finding(
            root,
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(root, Some(root)), &findings);
        let result = apply_fixes(&project(root, Some(root)), &plan, &dirty_runner(), true).await;
        assert_eq!(result.blocked, None);
        assert_eq!(result.written, vec![root.join(".npmrc")]);
        assert!(fs::read_to_string(root.join(".npmrc"))
            .unwrap()
            .contains("ignore-scripts=true"));
    }

    #[tokio::test]
    async fn non_git_directory_writes_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let findings = [npm_finding(
            root,
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(root, None), &findings);
        let result = apply_fixes(&project(root, None), &plan, &CannedRunner::new(), false).await;
        assert_eq!(result.blocked, None);
        assert_eq!(result.written, vec![root.join(".npmrc")]);
    }

    #[tokio::test]
    async fn already_compliant_file_is_not_rewritten() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let path = root.join(".npmrc");
        fs::write(&path, "ignore-scripts=true\n").unwrap();
        let before = fs::metadata(&path)
            .unwrap()
            .modified()
            .unwrap_or(UNIX_EPOCH);
        let findings = [npm_finding(
            root,
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(root, None), &findings);
        assert!(plan.files.is_empty());
        assert!(plan.changes.is_empty());
        let result = apply_fixes(&project(root, None), &plan, &CannedRunner::new(), false).await;
        assert_eq!(result.blocked, Some(Blocked::Nothing));
        assert!(result.written.is_empty());
        let after = fs::metadata(&path)
            .unwrap()
            .modified()
            .unwrap_or(UNIX_EPOCH);
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn unparseable_file_is_skipped_and_siblings_still_write() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("broken.yml"), "- a list\n").unwrap();
        let yaml = Finding {
            fix: Some(SettingsFix::new(
                root.join("broken.yml"),
                ConfigFormat::Yaml,
                vec![ConfigEdit::set("audit.level", "high")],
            )),
            ..npm_finding(root, vec![])
        };
        let npm = npm_finding(root, vec![ConfigEdit::set("ignore-scripts", true)]);
        let plan = plan_fixes(&project(root, None), &[yaml, npm]);
        assert_eq!(
            plan.skipped,
            vec![(root.join("broken.yml"), SkipReason::Unparseable)]
        );
        assert_eq!(plan.files.len(), 1);
        let result = apply_fixes(&project(root, None), &plan, &CannedRunner::new(), false).await;
        assert_eq!(result.written, vec![root.join(".npmrc")]);
        assert_eq!(
            fs::read_to_string(root.join("broken.yml")).unwrap(),
            "- a list\n"
        );
    }

    #[tokio::test]
    async fn apply_then_rescan_then_apply_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::write(root.join("package.json"), "{}").unwrap();
        fs::write(root.join("package-lock.json"), "lock").unwrap();
        let manager = DetectedManager {
            manager: Manager::Npm,
            role: Role::Primary,
            lockfile_path: Some(root.join("package-lock.json")),
            config_path: None,
        };
        let settings = resolve_settings(&parse_config("preset = \"standard\"").unwrap(), "npm");
        let findings = audit_manager_settings(root, &manager, &settings);
        assert!(findings.iter().any(|f| f.fix.is_some()));
        let proj = project(root, None);
        let plan = plan_fixes(&proj, &findings);
        let first = apply_fixes(&proj, &plan, &CannedRunner::new(), false).await;
        assert!(!first.written.is_empty());

        let findings = audit_manager_settings(root, &manager, &settings);
        let plan = plan_fixes(&proj, &findings);
        assert!(
            plan.files.is_empty(),
            "second pass still wants to write: {:?}",
            plan.changes
        );
        let second = apply_fixes(&proj, &plan, &CannedRunner::new(), false).await;
        assert_eq!(second.blocked, Some(Blocked::Nothing));
        assert!(second.written.is_empty());
    }
}
