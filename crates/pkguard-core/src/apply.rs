//! Plan and apply settings fixes. Reads and writes config files; never
//! touches lockfiles or package versions.

use crate::discover::Project;
use crate::exec::CommandRunner;
use crate::findings::Finding;
use crate::fix::{ConfigEdit, ConfigFormat, ConfigValue};
use crate::format::{self, EditError};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let mut skipped = plan.skipped.clone();
    for (file, body) in &plan.files {
        if is_forbidden_write(file, &project.root) {
            skipped.push((file.clone(), SkipReason::Forbidden));
            continue;
        }
        if write_inside_root(file, body, &project.root) {
            written.push(file.clone());
        }
    }
    let changes = plan
        .changes
        .iter()
        .filter(|change| written.iter().any(|path| path == &change.file))
        .cloned()
        .collect();
    ApplyResult {
        written,
        skipped,
        changes,
        blocked: None,
    }
}

/// Write through a capability handle on the project root.
///
/// Every path here is resolved by `cap-std` relative to an open root
/// directory, one component at a time, refusing any symlink or `..` that
/// leaves the root. Resolution happens inside the syscall, so a concurrent
/// swap of the destination or of any parent directory cannot redirect the
/// write outside the project — there is no check-then-use window to race.
///
/// The body lands in a fresh temp sibling opened `create_new` (`O_EXCL`, which
/// never follows a symlink), then a sandboxed rename puts it in place.
fn write_inside_root(file: &Path, body: &str, root: &Path) -> bool {
    let Some(relative) = relative_to_root(file, root) else {
        return false;
    };
    let Ok(dir) = Dir::open_ambient_dir(root, ambient_authority()) else {
        return false;
    };
    if let Some(parent) = relative.parent().filter(|p| !p.as_os_str().is_empty()) {
        // A parent that is a symlink reports `AlreadyExists` rather than
        // succeeding. Let it through: opening the temp file below resolves the
        // parent inside the sandbox, so that is where containment is decided.
        match dir.create_dir_all(parent) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return false,
        }
    }
    let Some(tmp) = create_temp_sibling(&dir, &relative) else {
        return false;
    };
    let wrote = {
        let mut handle = match dir.open_with(&tmp, OpenOptions::new().write(true)) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = dir.remove_file(&tmp);
                return false;
            }
        };
        handle.write_all(body.as_bytes()).is_ok()
    };
    if wrote && dir.rename(&tmp, &dir, &relative).is_ok() {
        return true;
    }
    let _ = dir.remove_file(&tmp);
    false
}

/// Lexical path of `file` beneath `root`, or `None` when it is not beneath it.
/// Containment is re-checked by `cap-std` on every component during the write;
/// this only turns the planned absolute path into something root-relative.
fn relative_to_root(file: &Path, root: &Path) -> Option<PathBuf> {
    let absolute = if file.is_absolute() {
        normalize(file)
    } else {
        normalize(&root.join(file))
    };
    let relative = absolute.strip_prefix(normalize(root)).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }
    Some(relative.to_path_buf())
}

/// Claim an unused temp name next to `relative` with `create_new`, so an
/// attacker who guesses the name cannot pre-plant a file or symlink for us
/// to write through — the open fails instead.
fn create_temp_sibling(dir: &Dir, relative: &Path) -> Option<PathBuf> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let base = relative.file_name()?.to_os_string();
    for _ in 0..TEMP_ATTEMPTS {
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let mut name = base.clone();
        name.push(format!(
            ".{}.{stamp:08x}{nonce:04x}.pkguard-tmp",
            process::id()
        ));
        let candidate = relative.with_file_name(name);
        match dir.open_with(&candidate, OpenOptions::new().write(true).create_new(true)) {
            Ok(_) => return Some(candidate),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

const TEMP_ATTEMPTS: u8 = 16;

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
    match (resolve_path(&absolute), resolve_path(root)) {
        (Some(file), Some(resolved_root)) => !is_inside(&file, &resolved_root),
        _ => true,
    }
}

/// Resolve existing prefixes so a symlink inside the project that points
/// outside it is treated as an escape. Missing path tails stay lexical.
/// Broken symlinks are followed by their link text. An unresolved chain
/// (cycle or depth cap) is `None` so the write is refused.
fn resolve_path(path: &Path) -> Option<PathBuf> {
    resolve_path_inner(path, 0)
}

const SYMLINK_DEPTH: u8 = 8;

fn resolve_path_inner(path: &Path, depth: u8) -> Option<PathBuf> {
    if let Ok(real) = std::fs::canonicalize(path) {
        return Some(real);
    }
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        if depth >= SYMLINK_DEPTH {
            return None;
        }
        let target = std::fs::read_link(path).ok()?;
        let dest = if target.is_absolute() {
            target
        } else {
            path.parent().unwrap_or(Path::new(".")).join(target)
        };
        return resolve_path_inner(&dest, depth + 1);
    }
    let mut cur = path.to_path_buf();
    let mut suffix = Vec::new();
    while !cur.exists()
        && std::fs::symlink_metadata(&cur)
            .map(|m| !m.file_type().is_symlink())
            .unwrap_or(true)
    {
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
    if std::fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) {
        let mut dest = resolve_path_inner(&cur, depth)?;
        for part in suffix.into_iter().rev() {
            dest.push(part);
        }
        return Some(dest);
    }
    let mut base = std::fs::canonicalize(&cur).unwrap_or_else(|_| normalize(&cur));
    for part in suffix.into_iter().rev() {
        base.push(part);
    }
    Some(base)
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
    fn a_broken_symlink_escaping_the_project_root_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let outside = tmp.path().join("outside");
        fs::create_dir(&root).unwrap();
        let link = root.join(".npmrc");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let findings = [finding(
            &root,
            link.clone(),
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(&root, None), &findings);
        assert!(
            plan.files.is_empty(),
            "broken symlink escape must not be planned"
        );
        assert_eq!(plan.skipped, vec![(link, SkipReason::Forbidden)]);
        assert!(
            !outside.exists(),
            "write must not create the outside target"
        );
    }

    #[test]
    fn a_long_broken_symlink_chain_escaping_the_project_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let outside = tmp.path().join("outside");
        fs::create_dir(&root).unwrap();
        let mut target = outside.clone();
        for i in 0..12 {
            let link = root.join(format!("hop{i}"));
            std::os::unix::fs::symlink(&target, &link).unwrap();
            target = link;
        }
        let npmrc = root.join(".npmrc");
        std::os::unix::fs::symlink(&target, &npmrc).unwrap();
        let findings = [finding(
            &root,
            npmrc.clone(),
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(&root, None), &findings);
        assert!(
            plan.files.is_empty(),
            "deep symlink chain must not be planned"
        );
        assert_eq!(plan.skipped, vec![(npmrc, SkipReason::Forbidden)]);
        assert!(!outside.exists());
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
    async fn a_symlink_swap_after_plan_does_not_write_outside() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let outside = tmp.path().join("outside");
        fs::create_dir(&root).unwrap();
        let npmrc = root.join(".npmrc");
        fs::write(&npmrc, "ignore-scripts=false\n").unwrap();
        let findings = [finding(
            &root,
            npmrc.clone(),
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(&root, None), &findings);
        assert!(!plan.files.is_empty());
        fs::remove_file(&npmrc).unwrap();
        std::os::unix::fs::symlink(&outside, &npmrc).unwrap();
        let result = apply_fixes(&project(&root, None), &plan, &CannedRunner::new(), false).await;
        assert!(result.written.is_empty());
        assert!(result.changes.is_empty());
        assert_eq!(result.skipped, vec![(npmrc, SkipReason::Forbidden)]);
        assert!(
            !outside.exists(),
            "write followed a swapped symlink: {}",
            fs::read_to_string(&outside).unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn a_parent_symlink_swap_after_plan_does_not_write_outside() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let outside = tmp.path().join("outside");
        let pkg = root.join("pkg");
        fs::create_dir_all(&pkg).unwrap();
        fs::create_dir(&outside).unwrap();
        let npmrc = pkg.join(".npmrc");
        fs::write(&npmrc, "ignore-scripts=false\n").unwrap();
        let findings = [finding(
            &root,
            npmrc.clone(),
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(&root, None), &findings);
        assert!(!plan.files.is_empty());
        fs::remove_file(&npmrc).unwrap();
        fs::remove_dir(&pkg).unwrap();
        std::os::unix::fs::symlink(&outside, &pkg).unwrap();
        let result = apply_fixes(&project(&root, None), &plan, &CannedRunner::new(), false).await;
        assert!(result.written.is_empty());
        assert!(result.changes.is_empty());
        assert_eq!(result.skipped, vec![(npmrc, SkipReason::Forbidden)]);
        assert!(
            !outside.join(".npmrc").exists(),
            "write followed a swapped parent symlink"
        );
    }

    /// The tests above stop escapes at `is_forbidden_write`, which is a
    /// check before the write. These call `write_inside_root` directly with
    /// the swap already in place — the state a racing attacker would create
    /// after that check passed — so only the capability sandbox can refuse.
    mod racing_the_write {
        use super::*;

        fn tmp_residue(dir: &Path) -> Vec<PathBuf> {
            fs::read_dir(dir)
                .unwrap()
                .filter_map(|entry| {
                    let path = entry.unwrap().path();
                    let name = path.file_name()?.to_string_lossy().into_owned();
                    name.contains("pkguard-tmp").then_some(path)
                })
                .collect()
        }

        #[test]
        fn a_destination_symlink_swapped_in_after_the_check_is_replaced_not_followed() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("proj");
            let outside = tmp.path().join("outside");
            fs::create_dir(&root).unwrap();
            let npmrc = root.join(".npmrc");
            std::os::unix::fs::symlink(&outside, &npmrc).unwrap();

            // The body goes to a temp sibling and is renamed over the link.
            // Rename replaces the link rather than following it, so the write
            // lands inside the project and `outside` is never created.
            assert!(write_inside_root(&npmrc, "ignore-scripts=true\n", &root));
            assert!(!outside.exists(), "write followed the swapped destination");
            assert!(
                !fs::symlink_metadata(&npmrc)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the swapped link survived the write"
            );
            assert_eq!(fs::read_to_string(&npmrc).unwrap(), "ignore-scripts=true\n");
            assert!(tmp_residue(&root).is_empty(), "temp file left behind");
        }

        #[test]
        fn a_parent_symlink_swapped_in_after_the_check_is_refused() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("proj");
            let outside = tmp.path().join("outside");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&outside).unwrap();
            let pkg = root.join("pkg");
            std::os::unix::fs::symlink(&outside, &pkg).unwrap();

            let npmrc = pkg.join(".npmrc");
            assert!(!write_inside_root(&npmrc, "ignore-scripts=true\n", &root));
            assert_eq!(
                fs::read_dir(&outside).unwrap().count(),
                0,
                "write escaped through the swapped parent"
            );
        }

        #[test]
        fn a_relative_parent_symlink_inside_the_root_still_writes() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("proj");
            let real = root.join("real");
            fs::create_dir_all(&real).unwrap();
            std::os::unix::fs::symlink("real", root.join("pkg")).unwrap();

            let npmrc = root.join("pkg/.npmrc");
            assert!(write_inside_root(&npmrc, "ignore-scripts=true\n", &root));
            assert_eq!(
                fs::read_to_string(real.join(".npmrc")).unwrap(),
                "ignore-scripts=true\n"
            );
        }

        /// An absolute symlink target cannot be verified against the root
        /// without re-introducing a resolve-then-write gap, so the sandbox
        /// refuses it even when it happens to point back inside. Writes fail
        /// closed: pkguard reports the file as unfixed and touches nothing.
        #[test]
        fn an_absolute_parent_symlink_is_refused_even_pointing_back_inside() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("proj");
            let real = root.join("real");
            fs::create_dir_all(&real).unwrap();
            std::os::unix::fs::symlink(&real, root.join("pkg")).unwrap();

            let npmrc = root.join("pkg/.npmrc");
            assert!(!write_inside_root(&npmrc, "ignore-scripts=true\n", &root));
            assert!(!real.join(".npmrc").exists());
            assert!(tmp_residue(&real).is_empty(), "temp file left behind");
        }

        #[test]
        fn a_traversing_path_is_refused_before_any_handle_is_opened() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("proj");
            fs::create_dir(&root).unwrap();

            let escaped = root.join("../outside/.npmrc");
            assert!(!write_inside_root(&escaped, "ignore-scripts=true\n", &root));
            assert!(!tmp.path().join("outside").exists());
        }

        #[test]
        fn the_root_itself_is_not_a_writable_destination() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("proj");
            fs::create_dir(&root).unwrap();

            assert!(!write_inside_root(&root, "ignore-scripts=true\n", &root));
        }

        #[test]
        fn a_successful_write_leaves_no_temp_file_behind() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let npmrc = root.join("nested/deep/.npmrc");

            assert!(write_inside_root(&npmrc, "ignore-scripts=true\n", root));
            assert_eq!(fs::read_to_string(&npmrc).unwrap(), "ignore-scripts=true\n");
            assert!(tmp_residue(root.join("nested/deep").as_path()).is_empty());
        }

        #[test]
        fn temp_names_are_not_reused_across_concurrent_writes() {
            let tmp = tempfile::tempdir().unwrap();
            let dir = Dir::open_ambient_dir(tmp.path(), ambient_authority()).unwrap();
            let relative = Path::new(".npmrc");

            let first = create_temp_sibling(&dir, relative).unwrap();
            let second = create_temp_sibling(&dir, relative).unwrap();
            assert_ne!(
                first, second,
                "a second write reused a live temp name: {first:?}"
            );
        }
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
    async fn failed_write_is_not_reported_as_fixed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join(".npmrc")).unwrap();
        let findings = [npm_finding(
            root,
            vec![ConfigEdit::set("ignore-scripts", true)],
        )];
        let plan = plan_fixes(&project(root, None), &findings);
        assert!(!plan.changes.is_empty());
        let result = apply_fixes(&project(root, None), &plan, &CannedRunner::new(), false).await;
        assert!(result.written.is_empty());
        assert!(
            result.changes.is_empty(),
            "failed writes must not appear as fixed: {:?}",
            result.changes
        );
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
