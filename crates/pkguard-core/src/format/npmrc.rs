use crate::fix::{ConfigEdit, ConfigValue};
use std::collections::{BTreeMap, BTreeSet};

/// npmrc / ini-style key=value parse; comments start with `#` or `;`.
#[must_use]
pub fn parse(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        if eq == 0 {
            continue;
        }
        let key = trimmed[..eq].trim().to_string();
        let value = trimmed[eq + 1..].trim().to_string();
        out.insert(key, value);
    }
    out
}

/// npmrc is flat, so values are always scalars. Lists and tables are not
/// expressible; JSON is the least-wrong fallback and no check emits one.
#[must_use]
pub fn scalar(value: &ConfigValue) -> String {
    match value {
        ConfigValue::Str(s) => s.clone(),
        ConfigValue::Bool(b) => b.to_string(),
        ConfigValue::Int(n) => n.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Fold the edit list into a final key -> value map plus a removal set. Later
/// edits win, so a set after an unset resurrects the key and vice versa.
fn resolve(edits: &[ConfigEdit]) -> (Vec<(String, String)>, BTreeSet<String>) {
    let mut updates: Vec<(String, String)> = Vec::new();
    let mut removed: BTreeSet<String> = BTreeSet::new();
    for edit in edits {
        let key = edit.key().to_string();
        updates.retain(|(existing, _)| existing != &key);
        match edit {
            ConfigEdit::Set { value, .. } => {
                removed.remove(&key);
                updates.push((key, scalar(value)));
            }
            ConfigEdit::Unset { .. } => {
                removed.insert(key);
            }
        }
    }
    (updates, removed)
}

/// Line-oriented rewrite: existing keys are replaced in place, unknown keys are
/// appended, and everything else — comments, blanks, ordering — is untouched.
#[must_use]
pub fn edit(raw: &str, edits: &[ConfigEdit]) -> String {
    let (updates, removed) = resolve(edits);
    let lookup: BTreeMap<&str, &str> = updates
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            out.push(line.to_string());
            continue;
        }
        let Some(eq) = trimmed.find('=').filter(|eq| *eq > 0) else {
            out.push(line.to_string());
            continue;
        };
        let key = trimmed[..eq].trim();
        if removed.contains(key) {
            continue;
        }
        match lookup.get(key) {
            Some(value) => {
                seen.insert(key.to_string());
                out.push(format!("{key}={value}"));
            }
            None => out.push(line.to_string()),
        }
    }

    while out.last().is_some_and(|line| line.trim().is_empty()) {
        out.pop();
    }
    for (key, value) in &updates {
        if !seen.contains(key) {
            out.push(format!("{key}={value}"));
        }
    }
    if out.is_empty() {
        return String::new();
    }
    format!("{}\n", out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(key: &str, value: impl Into<ConfigValue>) -> ConfigEdit {
        ConfigEdit::set(key, value)
    }

    #[test]
    fn existing_key_is_rewritten_in_place_and_comments_survive() {
        let raw = "# keep me\nignore-scripts=false\n\n; and me\nregistry=https://r.example\n";
        let out = edit(raw, &[set("ignore-scripts", true)]);
        assert_eq!(
            out,
            "# keep me\nignore-scripts=true\n\n; and me\nregistry=https://r.example\n"
        );
    }

    #[test]
    fn absent_key_is_appended_with_one_trailing_newline() {
        let out = edit("registry=https://r.example", &[set("ignore-scripts", true)]);
        assert_eq!(out, "registry=https://r.example\nignore-scripts=true\n");
    }

    #[test]
    fn trailing_blank_lines_do_not_push_appended_keys_down() {
        let out = edit("registry=https://r.example\n\n\n", &[set("audit", true)]);
        assert_eq!(out, "registry=https://r.example\naudit=true\n");
    }

    #[test]
    fn unset_removes_the_line_without_leaving_a_gap() {
        let raw = "a=1\ndangerously-allow-all-scripts=true\nb=2\n";
        let out = edit(raw, &[ConfigEdit::unset("dangerously-allow-all-scripts")]);
        assert_eq!(out, "a=1\nb=2\n");
    }

    #[test]
    fn empty_file_gets_just_the_new_keys() {
        let out = edit("", &[set("ignore-scripts", true), set("audit", true)]);
        assert_eq!(out, "ignore-scripts=true\naudit=true\n");
    }

    #[test]
    fn later_edits_win_over_earlier_ones_for_the_same_key() {
        let out = edit("", &[set("audit", false), ConfigEdit::unset("audit")]);
        assert_eq!(out, "");
        let out = edit("", &[ConfigEdit::unset("audit"), set("audit", true)]);
        assert_eq!(out, "audit=true\n");
    }

    #[test]
    fn scalars_render_without_quotes() {
        let out = edit(
            "",
            &[
                set("min-release-age", 7i64),
                set("registry", "https://r.example"),
                set("audit", true),
            ],
        );
        assert_eq!(
            out,
            "min-release-age=7\nregistry=https://r.example\naudit=true\n"
        );
    }

    #[test]
    fn applying_the_same_edits_twice_is_idempotent() {
        let edits = [set("ignore-scripts", true), ConfigEdit::unset("audit")];
        let once = edit("audit=false\nregistry=https://r.example\n", &edits);
        assert_eq!(edit(&once, &edits), once);
    }

    #[test]
    fn npmrc_parses_key_values_and_skips_comments() {
        let parsed = parse(
            "# comment\n; also comment\n\nignore-scripts = true\nregistry=https://r.example\nbroken-line\n",
        );
        assert_eq!(
            parsed.get("ignore-scripts").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            parsed.get("registry").map(String::as_str),
            Some("https://r.example")
        );
        assert_eq!(parsed.len(), 2);
    }
}
