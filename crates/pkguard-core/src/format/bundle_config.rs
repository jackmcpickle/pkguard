//! Bundler's `.bundle/config`: a YAML-ish `KEY: "value"` file that bundler
//! itself rewrites. Treated as flat text so comments and key order survive.

use crate::fix::ConfigEdit;
use std::collections::{BTreeMap, BTreeSet};

/// Index of the `key: value` separator. Bundler writes mirror keys such as
/// `BUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/`, so splitting on the first colon
/// would mangle them. Prefer `": "`, then a trailing colon (empty value), and
/// only then fall back to the first colon.
fn separator(line: &str) -> Option<usize> {
    if let Some(index) = line.find(": ").filter(|index| *index > 0) {
        return Some(index);
    }
    if line.ends_with(':') && line.len() > 1 {
        return Some(line.len() - 1);
    }
    line.find(':').filter(|index| *index > 0)
}

fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        return value[1..value.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }
    if bytes.len() >= 2 && bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'' {
        return value[1..value.len() - 1].to_string();
    }
    value.to_string()
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn is_structural(trimmed: &str) -> bool {
    trimmed.is_empty() || trimmed == "---" || trimmed.starts_with('#')
}

pub fn parse(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if is_structural(trimmed) {
            continue;
        }
        let Some(colon) = separator(trimmed) else {
            continue;
        };
        out.insert(
            trimmed[..colon].trim().to_string(),
            unquote(trimmed[colon + 1..].trim()),
        );
    }
    out
}

fn resolve(edits: &[ConfigEdit]) -> (Vec<(String, String)>, BTreeSet<String>) {
    let mut updates: Vec<(String, String)> = Vec::new();
    let mut removed: BTreeSet<String> = BTreeSet::new();
    for edit in edits {
        let key = edit.key().to_string();
        updates.retain(|(existing, _)| existing != &key);
        match edit {
            ConfigEdit::Set { value, .. } => {
                removed.remove(&key);
                updates.push((key, super::npmrc::scalar(value)));
            }
            ConfigEdit::Unset { .. } => {
                removed.insert(key);
            }
        }
    }
    (updates, removed)
}

pub fn edit(raw: &str, edits: &[ConfigEdit]) -> String {
    let (updates, removed) = resolve(edits);
    let lookup: BTreeMap<&str, &str> = updates
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    let mut has_marker = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if is_structural(trimmed) {
            has_marker |= trimmed == "---";
            out.push(line.to_string());
            continue;
        }
        let Some(colon) = separator(trimmed) else {
            out.push(line.to_string());
            continue;
        };
        let key = trimmed[..colon].trim();
        if removed.contains(key) {
            continue;
        }
        match lookup.get(key) {
            Some(value) => {
                seen.insert(key.to_string());
                out.push(format!("{key}: {}", quote(value)));
            }
            None => out.push(line.to_string()),
        }
    }

    while out.last().is_some_and(|line| line.trim().is_empty()) {
        out.pop();
    }
    let appended: Vec<&(String, String)> = updates
        .iter()
        .filter(|(key, _)| !seen.contains(key))
        .collect();
    if out.is_empty() && !appended.is_empty() && !has_marker {
        // Bundler writes the YAML document marker; match it on a fresh file.
        out.push("---".to_string());
    }
    for (key, value) in appended {
        out.push(format!("{key}: {}", quote(value)));
    }
    if out.is_empty() {
        return String::new();
    }
    format!("{}\n", out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_bundler_key_value_shape_into_a_fresh_file() {
        let out = edit("", &[ConfigEdit::set("BUNDLE_COOLDOWN", "7")]);
        assert_eq!(out, "---\nBUNDLE_COOLDOWN: \"7\"\n");
    }

    #[test]
    fn existing_key_is_rewritten_and_the_marker_and_comments_survive() {
        let raw = "---\n# tuned by hand\nBUNDLE_COOLDOWN: \"1\"\nBUNDLE_PATH: \"vendor/bundle\"\n";
        let out = edit(raw, &[ConfigEdit::set("BUNDLE_COOLDOWN", 7i64)]);
        assert_eq!(
            out,
            "---\n# tuned by hand\nBUNDLE_COOLDOWN: \"7\"\nBUNDLE_PATH: \"vendor/bundle\"\n"
        );
    }

    #[test]
    fn mirror_keys_containing_colons_are_not_mangled() {
        let raw = "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/: \"https://mirror.example\"\n";
        let parsed = parse(raw);
        assert_eq!(
            parsed
                .get("BUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/")
                .map(String::as_str),
            Some("https://mirror.example")
        );
        let out = edit(raw, &[ConfigEdit::set("BUNDLE_COOLDOWN", "7")]);
        assert!(out.contains("BUNDLE_MIRROR__HTTPS://RUBYGEMS.ORG/: \"https://mirror.example\""));
    }

    #[test]
    fn unquoted_values_are_read_and_normalized_on_write() {
        assert_eq!(
            parse("---\nBUNDLE_COOLDOWN: 7\n")
                .get("BUNDLE_COOLDOWN")
                .map(String::as_str),
            Some("7")
        );
        let out = edit(
            "---\nBUNDLE_COOLDOWN: 7\n",
            &[ConfigEdit::set("BUNDLE_COOLDOWN", "7")],
        );
        assert_eq!(out, "---\nBUNDLE_COOLDOWN: \"7\"\n");
    }

    #[test]
    fn unset_drops_the_line() {
        let out = edit(
            "---\nBUNDLE_FROZEN: \"false\"\nBUNDLE_PATH: \"vendor\"\n",
            &[ConfigEdit::unset("BUNDLE_FROZEN")],
        );
        assert_eq!(out, "---\nBUNDLE_PATH: \"vendor\"\n");
    }

    #[test]
    fn applying_the_same_edits_twice_is_idempotent() {
        let edits = [ConfigEdit::set("BUNDLE_COOLDOWN", "7")];
        let once = edit("---\nBUNDLE_PATH: \"vendor\"\n", &edits);
        assert_eq!(edit(&once, &edits), once);
    }
}
