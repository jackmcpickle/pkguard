//! JSON config editing (`composer.json`, `package.json`). Key order is
//! preserved via `serde_json`'s `preserve_order` feature so diffs stay small.

use super::EditError;
use crate::fix::{ConfigEdit, ConfigValue};
use serde_json::{Map, Value};

#[must_use]
pub fn to_json(value: &ConfigValue) -> Value {
    match value {
        ConfigValue::Str(s) => Value::String(s.clone()),
        ConfigValue::Bool(b) => Value::Bool(*b),
        ConfigValue::Int(n) => Value::Number((*n).into()),
        ConfigValue::List(items) => {
            Value::Array(items.iter().map(|s| Value::String(s.clone())).collect())
        }
        ConfigValue::Table(map) => Value::Object(
            map.iter()
                .map(|(key, child)| (key.clone(), to_json(child)))
                .collect(),
        ),
    }
}

/// Walk a dotted path, creating intermediate objects. A non-object on the way
/// down is replaced — the check that emitted the edit already decided the
/// current shape is wrong.
fn set_path(table: &mut Map<String, Value>, key: &str, value: Value) {
    match key.split_once('.') {
        None => {
            table.insert(key.to_string(), value);
        }
        Some((head, rest)) => {
            let child = table
                .entry(head.to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if !child.is_object() {
                *child = Value::Object(Map::new());
            }
            if let Some(map) = child.as_object_mut() {
                set_path(map, rest, value);
            }
        }
    }
}

fn unset_path(table: &mut Map<String, Value>, key: &str) {
    match key.split_once('.') {
        None => {
            table.shift_remove(key);
        }
        Some((head, rest)) => {
            if let Some(map) = table.get_mut(head).and_then(Value::as_object_mut) {
                unset_path(map, rest);
            }
        }
    }
}

pub fn apply(table: &mut Map<String, Value>, edits: &[ConfigEdit]) {
    for edit in edits {
        match edit {
            ConfigEdit::Set { key, value } => set_path(table, key, to_json(value)),
            ConfigEdit::Unset { key } => unset_path(table, key),
        }
    }
}

pub fn edit(raw: &str, edits: &[ConfigEdit]) -> Result<String, EditError> {
    let mut table = if raw.trim().is_empty() {
        Map::new()
    } else {
        match serde_json::from_str::<Value>(raw) {
            Ok(Value::Object(map)) => map,
            Ok(_) | Err(_) => return Err(EditError::Unparseable("JSON")),
        }
    };
    apply(&mut table, edits);
    let body = serde_json::to_string_pretty(&Value::Object(table))
        .map_err(|_| EditError::Unparseable("JSON"))?;
    Ok(format!("{body}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_path_creates_intermediate_objects() {
        let out = edit(
            "{}",
            &[
                ConfigEdit::set("config.policy.advisories.block", true),
                ConfigEdit::set("config.policy.advisories.audit", "fail"),
            ],
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["config"]["policy"]["advisories"]["block"], true);
        assert_eq!(parsed["config"]["policy"]["advisories"]["audit"], "fail");
    }

    #[test]
    fn sibling_keys_keep_their_original_order() {
        let raw = r#"{"name":"acme/app","require":{"php":"^8"},"config":{"vendor-dir":"vendor"}}"#;
        let out = edit(raw, &[ConfigEdit::set("config.secure-http", true)]).unwrap();
        let keys: Vec<&str> = out
            .lines()
            .filter_map(|line| line.trim().strip_prefix('"'))
            .filter_map(|rest| rest.split('"').next())
            .collect();
        let top: Vec<&&str> = keys
            .iter()
            .filter(|k| ["name", "require", "config"].contains(k))
            .collect();
        assert_eq!(top, [&"name", &"require", &"config"]);
        // the pre-existing nested key survives alongside the new one
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["config"]["vendor-dir"], "vendor");
        assert_eq!(parsed["config"]["secure-http"], true);
    }

    #[test]
    fn unset_removes_a_nested_key_and_leaves_its_parent() {
        let raw = r#"{"config":{"disable-tls":true,"secure-http":false}}"#;
        let out = edit(
            raw,
            &[
                ConfigEdit::unset("config.disable-tls"),
                ConfigEdit::set("config.secure-http", true),
            ],
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert!(parsed["config"].get("disable-tls").is_none());
        assert_eq!(parsed["config"]["secure-http"], true);
    }

    #[test]
    fn a_non_object_document_is_unparseable() {
        assert_eq!(edit("[1,2]", &[]), Err(EditError::Unparseable("JSON")));
        assert_eq!(edit("{not json", &[]), Err(EditError::Unparseable("JSON")));
    }

    #[test]
    fn output_ends_with_exactly_one_newline() {
        let out = edit("{}", &[ConfigEdit::set("a", true)]).unwrap();
        assert!(out.ends_with("}\n"));
        assert!(!out.ends_with("\n\n"));
    }

    #[test]
    fn applying_the_same_edits_twice_is_idempotent() {
        let edits = [ConfigEdit::set("config.secure-http", true)];
        let once = edit(r#"{"name":"acme/app"}"#, &edits).unwrap();
        assert_eq!(edit(&once, &edits).unwrap(), once);
    }
}
