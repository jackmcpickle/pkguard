use super::EditError;
use crate::fix::{ConfigEdit, ConfigValue};
use serde_yaml::{Mapping, Value};

pub type Yaml = Value;

/// Parse a YAML mapping. Non-mappings and invalid input become an empty map.
#[must_use]
pub fn parse(raw: &str) -> Yaml {
    if raw.trim().is_empty() {
        return Value::Mapping(serde_yaml::Mapping::new());
    }
    match serde_yaml::from_str(raw) {
        Ok(Value::Mapping(map)) => Value::Mapping(map),
        Ok(_) | Err(_) => Value::Mapping(serde_yaml::Mapping::new()),
    }
}

#[must_use]
pub fn get<'a>(value: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    value.as_mapping()?.get(Value::String(key.to_string()))
}

#[must_use]
pub fn first<'a>(value: &'a Yaml, keys: &[&str]) -> Option<&'a Yaml> {
    keys.iter().find_map(|key| get(value, key))
}

#[must_use]
pub fn as_str(value: &Yaml) -> Option<&str> {
    value.as_str()
}

#[must_use]
pub fn as_f64(value: &Yaml) -> Option<f64> {
    value.as_f64().or_else(|| value.as_i64().map(|n| n as f64))
}

pub fn is_true(value: Option<&Yaml>) -> bool {
    value.and_then(Value::as_bool) == Some(true)
}

pub fn is_false(value: Option<&Yaml>) -> bool {
    value.and_then(Value::as_bool) == Some(false)
}

pub fn is_mapping(value: Option<&Yaml>) -> bool {
    value.is_some_and(Value::is_mapping)
}

#[must_use]
pub fn is_star(value: &Yaml) -> bool {
    as_str(value) == Some("*")
}

fn to_yaml(value: &ConfigValue) -> Value {
    match value {
        ConfigValue::Str(s) => Value::String(s.clone()),
        ConfigValue::Bool(b) => Value::Bool(*b),
        ConfigValue::Int(n) => Value::Number((*n).into()),
        ConfigValue::List(items) => {
            Value::Sequence(items.iter().map(|s| Value::String(s.clone())).collect())
        }
        ConfigValue::Table(map) => Value::Mapping(
            map.iter()
                .map(|(key, child)| (Value::String(key.clone()), to_yaml(child)))
                .collect(),
        ),
    }
}

fn set_path(map: &mut Mapping, key: &str, value: Value) {
    match key.split_once('.') {
        None => {
            map.insert(Value::String(key.to_string()), value);
        }
        Some((head, rest)) => {
            let slot = Value::String(head.to_string());
            if !map.get(&slot).is_some_and(Value::is_mapping) {
                map.insert(slot.clone(), Value::Mapping(Mapping::new()));
            }
            if let Some(Value::Mapping(child)) = map.get_mut(&slot) {
                set_path(child, rest, value);
            }
        }
    }
}

fn unset_path(map: &mut Mapping, key: &str) {
    match key.split_once('.') {
        None => {
            map.remove(Value::String(key.to_string()));
        }
        Some((head, rest)) => {
            if let Some(Value::Mapping(child)) = map.get_mut(Value::String(head.to_string())) {
                unset_path(child, rest);
            }
        }
    }
}

/// Edit a YAML config (`.yarnrc.yml`, `pnpm-workspace.yaml`).
///
/// Comments are lost: `serde_yaml` has no comment-preserving edit mode. This
/// matches the behaviour of the TypeScript implementation this was ported from.
///
/// # Errors
///
/// Returns [`EditError::Unparseable`] if `raw` is not valid YAML.
pub fn edit(raw: &str, edits: &[ConfigEdit]) -> Result<String, EditError> {
    let mut map = if raw.trim().is_empty() {
        Mapping::new()
    } else {
        match serde_yaml::from_str::<Value>(raw) {
            Ok(Value::Mapping(map)) => map,
            Ok(_) | Err(_) => return Err(EditError::Unparseable("YAML")),
        }
    };
    for edit in edits {
        match edit {
            ConfigEdit::Set { key, value } => set_path(&mut map, key, to_yaml(value)),
            ConfigEdit::Unset { key } => unset_path(&mut map, key),
        }
    }
    if map.is_empty() {
        return Ok(String::new());
    }
    serde_yaml::to_string(&Value::Mapping(map)).map_err(|_| EditError::Unparseable("YAML"))
}

pub fn is_blanket_exclude(value: Option<&Yaml>) -> bool {
    let Some(value) = value else {
        return false;
    };
    if is_star(value) {
        return true;
    }
    if let Some(items) = value.as_sequence() {
        return items.iter().any(is_star);
    }
    if let Some(map) = value.as_mapping() {
        return map.keys().any(|key| as_str(key).is_some_and(|s| s == "*"));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_key_is_written_as_a_nested_map() {
        let out = edit("", &[ConfigEdit::set("audit.level", "high")]).unwrap();
        let parsed = parse(&out);
        assert_eq!(
            get(&parsed, "audit")
                .and_then(|audit| get(audit, "level"))
                .and_then(as_str),
            Some("high")
        );
    }

    #[test]
    fn existing_sibling_keys_survive_an_edit() {
        let raw = "registry: https://r.example\naudit:\n  level: low\n";
        let out = edit(raw, &[ConfigEdit::set("audit.level", "high")]).unwrap();
        let parsed = parse(&out);
        assert_eq!(
            get(&parsed, "registry").and_then(as_str),
            Some("https://r.example")
        );
        assert_eq!(
            get(&parsed, "audit")
                .and_then(|audit| get(audit, "level"))
                .and_then(as_str),
            Some("high")
        );
    }

    // A blanket `*` must be replaced outright, never merged into, or the
    // wildcard would survive alongside the narrower value we just wrote.
    #[test]
    fn a_blanket_star_value_is_replaced_not_merged() {
        let raw = "minimumReleaseAgeExclude: \"*\"\n";
        let out = edit(
            raw,
            &[ConfigEdit::set(
                "minimumReleaseAgeExclude",
                ConfigValue::List(vec![]),
            )],
        )
        .unwrap();
        let parsed = parse(&out);
        assert!(!is_blanket_exclude(get(
            &parsed,
            "minimumReleaseAgeExclude"
        )));
    }

    #[test]
    fn a_scalar_in_the_path_is_replaced_by_a_map() {
        let out = edit("audit: true\n", &[ConfigEdit::set("audit.level", "high")]).unwrap();
        let parsed = parse(&out);
        assert!(is_mapping(get(&parsed, "audit")));
    }

    #[test]
    fn unset_removes_the_key() {
        let raw = "audit: true\nnpmAudit: true\nenableNpmAudit: false\n";
        let out = edit(
            raw,
            &[
                ConfigEdit::unset("audit"),
                ConfigEdit::unset("npmAudit"),
                ConfigEdit::set("enableNpmAudit", true),
            ],
        )
        .unwrap();
        let parsed = parse(&out);
        assert!(get(&parsed, "audit").is_none());
        assert!(get(&parsed, "npmAudit").is_none());
        assert!(is_true(get(&parsed, "enableNpmAudit")));
    }

    #[test]
    fn a_non_mapping_document_is_unparseable() {
        assert_eq!(
            edit("- just a list\n", &[]),
            Err(EditError::Unparseable("YAML"))
        );
        assert_eq!(
            edit("key: [unclosed\n", &[]),
            Err(EditError::Unparseable("YAML"))
        );
    }

    #[test]
    fn applying_the_same_edits_twice_is_idempotent() {
        let edits = [ConfigEdit::set("enableScripts", false)];
        let once = edit("registry: https://r.example\n", &edits).unwrap();
        assert_eq!(edit(&once, &edits).unwrap(), once);
    }

    #[test]
    fn yaml_parses_nested_maps_and_ignores_non_maps() {
        let parsed = parse("allowBuilds:\n  esbuild: false\naudit:\n  level: high\n");
        assert_eq!(
            get(&parsed, "audit")
                .and_then(|audit| get(audit, "level"))
                .and_then(as_str),
            Some("high")
        );
        assert!(is_false(
            get(&parsed, "allowBuilds").and_then(|builds| get(builds, "esbuild"))
        ));
        assert!(parse("- just a list\n").as_mapping().unwrap().is_empty());
    }
}
