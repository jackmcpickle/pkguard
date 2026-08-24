//! TOML config editing (`bunfig.toml`, `uv.toml`, `pyproject.toml`,
//! `.cargo/config.toml`) via `toml_edit`, which preserves comments,
//! whitespace, and key order in the parts of the file it does not touch.

use super::EditError;
use crate::fix::{ConfigEdit, ConfigValue};
use toml_edit::{value as toml_value, Array, DocumentMut, Item, Table};

fn to_item(value: &ConfigValue) -> Item {
    match value {
        ConfigValue::Str(s) => toml_value(s.as_str()),
        ConfigValue::Bool(b) => toml_value(*b),
        ConfigValue::Int(n) => toml_value(*n),
        ConfigValue::List(items) => {
            let mut array = Array::new();
            for item in items {
                array.push(item.as_str());
            }
            toml_value(array)
        }
        ConfigValue::Table(map) => {
            let mut table = Table::new();
            table.set_implicit(false);
            for (key, child) in map {
                table.insert(key, to_item(child));
            }
            Item::Table(table)
        }
    }
}

/// Walk a dotted path, creating implicit intermediate tables. An implicit
/// table renders as `[a.b]` rather than an empty `[a]` header, which keeps
/// `pyproject.toml` edits from adding noise.
fn set_path(table: &mut Table, key: &str, value: Item) {
    match key.split_once('.') {
        // Assign through `get_mut` when the key exists: `insert` swaps in a
        // fresh `Key` and drops the comment attached to the old one.
        None => match table.get_mut(key) {
            Some(existing) => *existing = value,
            None => {
                table.insert(key, value);
            }
        },
        Some((head, rest)) => {
            if !table.contains_key(head) || table[head].as_table_like().is_none() {
                let mut child = Table::new();
                child.set_implicit(true);
                table.insert(head, Item::Table(child));
            }
            if let Some(child) = table[head].as_table_mut() {
                set_path(child, rest, value);
            }
        }
    }
}

fn unset_path(table: &mut Table, key: &str) {
    match key.split_once('.') {
        None => {
            table.remove(key);
        }
        Some((head, rest)) => {
            if let Some(child) = table.get_mut(head).and_then(Item::as_table_mut) {
                unset_path(child, rest);
            }
        }
    }
}

pub fn edit(raw: &str, edits: &[ConfigEdit]) -> Result<String, EditError> {
    let mut doc = raw
        .parse::<DocumentMut>()
        .map_err(|_| EditError::Unparseable("TOML"))?;
    let table = doc.as_table_mut();
    for edit in edits {
        match edit {
            ConfigEdit::Set { key, value } => set_path(table, key, to_item(value)),
            ConfigEdit::Unset { key } => unset_path(table, key),
        }
    }
    let body = doc.to_string();
    Ok(if body.ends_with('\n') {
        body
    } else {
        format!("{body}\n")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_key_is_created_in_an_empty_file() {
        let out = edit("", &[ConfigEdit::set("install.ignoreScripts", true)]).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(parsed["install"]["ignoreScripts"].as_bool(), Some(true));
    }

    #[test]
    fn existing_table_is_updated_and_its_comments_survive() {
        let raw = "# tuned by hand\n[install]\n# keep scripts off\nignoreScripts = false\nregistry = \"https://r.example\"\n";
        let out = edit(raw, &[ConfigEdit::set("install.ignoreScripts", true)]).unwrap();
        assert!(out.contains("# tuned by hand"));
        assert!(out.contains("# keep scripts off"));
        assert!(out.contains("ignoreScripts = true"));
        assert!(out.contains("registry = \"https://r.example\""));
    }

    #[test]
    fn tool_uv_key_lands_in_pyproject_without_disturbing_project() {
        let raw = "[project]\nname = \"app\"\nversion = \"0.1.0\"\n";
        let out = edit(
            raw,
            &[ConfigEdit::set("tool.uv.exclude-newer", "2026-08-01")],
        )
        .unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(parsed["project"]["name"].as_str(), Some("app"));
        assert_eq!(parsed["project"]["version"].as_str(), Some("0.1.0"));
        assert_eq!(
            parsed["tool"]["uv"]["exclude-newer"].as_str(),
            Some("2026-08-01")
        );
        // implicit parent: no bare `[tool]` header is emitted
        assert!(!out.contains("\n[tool]\n"));
    }

    #[test]
    fn integers_and_lists_write_as_native_toml() {
        let out = edit(
            "",
            &[
                ConfigEdit::set("install.minimumReleaseAge", 604800i64),
                ConfigEdit::set("source.allowed", ConfigValue::List(vec!["registry".into()])),
            ],
        )
        .unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(
            parsed["install"]["minimumReleaseAge"].as_integer(),
            Some(604800)
        );
        assert_eq!(parsed["source"]["allowed"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn unset_removes_a_nested_key_only() {
        let raw = "[install]\nignoreScripts = true\nregistry = \"https://r.example\"\n";
        let out = edit(raw, &[ConfigEdit::unset("install.registry")]).unwrap();
        let parsed: toml::Value = toml::from_str(&out).unwrap();
        assert!(parsed["install"].get("registry").is_none());
        assert_eq!(parsed["install"]["ignoreScripts"].as_bool(), Some(true));
    }

    #[test]
    fn malformed_toml_is_unparseable() {
        assert_eq!(
            edit("[install\nbroken", &[]),
            Err(EditError::Unparseable("TOML"))
        );
    }

    #[test]
    fn applying_the_same_edits_twice_is_idempotent() {
        let edits = [ConfigEdit::set("install.ignoreScripts", true)];
        let once = edit("[project]\nname = \"app\"\n", &edits).unwrap();
        assert_eq!(edit(&once, &edits).unwrap(), once);
    }
}
