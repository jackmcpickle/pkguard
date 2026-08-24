//! The fix payload a settings finding carries.
//!
//! Which file to edit, in which format, and which key/value edits to make.
//! Pure data — the writers live in `format`, and the safety rules and disk IO
//! live in `apply`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A value a config edit can write. Mirrors the intersection of what npmrc,
/// YAML, TOML, JSON, and bundler's config format can all represent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<String>),
    Table(BTreeMap<String, Self>),
}

impl From<bool> for ConfigValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for ConfigValue {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<&str> for ConfigValue {
    fn from(value: &str) -> Self {
        Self::Str(value.to_string())
    }
}

impl From<String> for ConfigValue {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

/// One edit against a config file. `key` is dotted: a nested path for the
/// structured formats (YAML, TOML, JSON), a literal key for the flat ones
/// (npmrc, bundle-config).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum ConfigEdit {
    Set { key: String, value: ConfigValue },
    Unset { key: String },
}

impl ConfigEdit {
    pub fn set(key: impl Into<String>, value: impl Into<ConfigValue>) -> Self {
        Self::Set {
            key: key.into(),
            value: value.into(),
        }
    }

    pub fn unset(key: impl Into<String>) -> Self {
        Self::Unset { key: key.into() }
    }

    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Set { key, .. } | Self::Unset { key } => key,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigFormat {
    Npmrc,
    Yaml,
    Toml,
    Json,
    BundleConfig,
}

/// Everything `--fix` needs to repair one finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsFix {
    pub file: PathBuf,
    pub format: ConfigFormat,
    pub edits: Vec<ConfigEdit>,
}

impl SettingsFix {
    pub fn new(file: impl Into<PathBuf>, format: ConfigFormat, edits: Vec<ConfigEdit>) -> Self {
        Self {
            file: file.into(),
            format,
            edits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, FindingKind, Severity};

    #[test]
    fn settings_fix_round_trips_as_camel_case_json() {
        let fix = SettingsFix::new(
            "/p/.npmrc",
            ConfigFormat::Npmrc,
            vec![
                ConfigEdit::set("ignore-scripts", true),
                ConfigEdit::unset("dangerously-allow-all-scripts"),
            ],
        );
        let json = serde_json::to_value(&fix).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "file": "/p/.npmrc",
                "format": "npmrc",
                "edits": [
                    {"op": "set", "key": "ignore-scripts", "value": true},
                    {"op": "unset", "key": "dangerously-allow-all-scripts"},
                ],
            })
        );
        assert_eq!(serde_json::from_value::<SettingsFix>(json).unwrap(), fix);
    }

    #[test]
    fn bundle_config_format_serializes_kebab_case() {
        assert_eq!(
            serde_json::to_string(&ConfigFormat::BundleConfig).unwrap(),
            "\"bundle-config\""
        );
    }

    #[test]
    fn config_values_serialize_as_their_native_json_shape() {
        let table = ConfigValue::Table(BTreeMap::from([
            ("level".to_string(), ConfigValue::Str("high".into())),
            ("block".to_string(), ConfigValue::Bool(true)),
        ]));
        assert_eq!(
            serde_json::to_value(&table).unwrap(),
            serde_json::json!({"level": "high", "block": true})
        );

        let list = ConfigValue::List(vec!["a".into(), "b".into()]);
        assert_eq!(
            serde_json::to_value(&list).unwrap(),
            serde_json::json!(["a", "b"])
        );

        assert_eq!(
            serde_json::to_value(ConfigValue::Int(7)).unwrap(),
            serde_json::json!(7)
        );
        // A bare number must not round-trip into a string.
        assert_eq!(
            serde_json::from_value::<ConfigValue>(serde_json::json!(7)).unwrap(),
            ConfigValue::Int(7)
        );
        assert_eq!(
            serde_json::from_value::<ConfigValue>(serde_json::json!(true)).unwrap(),
            ConfigValue::Bool(true)
        );
    }

    fn bare_finding() -> Finding {
        Finding {
            kind: FindingKind::Settings,
            code: "scripts.unrestricted".into(),
            message: "m".into(),
            severity: Severity::High,
            path: "/p/.npmrc".into(),
            fixable: false,
            manager: None,
            package: None,
            current_version: None,
            fix_version: None,
            fix: None,
        }
    }

    // schemaVersion 2 consumers must not see a new key on findings that have
    // no fix, so the JSON report stays backward compatible.
    #[test]
    fn finding_without_a_fix_omits_the_key_entirely() {
        let json = serde_json::to_value(bare_finding()).unwrap();
        assert!(json.get("fix").is_none(), "unexpected fix key: {json}");
    }

    #[test]
    fn finding_with_a_fix_round_trips() {
        let finding = Finding {
            fixable: true,
            fix: Some(SettingsFix::new(
                "/p/.npmrc",
                ConfigFormat::Npmrc,
                vec![ConfigEdit::set("ignore-scripts", true)],
            )),
            ..bare_finding()
        };
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["fix"]["format"], "npmrc");
        assert_eq!(serde_json::from_value::<Finding>(json).unwrap(), finding);
    }
}
