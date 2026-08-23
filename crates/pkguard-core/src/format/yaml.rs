use serde_yaml::Value;

pub type Yaml = Value;

/// Parse a YAML mapping. Non-mappings and invalid input become an empty map.
pub fn parse(raw: &str) -> Yaml {
    if raw.trim().is_empty() {
        return Value::Mapping(serde_yaml::Mapping::new());
    }
    match serde_yaml::from_str(raw) {
        Ok(Value::Mapping(map)) => Value::Mapping(map),
        Ok(_) | Err(_) => Value::Mapping(serde_yaml::Mapping::new()),
    }
}

pub fn get<'a>(value: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    value.as_mapping()?.get(Value::String(key.to_string()))
}

pub fn first<'a>(value: &'a Yaml, keys: &[&str]) -> Option<&'a Yaml> {
    keys.iter().find_map(|key| get(value, key))
}

pub fn as_str(value: &Yaml) -> Option<&str> {
    value.as_str()
}

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

pub fn is_star(value: &Yaml) -> bool {
    as_str(value) == Some("*")
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
