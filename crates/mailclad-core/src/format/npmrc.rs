use std::collections::BTreeMap;

/// npmrc / ini-style key=value parse; comments start with `#` or `;`.
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
