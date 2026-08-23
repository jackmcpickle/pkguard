pub mod npmrc;
pub mod yaml;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npmrc_parses_key_values_and_skips_comments() {
        let parsed = npmrc::parse(
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

    #[test]
    fn yaml_parses_nested_maps_and_ignores_non_maps() {
        let parsed = yaml::parse("allowBuilds:\n  esbuild: false\naudit:\n  level: high\n");
        assert_eq!(
            yaml::get(&parsed, "audit")
                .and_then(|audit| yaml::get(audit, "level"))
                .and_then(yaml::as_str),
            Some("high")
        );
        assert!(yaml::is_false(
            yaml::get(&parsed, "allowBuilds").and_then(|builds| yaml::get(builds, "esbuild"))
        ));
        assert!(yaml::parse("- just a list\n")
            .as_mapping()
            .unwrap()
            .is_empty());
    }
}
