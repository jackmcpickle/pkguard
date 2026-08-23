pub mod npmrc;

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
}
