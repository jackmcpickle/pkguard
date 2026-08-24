pub mod bundle_config;
pub mod json;
pub mod npmrc;
pub mod toml;
pub mod yaml;

use crate::fix::{ConfigEdit, ConfigFormat};

/// Why a config file could not be edited. There is exactly one reason, and it
/// always means "leave the file alone" — never "write it anyway".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    #[error("config file is not valid {0}")]
    Unparseable(&'static str),
}

/// Apply `edits` to `raw` in `format`, returning the new file body.
///
/// The flat formats (npmrc, bundle-config) rewrite line by line so comments,
/// blank lines, and key order survive. The structured ones parse and
/// re-serialize; TOML keeps its comments via `toml_edit`, YAML does not.
pub fn edit(format: ConfigFormat, raw: &str, edits: &[ConfigEdit]) -> Result<String, EditError> {
    match format {
        ConfigFormat::Npmrc => Ok(npmrc::edit(raw, edits)),
        ConfigFormat::BundleConfig => Ok(bundle_config::edit(raw, edits)),
        ConfigFormat::Yaml => yaml::edit(raw, edits),
        ConfigFormat::Toml => toml::edit(raw, edits),
        ConfigFormat::Json => json::edit(raw, edits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ConfigFormat; 5] = [
        ConfigFormat::Npmrc,
        ConfigFormat::BundleConfig,
        ConfigFormat::Yaml,
        ConfigFormat::Toml,
        ConfigFormat::Json,
    ];

    #[test]
    fn every_format_dispatches_to_a_writer_that_records_the_edit() {
        for format in ALL {
            let out = edit(format, "", &[ConfigEdit::set("solo", true)])
                .unwrap_or_else(|err| panic!("{format:?} failed on an empty file: {err}"));
            assert!(out.contains("solo"), "{format:?} dropped the edit: {out:?}");
        }
    }

    // A writer that silently returns the input on garbage would let `--fix`
    // clobber a file it did not understand. Every format must refuse instead.
    #[test]
    fn structured_formats_refuse_unparseable_input() {
        assert!(edit(ConfigFormat::Yaml, "- a list\n", &[]).is_err());
        assert!(edit(ConfigFormat::Toml, "[broken\n", &[]).is_err());
        assert!(edit(ConfigFormat::Json, "{nope", &[]).is_err());
    }

    #[test]
    fn every_format_is_idempotent_under_repeated_edits() {
        let edits = [ConfigEdit::set("solo", true)];
        for format in ALL {
            let once = edit(format, "", &edits).unwrap();
            let twice = edit(format, &once, &edits).unwrap();
            assert_eq!(once, twice, "{format:?} is not idempotent");
        }
    }

    #[test]
    fn every_format_ends_with_exactly_one_trailing_newline() {
        for format in ALL {
            let out = edit(format, "", &[ConfigEdit::set("solo", true)]).unwrap();
            assert!(out.ends_with('\n'), "{format:?}: {out:?}");
            assert!(!out.ends_with("\n\n"), "{format:?}: {out:?}");
        }
    }
}
