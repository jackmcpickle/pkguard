use std::path::PathBuf;

/// User-level `config.toml`. `PKGUARD_CONFIG_DIR` wins so tests and CI can
/// pin a directory without touching the real home.
pub fn user_config_file() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("PKGUARD_CONFIG_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir).join("config.toml"));
        }
    }
    directories::ProjectDirs::from("dev", "pkguard", "pkguard")
        .map(|dirs| dirs.config_dir().join("config.toml"))
}

pub fn user_config_if_present() -> Option<PathBuf> {
    user_config_file().filter(|path| path.is_file())
}
