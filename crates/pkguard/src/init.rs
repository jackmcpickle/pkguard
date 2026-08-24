use crate::cli::InitArgs;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

const STARTER: &str = include_str!("config.default.toml");

pub fn run(args: &InitArgs) -> i32 {
    let Some(target) = resolve_target(args.local) else {
        let _ = writeln!(io::stderr(), "could not resolve the user config directory");
        return 2;
    };
    if target.exists() && !args.force {
        let _ = writeln!(
            io::stderr(),
            "Refusing to overwrite existing file {} (use --force)",
            target.display()
        );
        return 2;
    }
    if let Some(parent) = target.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            let _ = writeln!(io::stderr(), "could not create {}: {err}", parent.display());
            return 2;
        }
    }
    if let Err(err) = fs::write(&target, STARTER) {
        let _ = writeln!(io::stderr(), "could not write {}: {err}", target.display());
        return 2;
    }
    println!("{}", target.display());
    0
}

fn resolve_target(local: bool) -> Option<PathBuf> {
    if local {
        let cwd = std::env::current_dir().ok()?;
        return Some(cwd.join(".pkguard.toml"));
    }
    crate::paths::user_config_file()
}
