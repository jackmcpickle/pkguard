//! Docs-site catalog: everything the docs site renders about the CLI, emitted
//! by the hidden `dump-catalog` command. Commands come from the live clap
//! definitions and managers from the `Manager` enum, so the site cannot drift
//! from the binary. The generated file is checked in at
//! `site/src/generated/catalog.json`; CI diffs it against a fresh dump.

use clap::CommandFactory;
use pkguard_core::config::PresetDefaults;
use pkguard_core::manager::Manager;
use pkguard_core::policy::Preset;
use serde_json::{json, Map, Value};

pub const CONFIG_SEARCH_ORDER: &str = "Reads the user config, then .pkguard.toml at the scan \
     root and in each repo. Closer wins; flags win over files.";

/// Agentic-hygiene finding codes. The codes are part of the finding-code
/// contract carried over from the TS build; the checks themselves are being
/// ported with the fix surface.
const AGENTIC_CATALOG: &[(&str, &str, &str, &str)] = &[
    (
        "cache.path-committed",
        "Committed store or cache path",
        "A project file pins storeDir, cache, cacheFolder, or install.cache.dir.",
        "Shared caches belong in user config. A committed home path breaks CI and other agents. \
         Apply only unsets an in-repo path — it never writes ~/…/store.",
    ),
    (
        "agentic.cache-disabled",
        "Global cache disabled",
        "yarn enableGlobalCache is false.",
        "Leave enableGlobalCache true unless the team vendors .yarn/cache (Zero-Installs).",
    ),
    (
        "overrides.present",
        "Version override precedent",
        "overrides, resolutions, or pnpm workspace overrides force a version the manifest does \
         not show.",
        "The next agent will copy this instead of upgrading. Presence is the warning; apply \
         never deletes a pin.",
    ),
    (
        "overrides.legacy-location",
        "Legacy pnpm overrides location",
        "package.json#pnpm.overrides on pnpm 11 or later.",
        "pnpm 11 ignores package.json#pnpm. Apply can move the map to pnpm-workspace.yaml only.",
    ),
    (
        "layout.shamefully-hoist",
        "Shameful hoist",
        "pnpm shamefullyHoist is true, or publicHoistPattern contains *.",
        "Makes require() succeed for undeclared deps. The next isolated install breaks.",
    ),
    (
        "layout.pnp",
        "Plug'n'Play linker",
        "yarn or pnpm nodeLinker is pnp (yarn's default).",
        "Most agents assume node_modules and run node, not yarn node. Apply to node-modules is \
         opt-in because it changes the team layout.",
    ),
];

fn help_text(help: Option<&clap::builder::StyledStr>) -> String {
    help.map(|h| h.to_string()).unwrap_or_default()
}

fn flag_value(arg: &clap::Arg) -> Value {
    if !arg.get_num_args().is_some_and(|r| r.takes_values()) {
        return Value::Null;
    }
    let possible: Vec<String> = arg
        .get_possible_values()
        .into_iter()
        .map(|v| v.get_name().to_string())
        .collect();
    if !possible.is_empty() {
        return json!(possible.join("|"));
    }
    let name = arg
        .get_value_names()
        .and_then(|names| names.first())
        .map(|n| n.to_string().to_lowercase())
        .unwrap_or_else(|| arg.get_id().to_string());
    json!(name)
}

fn command_doc(cmd: &clap::Command) -> Value {
    let mut arguments = Vec::new();
    let mut flags = Vec::new();
    for arg in cmd.get_arguments() {
        if arg.is_positional() {
            arguments.push(json!({
                "name": arg.get_id().as_str(),
                "required": arg.is_required_set(),
                "description": help_text(arg.get_help()),
            }));
            continue;
        }
        let mut names = Vec::new();
        if let Some(short) = arg.get_short() {
            names.push(format!("-{short}"));
        }
        if let Some(long) = arg.get_long() {
            names.push(format!("--{long}"));
        }
        flags.push(json!({
            "names": names,
            "value": flag_value(arg),
            "description": help_text(arg.get_help()),
        }));
    }
    json!({
        "name": cmd.get_name(),
        "summary": help_text(cmd.get_about()),
        "arguments": arguments,
        "flags": flags,
    })
}

fn manager_doc(manager: Manager) -> Value {
    json!({
        "name": manager.name(),
        "kind": if manager.is_legacy_python() { "python-legacy" } else { "config" },
        "binary": manager.binary(),
        "auditArgv": manager.audit_argv(),
        "lockfileNames": manager.lockfile_names(),
        "configNames": manager.config_names(),
        "writeConfigName": manager.write_config_name(),
        "ported": manager.ported(),
    })
}

fn preset_doc(preset: Preset) -> (String, Value) {
    let defaults = PresetDefaults::for_preset(preset);
    (
        preset.as_str().to_string(),
        json!({
            "auditLevel": defaults.audit_level.as_str(),
            "ignoreScripts": defaults.ignore_scripts,
            "minReleaseAgeDays": defaults.min_release_age_days,
            "requireLockfile": defaults.require_lockfile,
            "requirePmPin": defaults.require_pm_pin,
        }),
    )
}

pub fn catalog() -> Value {
    let mut root = crate::cli::Cli::command();
    root.build();

    let commands: Vec<Value> = root
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .map(command_doc)
        .collect();

    let presets: Map<String, Value> = [Preset::Relaxed, Preset::Standard, Preset::Strict]
        .into_iter()
        .map(preset_doc)
        .collect();

    let agentic: Vec<Value> = AGENTIC_CATALOG
        .iter()
        .map(|(code, title, description, caveat)| {
            json!({
                "code": code,
                "title": title,
                "description": description,
                "caveat": caveat,
            })
        })
        .collect();

    json!({
        "appName": root.get_name(),
        "version": root.get_version(),
        "configFileName": ".pkguard.toml",
        "cacheEnvVar": "PKGUARD_CACHE_DIR",
        "userConfigPaths": {
            "linux": "~/.config/pkguard/config.toml",
            "macos": "~/Library/Application Support/dev.pkguard.pkguard/config.toml",
        },
        "configSearchOrder": CONFIG_SEARCH_ORDER,
        "commands": commands,
        "managers": Manager::ALL.map(manager_doc),
        "presetDefaults": Value::Object(presets),
        "agentic": agentic,
    })
}

pub fn print() {
    println!("{}", serde_json::to_string_pretty(&catalog()).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_command_comes_from_clap() {
        let doc = catalog();
        let commands = doc["commands"].as_array().unwrap();
        let scan = commands
            .iter()
            .find(|c| c["name"] == "scan")
            .expect("scan command in catalog");
        assert_eq!(scan["arguments"][0]["name"], "path");
        assert_eq!(scan["arguments"][0]["required"], false);
        let flags: Vec<&str> = scan["flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                f["names"]
                    .as_array()
                    .unwrap()
                    .last()
                    .unwrap()
                    .as_str()
                    .unwrap()
            })
            .collect();
        for expected in [
            "--preset",
            "--jobs",
            "--format",
            "--refresh",
            "--no-cache",
            "--quiet",
        ] {
            assert!(flags.contains(&expected), "missing {expected} in {flags:?}");
        }
    }

    #[test]
    fn hidden_commands_stay_out_of_the_catalog() {
        let doc = catalog();
        let names: Vec<&str> = doc["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(!names.contains(&"dump-catalog"));
        assert!(!names.contains(&"help"));
    }

    #[test]
    fn value_enums_render_their_choices() {
        let doc = catalog();
        let scan = &doc["commands"][0];
        let preset = scan["flags"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["names"].as_array().unwrap().contains(&json!("--preset")))
            .unwrap();
        assert_eq!(preset["value"], "relaxed|standard|strict");
    }

    #[test]
    fn managers_come_from_the_enum() {
        let doc = catalog();
        let managers = doc["managers"].as_array().unwrap();
        assert_eq!(managers.len(), Manager::ALL.len());
        let npm = managers.iter().find(|m| m["name"] == "npm").unwrap();
        assert_eq!(npm["auditArgv"], json!(["npm", "audit", "--json"]));
        assert_eq!(npm["ported"], true);
        let poetry = managers.iter().find(|m| m["name"] == "poetry").unwrap();
        assert_eq!(poetry["kind"], "python-legacy");
        assert_eq!(poetry["binary"], Value::Null);
    }

    #[test]
    fn preset_defaults_match_core() {
        let doc = catalog();
        assert_eq!(doc["presetDefaults"]["standard"]["auditLevel"], "high");
        assert_eq!(doc["presetDefaults"]["strict"]["minReleaseAgeDays"], 14);
        assert_eq!(doc["presetDefaults"]["relaxed"]["requirePmPin"], false);
    }
}
