// Typed view over site/src/generated/catalog.json, which is emitted by the
// Rust CLI (`pkguard dump-catalog`) and checked in. CI regenerates it and
// fails on a diff, so everything imported here matches the shipped binary.
import catalogJson from "../generated/catalog.json";

export interface HelpArg {
  name: string;
  required: boolean;
  description: string;
}

export interface HelpFlag {
  names: readonly string[];
  value: string | null;
  description: string;
}

export interface CommandHelp {
  name: string;
  summary: string;
  arguments: readonly HelpArg[];
  flags: readonly HelpFlag[];
}

export interface ManagerDoc {
  name: string;
  kind: "config" | "python-legacy";
  binary: string | null;
  auditArgv: readonly string[] | null;
  lockfileNames: readonly string[];
  configNames: readonly string[];
  writeConfigName: string | null;
  ported: boolean;
}

export interface AgenticCheck {
  code: string;
  title: string;
  description: string;
  caveat: string;
}

export interface PresetDefaults {
  auditLevel: string;
  ignoreScripts: boolean;
  minReleaseAgeDays: number;
  requireLockfile: boolean;
  requirePmPin: boolean;
}

interface Catalog {
  appName: string;
  version: string;
  configFileName: string;
  cacheEnvVar: string;
  userConfigPaths: { linux: string; macos: string };
  configSearchOrder: string;
  commands: readonly CommandHelp[];
  managers: readonly ManagerDoc[];
  presetDefaults: Record<string, PresetDefaults>;
  agentic: readonly AgenticCheck[];
}

const catalog = catalogJson as unknown as Catalog;

export const APP_NAME = catalog.appName;
export const APP_VERSION = catalog.version;
export const CONFIG_FILE_NAME = catalog.configFileName;
export const CACHE_ENV_VAR = catalog.cacheEnvVar;
export const USER_CONFIG_PATHS = catalog.userConfigPaths;
export const CONFIG_SEARCH_ORDER = catalog.configSearchOrder;
export const COMMANDS = catalog.commands;
export const MANAGER_DOCS = catalog.managers;
export const PRESET_DEFAULTS = catalog.presetDefaults;
export const AGENTIC_CATALOG = catalog.agentic;

export const argToken = (arg: HelpArg): string =>
  arg.required ? `<${arg.name}>` : `[${arg.name}]`;

export const commandSynopsis = (command: CommandHelp): string => {
  if (command.arguments.length === 0) {
    return command.name;
  }
  return `${command.name} ${command.arguments.map(argToken).join(" ")}`;
};

export const flagLabel = (flag: HelpFlag): string => {
  const names = flag.names.join(", ");
  return flag.value === null ? names : `${names} <${flag.value}>`;
};
