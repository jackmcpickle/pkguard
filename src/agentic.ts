import { parse as parseTomlRaw } from "smol-toml";

import { AGENTIC_CATALOG } from "./agentic-catalog";
import type {
  ConfigEdit,
  ConfigFormat,
  DetectedManager,
  Finding,
  PackageManager,
  Policy,
  Project,
  SettingsFix,
} from "./domain";
import { profileFor } from "./managers/profile";
import { resolveSettings } from "./policy";
import { isPlainObject, isStar } from "./std";

export type { AgenticCheck } from "./agentic-catalog";
export { AGENTIC_CATALOG } from "./agentic-catalog";

const CATALOG_BY_CODE = new Map(
  AGENTIC_CATALOG.map((check) => [check.code, check])
);

export const agenticCaveat = (code: string): string | null =>
  CATALOG_BY_CODE.get(code)?.caveat ?? null;

export const isAgenticCode = (code: string): boolean =>
  CATALOG_BY_CODE.has(code);

type ReadFile = (path: string) => string | null;

const MANAGER_VERSION_PATTERN = /^(?<name>[a-z]+)@(?<major>\d+)/u;

const NPMRC_LINE_BREAK = /\r?\n/u;

const joinRoot = (root: string, name: string): string =>
  root.endsWith("/") ? `${root}${name}` : `${root}/${name}`;

const writePath = (project: Project, manager: PackageManager): string => {
  const name = profileFor(manager).writeConfigName;
  return name === null
    ? joinRoot(project.root, profileFor(manager).configNames[0] ?? "")
    : joinRoot(project.root, name);
};

const parseJsonObject = (raw: string | null): Record<string, unknown> => {
  if (raw === null) {
    return {};
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
};

const parseYaml = (raw: string): Record<string, unknown> => {
  if (raw.trim() === "") {
    return {};
  }
  try {
    const parsed: unknown = Bun.YAML.parse(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
};

const parseToml = (raw: string): Record<string, unknown> => {
  if (raw.trim() === "") {
    return {};
  }
  try {
    const parsed: unknown = parseTomlRaw(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
};

const parseNpmrc = (raw: string): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const line of raw.split(NPMRC_LINE_BREAK)) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith(";")) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq <= 0) {
      continue;
    }
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
};

const hasEntries = (value: unknown): boolean => {
  if (!isPlainObject(value)) {
    return false;
  }
  return Object.keys(value).length > 0;
};

const firstPresentKey = (
  table: Record<string, unknown>,
  keys: readonly string[]
): string | null => {
  for (const key of keys) {
    const value = table[key];
    if (typeof value === "string" && value.trim() !== "") {
      return key;
    }
  }
  return null;
};

const hoistHasStar = (value: unknown): boolean => {
  if (isStar(value)) {
    return true;
  }
  if (!Array.isArray(value)) {
    return false;
  }
  return value.some(isStar);
};

const managerMajor = (
  manifest: Record<string, unknown>,
  name: string
): number | null => {
  const field = manifest.packageManager;
  if (typeof field !== "string") {
    return null;
  }
  const match = MANAGER_VERSION_PATTERN.exec(field);
  if (match?.groups === undefined || match.groups["name"] !== name) {
    return null;
  }
  return Number(match.groups["major"]);
};

const atLeastOrUnknown = (major: number | null, need: number): boolean =>
  major === null || major >= need;

const unsetOp = (key: string): ConfigEdit => ({ key, op: "unset" });

const setOp = (key: string, value: boolean | string): ConfigEdit => ({
  key,
  op: "set",
  value,
});

const configFix = (
  file: string,
  format: ConfigFormat,
  edits: readonly ConfigEdit[]
): SettingsFix => ({ edits, file, format });

const note = (
  code: string,
  message: string,
  path: string,
  manager: PackageManager,
  apply: boolean,
  fix?: SettingsFix
): Finding => ({
  code,
  fixable: apply && fix !== undefined,
  kind: "settings",
  manager,
  message,
  path,
  severity: "info",
  ...(apply && fix !== undefined ? { fix } : {}),
});

const cacheFinding = (
  path: string,
  manager: PackageManager,
  apply: boolean,
  fix?: SettingsFix
): Finding =>
  note(
    "cache.path-committed",
    "committed store or cache path should not live in project config",
    path,
    manager,
    apply,
    fix
  );

const overrideFinding = (path: string, manager: PackageManager): Finding =>
  note(
    "overrides.present",
    "overrides create a version precedent the next agent will copy",
    path,
    manager,
    false
  );

const readUvTable = (
  project: Project,
  manager: DetectedManager,
  readFile: ReadFile
): { table: Record<string, unknown>; path: string; prefix: string } => {
  const configPath =
    manager.configPath ?? joinRoot(project.root, "pyproject.toml");
  const uvToml = joinRoot(project.root, "uv.toml");
  const uvRaw = readFile(uvToml);
  if (uvRaw !== null) {
    return { path: uvToml, prefix: "", table: parseToml(uvRaw) };
  }
  const pyproject = parseToml(readFile(configPath) ?? "");
  const tool = isPlainObject(pyproject.tool) ? pyproject.tool : {};
  const table = isPlainObject(tool.uv) ? tool.uv : {};
  return { path: configPath, prefix: "tool.uv.", table };
};

const npmFindings = (
  project: Project,
  manager: DetectedManager,
  apply: boolean,
  readFile: ReadFile
): Finding[] => {
  const findings: Finding[] = [];
  const { manifestPath } = manager;
  const manifest = parseJsonObject(readFile(manifestPath));
  if (hasEntries(manifest.overrides)) {
    findings.push(overrideFinding(manifestPath, "npm"));
  }
  const npmrcPath = manager.configPath ?? joinRoot(project.root, ".npmrc");
  const npmrc = parseNpmrc(readFile(npmrcPath) ?? "");
  if (npmrc.cache !== undefined && npmrc.cache.trim() !== "") {
    findings.push(
      cacheFinding(
        npmrcPath,
        "npm",
        apply,
        configFix(writePath(project, "npm"), "npmrc", [unsetOp("cache")])
      )
    );
  }
  return findings;
};

const yarnLinker = (yarnrc: Record<string, unknown>): string | undefined => {
  const raw = yarnrc.nodeLinker ?? yarnrc["node-linker"];
  return typeof raw === "string" ? raw.toLowerCase() : undefined;
};

const yarnOverrideFindings = (
  manifest: Record<string, unknown>,
  manifestPath: string
): Finding[] =>
  hasEntries(manifest.resolutions) || hasEntries(manifest.overrides)
    ? [overrideFinding(manifestPath, "yarn")]
    : [];

const yarnCacheFindings = (
  yarnrc: Record<string, unknown>,
  yarnrcPath: string,
  apply: boolean,
  file: string
): Finding[] => {
  const findings: Finding[] = [];
  const cacheFolder = yarnrc.cacheFolder ?? yarnrc["cache-folder"];
  if (typeof cacheFolder === "string" && cacheFolder.trim() !== "") {
    findings.push(
      cacheFinding(
        yarnrcPath,
        "yarn",
        apply,
        configFix(file, "yaml", [unsetOp("cacheFolder")])
      )
    );
  }
  if (yarnrc.enableGlobalCache === false) {
    findings.push(
      note(
        "agentic.cache-disabled",
        "yarn enableGlobalCache should stay true for a shared cache",
        yarnrcPath,
        "yarn",
        apply,
        configFix(file, "yaml", [setOp("enableGlobalCache", true)])
      )
    );
  }
  return findings;
};

const yarnPnpFinding = (
  yarnrc: Record<string, unknown>,
  yarnrcPath: string,
  apply: boolean,
  file: string
): Finding[] => {
  const linker = yarnLinker(yarnrc);
  if (linker !== undefined && linker !== "pnp") {
    return [];
  }
  return [
    note(
      "layout.pnp",
      "yarn Plug'n'Play leaves no node_modules for agents that run node",
      yarnrcPath,
      "yarn",
      apply,
      configFix(file, "yaml", [setOp("nodeLinker", "node-modules")])
    ),
  ];
};

const yarnFindings = (
  project: Project,
  manager: DetectedManager,
  apply: boolean,
  readFile: ReadFile
): Finding[] => {
  const { manifestPath } = manager;
  const yarnrcPath =
    manager.configPath ?? joinRoot(project.root, ".yarnrc.yml");
  const yarnrc = parseYaml(readFile(yarnrcPath) ?? "");
  const file = writePath(project, "yarn");
  return [
    ...yarnOverrideFindings(
      parseJsonObject(readFile(manifestPath)),
      manifestPath
    ),
    ...yarnCacheFindings(yarnrc, yarnrcPath, apply, file),
    ...yarnPnpFinding(yarnrc, yarnrcPath, apply, file),
  ];
};

const pnpmHoistFindings = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  apply: boolean,
  file: string
): Finding[] => {
  const shameful =
    yaml.shamefullyHoist === true || yaml["shamefully-hoist"] === true;
  const publicHoist = yaml.publicHoistPattern ?? yaml["public-hoist-pattern"];
  if (!shameful && !hoistHasStar(publicHoist)) {
    return [];
  }
  const edits: ConfigEdit[] = [];
  if (shameful) {
    edits.push(setOp("shamefullyHoist", false));
  }
  if (hoistHasStar(publicHoist)) {
    edits.push(unsetOp("publicHoistPattern"));
  }
  return [
    note(
      "layout.shamefully-hoist",
      "pnpm shameful hoist makes undeclared require() succeed",
      yamlPath,
      "pnpm",
      apply,
      configFix(file, "yaml", edits)
    ),
  ];
};

const pnpmOverrideFindings = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  manifest: Record<string, unknown>,
  manifestPath: string
): Finding[] => {
  const findings: Finding[] = [];
  if (hasEntries(yaml.overrides)) {
    findings.push(overrideFinding(yamlPath, "pnpm"));
  }
  const pnpmField = isPlainObject(manifest.pnpm) ? manifest.pnpm : {};
  if (
    hasEntries(pnpmField.overrides) &&
    atLeastOrUnknown(managerMajor(manifest, "pnpm"), 11)
  ) {
    findings.push(
      note(
        "overrides.legacy-location",
        "pnpm 11 ignores package.json#pnpm.overrides; use pnpm-workspace.yaml",
        manifestPath,
        "pnpm",
        false
      )
    );
  }
  return findings;
};

const pnpmStoreFinding = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  apply: boolean,
  file: string
): Finding[] => {
  const storeKey = firstPresentKey(yaml, [
    "storeDir",
    "store-dir",
    "cacheDir",
    "cache-dir",
  ]);
  if (storeKey === null) {
    return [];
  }
  return [
    cacheFinding(
      yamlPath,
      "pnpm",
      apply,
      configFix(file, "yaml", [unsetOp(storeKey)])
    ),
  ];
};

const pnpmPnpFinding = (
  yaml: Record<string, unknown>,
  yamlPath: string,
  apply: boolean,
  file: string
): Finding[] => {
  const linker = yaml.nodeLinker ?? yaml["node-linker"];
  if (typeof linker !== "string" || linker.toLowerCase() !== "pnp") {
    return [];
  }
  return [
    note(
      "layout.pnp",
      "pnpm nodeLinker pnp leaves no node_modules for agents that run node",
      yamlPath,
      "pnpm",
      apply,
      configFix(file, "yaml", [setOp("nodeLinker", "isolated")])
    ),
  ];
};

const pnpmFindings = (
  project: Project,
  manager: DetectedManager,
  apply: boolean,
  readFile: ReadFile
): Finding[] => {
  const { manifestPath } = manager;
  const yamlPath =
    manager.configPath ?? joinRoot(project.root, "pnpm-workspace.yaml");
  const yaml = parseYaml(readFile(yamlPath) ?? "");
  const file = writePath(project, "pnpm");
  return [
    ...pnpmOverrideFindings(
      yaml,
      yamlPath,
      parseJsonObject(readFile(manifestPath)),
      manifestPath
    ),
    ...pnpmStoreFinding(yaml, yamlPath, apply, file),
    ...pnpmHoistFindings(yaml, yamlPath, apply, file),
    ...pnpmPnpFinding(yaml, yamlPath, apply, file),
  ];
};

const bunCacheDir = (install: Record<string, unknown>): string | null => {
  const { cache } = install;
  if (typeof cache === "string" && cache.trim() !== "") {
    return cache;
  }
  if (isPlainObject(cache) && typeof cache.dir === "string") {
    return cache.dir.trim() === "" ? null : cache.dir;
  }
  return null;
};

const bunFindings = (
  project: Project,
  manager: DetectedManager,
  apply: boolean,
  readFile: ReadFile
): Finding[] => {
  const findings: Finding[] = [];
  const { manifestPath } = manager;
  const manifest = parseJsonObject(readFile(manifestPath));
  if (hasEntries(manifest.overrides) || hasEntries(manifest.resolutions)) {
    findings.push(overrideFinding(manifestPath, "bun"));
  }
  const bunfigPath =
    manager.configPath ?? joinRoot(project.root, "bunfig.toml");
  const bunfig = parseToml(readFile(bunfigPath) ?? "");
  const install = isPlainObject(bunfig.install) ? bunfig.install : {};
  if (bunCacheDir(install) !== null) {
    findings.push(
      cacheFinding(
        bunfigPath,
        "bun",
        apply,
        configFix(writePath(project, "bun"), "toml", [
          unsetOp("install.cache.dir"),
        ])
      )
    );
  }
  return findings;
};

const uvFindings = (
  project: Project,
  manager: DetectedManager,
  apply: boolean,
  readFile: ReadFile
): Finding[] => {
  const { path, prefix, table } = readUvTable(project, manager, readFile);
  const cacheDir = table["cache-dir"] ?? table.cacheDir;
  if (typeof cacheDir !== "string" || cacheDir.trim() === "") {
    return [];
  }
  return [
    cacheFinding(
      path,
      "uv",
      apply,
      configFix(path, "toml", [unsetOp(`${prefix}cache-dir`)])
    ),
  ];
};

const AUDITORS: Partial<
  Record<
    PackageManager,
    (
      project: Project,
      manager: DetectedManager,
      apply: boolean,
      readFile: ReadFile
    ) => Finding[]
  >
> = {
  bun: bunFindings,
  npm: npmFindings,
  pnpm: pnpmFindings,
  uv: uvFindings,
  yarn: yarnFindings,
};

export const auditAgentic = (
  project: Project,
  manager: DetectedManager,
  policy: Policy,
  readFile: ReadFile
): Finding[] => {
  const settings = resolveSettings(policy, manager.name);
  if (!settings.agentic) {
    return [];
  }
  const auditor = AUDITORS[manager.name];
  return auditor === undefined
    ? []
    : auditor(project, manager, settings.applyAgentic, readFile);
};
