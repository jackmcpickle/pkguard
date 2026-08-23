import path from "node:path";

import { APP_VERSION } from "./app-name";
import type { ApplyPrompt } from "./apply-advisories";
import { auditPath } from "./audit";
import type { AuditMode, AuditResult, WriteDeps } from "./audit";
import { dirConfigPath, userCachePath, userConfigPath } from "./config-paths";
import type { ConfigSource } from "./config-sources";
import { formatConfigSources } from "./config-sources";
import defaultConfigToml from "./config.default.toml" with { type: "text" };
import type { ExitCode, PresetName } from "./domain";
import {
  commandByName,
  formatCommandHelp,
  formatRootHelp,
  formatUnknownCommand,
  isHelpFlag,
  isVersionFlag,
} from "./help";
import type { Host } from "./host";
import type { PolicyLayers } from "./policy";
import { formatHuman, formatJson, formatMarkdown, formatSarif } from "./report";

interface AuditFlags {
  path?: string;
  preset?: PresetName;
  apply: boolean;
  applyAdvisories: boolean;
  applyAgentic: boolean;
  interactive: boolean;
  concurrency: number;
  json: boolean;
  sarif: boolean;
  report?: string;
  force: boolean;
  commit: boolean;
  allowMajors: boolean;
  refresh: boolean;
  noCache: boolean;
}

type BooleanFlagKey =
  | "allowMajors"
  | "apply"
  | "applyAdvisories"
  | "applyAgentic"
  | "commit"
  | "force"
  | "interactive"
  | "json"
  | "noCache"
  | "refresh"
  | "sarif";

const BOOLEAN_FLAGS: Readonly<Record<string, BooleanFlagKey>> = {
  "--allow-majors": "allowMajors",
  "--apply": "apply",
  "--apply-advisories": "applyAdvisories",
  "--apply-agentic": "applyAgentic",
  "--commit": "commit",
  "--fix": "apply",
  "--force": "force",
  "--interactive": "interactive",
  "--json": "json",
  "--no-cache": "noCache",
  "--refresh": "refresh",
  "--sarif": "sarif",
  "-i": "interactive",
};

const PRESET_NAMES: ReadonlySet<string> = new Set([
  "relaxed",
  "standard",
  "strict",
]);

const PROMPT_CHOICES: ReadonlySet<string> = new Set([
  "settings",
  "advisories",
  "both",
  "skip",
]);

type PromptChoice = "settings" | "advisories" | "both" | "skip";

const isPresetName = (value: string | undefined): value is PresetName =>
  value !== undefined && PRESET_NAMES.has(value);

const presetFlags = (
  preset: PresetName | undefined
): { preset: PresetName } | undefined =>
  preset === undefined ? undefined : { preset };

const readUntilNewline = async (
  readChunk: () => Promise<string | null>,
  buffered: string
): Promise<string> => {
  if (buffered.includes("\n")) {
    return buffered;
  }
  const chunk = await readChunk();
  if (chunk === null) {
    return buffered;
  }
  return readUntilNewline(readChunk, buffered + chunk);
};

export const createLineReader = (
  readChunk: () => Promise<string | null>
): (() => Promise<string>) => {
  let leftover = "";
  return async () => {
    const buffered = await readUntilNewline(readChunk, leftover);
    const nl = buffered.indexOf("\n");
    if (nl === -1) {
      leftover = "";
      return buffered;
    }
    leftover = buffered.slice(nl + 1);
    return buffered.slice(0, nl).replace(/\r$/u, "");
  };
};

const isPromptChoice = (value: string): value is PromptChoice =>
  PROMPT_CHOICES.has(value);

const defaultPrompt =
  (
    write: (text: string) => void,
    readLine: () => Promise<string>
  ): ApplyPrompt =>
  async ({ project, settingsCount, advisoryCount }) => {
    write(
      `${project.root}: ${settingsCount} settings, ${advisoryCount} advisories [settings|advisories|both|skip] `
    );
    const raw = await readLine();
    const line = raw.trim().toLowerCase();
    return isPromptChoice(line) ? line : "skip";
  };

const resolvePrompt = (
  host: Host,
  flags: AuditFlags
): ApplyPrompt | undefined =>
  host.prompt ??
  (flags.interactive
    ? defaultPrompt(host.stdout, createLineReader(host.readStdinChunk))
    : undefined);

const setPreset = (flags: AuditFlags, value: string | undefined): void => {
  if (isPresetName(value)) {
    flags.preset = value;
  }
};

const setConcurrency = (flags: AuditFlags, raw: string | undefined): void => {
  const value = Number(raw);
  if (Number.isFinite(value) && value >= 1) {
    flags.concurrency = value;
  }
};

const consumePreset = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number | null => {
  if (arg === "--preset") {
    setPreset(flags, next);
    return 1;
  }
  if (arg.startsWith("--preset=")) {
    setPreset(flags, arg.slice("--preset=".length));
    return 0;
  }
  return null;
};

const consumeConcurrency = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number | null => {
  if (arg === "--concurrency") {
    setConcurrency(flags, next);
    return 1;
  }
  if (arg.startsWith("--concurrency=")) {
    setConcurrency(flags, arg.slice("--concurrency=".length));
    return 0;
  }
  return null;
};

const consumeReport = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number | null => {
  if (arg === "--report") {
    flags.report = next;
    return 1;
  }
  if (arg.startsWith("--report=")) {
    flags.report = arg.slice("--report=".length);
    return 0;
  }
  return null;
};

const consumeValueFlag = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number | null =>
  consumePreset(flags, arg, next) ??
  consumeConcurrency(flags, arg, next) ??
  consumeReport(flags, arg, next);

const consumeArg = (
  flags: AuditFlags,
  arg: string,
  next: string | undefined
): number => {
  const boolKey = BOOLEAN_FLAGS[arg];
  if (boolKey !== undefined) {
    flags[boolKey] = true;
    return 0;
  }
  const consumed = consumeValueFlag(flags, arg, next);
  if (consumed !== null) {
    return consumed;
  }
  if (!arg.startsWith("-")) {
    flags.path = arg;
  }
  return 0;
};

const parseAuditArgs = (args: string[]): AuditFlags => {
  const flags: AuditFlags = {
    allowMajors: false,
    apply: false,
    applyAdvisories: false,
    applyAgentic: false,
    commit: false,
    concurrency: 4,
    force: false,
    interactive: false,
    json: false,
    noCache: false,
    refresh: false,
    sarif: false,
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) {
      continue;
    }
    index += consumeArg(flags, arg, args[index + 1]);
  }
  return flags;
};

const resolveRoot = (flagPath: string | undefined, cwd: string): string => {
  if (flagPath === undefined) {
    return cwd;
  }
  if (path.isAbsolute(flagPath)) {
    return flagPath;
  }
  return path.join(cwd, flagPath);
};

const buildWriteDeps = (flags: AuditFlags, host: Host): WriteDeps => ({
  commit: flags.commit,
  force: flags.force,
  gitCommit: host.gitCommit,
  gitStatus: host.gitStatus,
  writeFile: host.files.writeFile,
});

const modeFromFlags = (
  flags: AuditFlags,
  write: WriteDeps,
  prompt: ApplyPrompt | undefined
): AuditMode => {
  if (flags.interactive && prompt !== undefined) {
    return {
      kind: "interactive",
      prompt,
      write,
    };
  }
  if (flags.apply || flags.applyAdvisories || flags.applyAgentic) {
    return {
      advisories: flags.applyAdvisories,
      agenticOnly: flags.applyAgentic && !flags.apply,
      allowMajors: flags.allowMajors,
      kind: "apply",
      settings: flags.apply || flags.applyAgentic,
      write,
    };
  }
  return { kind: "audit" };
};

export const resolveColor = (host: Host): boolean =>
  host.env.NO_COLOR === undefined && host.isTTY;

const emitOutput = (
  flags: AuditFlags,
  result: AuditResult,
  host: Host,
  cwd: string,
  color: boolean
): void => {
  if (flags.report !== undefined) {
    const reportPath = path.isAbsolute(flags.report)
      ? flags.report
      : path.join(cwd, flags.report);
    host.files.writeFile(reportPath, formatMarkdown(result));
  }
  if (flags.json) {
    host.stdout(formatJson(result));
    return;
  }
  if (flags.sarif) {
    host.stdout(formatSarif(result));
    return;
  }
  host.stdout(formatHuman(result, { color }));
};

const topicFromHelpArgs = (rest: string[]): string | undefined =>
  rest.find((arg) => !isHelpFlag(arg));

const writeHelp = (
  text: string,
  write: (s: string) => void
): { exitCode: 0 } => {
  write(text);
  return { exitCode: 0 };
};

const writeUsageError = (
  text: string,
  write: (s: string) => void
): { exitCode: 2 } => {
  write(text);
  return { exitCode: 2 };
};

const helpConfigSources = (host: Host): ConfigSource[] => [
  { kind: "user", path: userConfigPath(host.env) },
  { kind: "scan", path: dirConfigPath(host.cwd()) },
];

const withHelpConfig = (text: string, host: Host, color: boolean): string =>
  `${text}${formatConfigSources(helpConfigSources(host), host.files.readFile, {
    color,
  })}`;

const helpForCommand = (
  name: string,
  color: boolean,
  host: Host
): { exitCode: ExitCode } => {
  const command = commandByName(name);
  if (command === undefined) {
    return writeUsageError(
      withHelpConfig(formatUnknownCommand(name, color), host, color),
      host.stderr
    );
  }
  const body = formatCommandHelp(command, color);
  const text = name === "audit" ? withHelpConfig(body, host, color) : body;
  return writeHelp(text, host.stdout);
};

const dispatchExplicitHelp = (
  head: string,
  rest: string[],
  color: boolean,
  host: Host
): { exitCode: ExitCode } => {
  const topic = topicFromHelpArgs(rest);
  if (topic !== undefined) {
    return helpForCommand(topic, color, host);
  }
  if (head === "help" && rest.some(isHelpFlag)) {
    return helpForCommand("help", color, host);
  }
  return writeHelp(
    withHelpConfig(formatRootHelp(color), host, color),
    host.stdout
  );
};

const dispatchTrailingHelp = (
  head: string,
  rest: string[],
  color: boolean,
  host: Host
): { exitCode: ExitCode } | null => {
  if (!rest.some(isHelpFlag)) {
    return null;
  }
  const command = commandByName(head);
  if (command === undefined) {
    return null;
  }
  return helpForCommand(head, color, host);
};

const dispatchHelp = (
  head: string,
  rest: string[],
  color: boolean,
  host: Host
): { exitCode: ExitCode } | null => {
  if (head === "help" || isHelpFlag(head)) {
    return dispatchExplicitHelp(head, rest, color, host);
  }
  return dispatchTrailingHelp(head, rest, color, host);
};

interface InitFlags {
  force: boolean;
  local: boolean;
}

type InitParse =
  | { ok: true; flags: InitFlags }
  | { ok: false; unknown: string };

const applyInitFlag = (flags: InitFlags, arg: string): boolean => {
  if (arg === "--force") {
    flags.force = true;
    return true;
  }
  if (arg === "--local") {
    flags.local = true;
    return true;
  }
  return false;
};

const parseInitArgs = (args: string[]): InitParse => {
  const flags: InitFlags = { force: false, local: false };
  for (const arg of args) {
    if (!applyInitFlag(flags, arg)) {
      return { ok: false, unknown: arg };
    }
  }
  return { flags, ok: true };
};

const runInit = (args: string[], host: Host): { exitCode: ExitCode } => {
  const parsed = parseInitArgs(args);
  if (!parsed.ok) {
    return writeUsageError(`Unknown option: ${parsed.unknown}\n`, host.stderr);
  }
  const { flags } = parsed;
  const target = flags.local
    ? dirConfigPath(host.cwd())
    : userConfigPath(host.env);
  if (host.files.exists(target) && !flags.force) {
    return writeUsageError(
      `Refusing to overwrite existing file ${target} (use --force)\n`,
      host.stderr
    );
  }
  host.files.writeFile(target, defaultConfigToml);
  host.stdout(`${target}\n`);
  return { exitCode: 0 };
};

const auditConfigSources = (
  env: Record<string, string | undefined>,
  root: string,
  projectRoots: readonly string[]
): ConfigSource[] => [
  { kind: "user", path: userConfigPath(env) },
  { kind: "scan", path: dirConfigPath(root) },
  ...projectRoots.map((projectRoot): ConfigSource => ({
    kind: "repo",
    path: dirConfigPath(projectRoot),
  })),
];

const emitConfigSources = (
  flags: AuditFlags,
  result: AuditResult,
  env: Record<string, string | undefined>,
  root: string,
  host: Host,
  color: boolean
): void => {
  const block = formatConfigSources(
    auditConfigSources(
      env,
      root,
      result.projects.map(({ project }) => project.root)
    ),
    host.files.readFile,
    { color }
  );
  if (flags.json || flags.sarif) {
    host.stderr(block);
    return;
  }
  host.stdout(block);
};

const runAudit = async (
  rest: string[],
  host: Host,
  cwd: string,
  env: Record<string, string | undefined>,
  color: boolean
): Promise<{ exitCode: ExitCode }> => {
  const flags = parseAuditArgs(rest);
  const root = resolveRoot(flags.path, cwd);
  const layers: PolicyLayers = {
    flags: {
      ...presetFlags(flags.preset),
      ...(flags.applyAgentic ? { overrides: { applyAgentic: true } } : {}),
    },
    scanToml: host.files.readFile(dirConfigPath(root)) ?? undefined,
    userToml: host.files.readFile(userConfigPath(env)) ?? undefined,
  };
  const result = await auditPath(root, {
    concurrency: flags.concurrency,
    deps: {
      cache: host.createCache(userCachePath(env)),
      digest: host.digest,
      isDir: host.files.isDir,
      now: host.now,
      readDir: host.files.readDir,
      readFile: host.files.readFile,
      run: host.run,
      runOsv: host.runOsv,
      which: host.which,
    },
    layers,
    mode: modeFromFlags(
      flags,
      buildWriteDeps(flags, host),
      resolvePrompt(host, flags)
    ),
    noCache: flags.noCache,
    refresh: flags.refresh,
  });
  emitConfigSources(flags, result, env, root, host, color);
  emitOutput(flags, result, host, cwd, color);
  return { exitCode: result.exitCode };
};

export const run = async (
  argv: string[],
  host: Host
): Promise<{ exitCode: ExitCode }> => {
  const cwd = host.cwd();
  const { env } = host;
  const color = resolveColor(host);
  const [head, ...rest] = argv;
  if (head === undefined) {
    return writeUsageError(
      withHelpConfig(formatRootHelp(color), host, color),
      host.stderr
    );
  }
  if (argv.some(isVersionFlag)) {
    host.stdout(`${APP_VERSION}\n`);
    return { exitCode: 0 };
  }
  const helpResult = dispatchHelp(head, rest, color, host);
  if (helpResult !== null) {
    return helpResult;
  }
  if (head === "init") {
    return runInit(rest, host);
  }
  if (head !== "audit") {
    return writeUsageError(
      withHelpConfig(formatUnknownCommand(head, color), host, color),
      host.stderr
    );
  }
  return await runAudit(rest, host, cwd, env, color);
};
