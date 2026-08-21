import {
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import { APP_NAME, CONFIG_FILE_NAME } from "./app-name";
import type { ApplyPrompt } from "./apply-advisories";
import { auditPath, defaultDigest } from "./audit";
import type { AuditResult, AuditRun } from "./audit";
import { CACHE_TTL_MS, createFsCache } from "./cache";
import type { Cache } from "./cache";
import type { ExitCode, Finding, PresetName } from "./domain";
import {
  commandByName,
  formatCommandHelp,
  formatRootHelp,
  formatUnknownCommand,
  isHelpFlag,
} from "./help";
import { loadPolicy } from "./policy";
import {
  formatApplySkipped,
  formatHuman,
  formatJson,
  formatMarkdown,
  formatSarif,
} from "./report";

interface RunDeps {
  stdout: { write: (s: string) => unknown };
  stderr: { write: (s: string) => unknown };
  cwd: string;
  env: Record<string, string | undefined>;
  run?: AuditRun;
  runOsv?: (lockOrRequirements: string) => Promise<Finding[]>;
  which?: (binary: string) => string | null;
  cache?: Cache;
  now?: () => number;
  digest?: (lockfileBytes: string) => string;
  writeFile?: (path: string, body: string) => void;
  gitStatus?: (root: string) => "clean" | "dirty" | "not-git";
  gitCommit?: (root: string, message: string, files: string[]) => boolean;
  prompt?: ApplyPrompt;
  readLine?: () => Promise<string>;
  currentVersions?: Record<string, string>;
  fixVersions?: Record<string, string>;
  color?: boolean;
}

interface AuditFlags {
  path?: string;
  preset?: PresetName;
  apply: boolean;
  applyAdvisories: boolean;
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
  "--commit": "commit",
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

const readFile = (filePath: string): string | null => {
  try {
    return readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
};

const readDir = (dir: string): string[] => {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
};

const isDir = (filePath: string): boolean => {
  try {
    return statSync(filePath).isDirectory();
  } catch {
    return false;
  }
};

const writeFile = (filePath: string, body: string): void => {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, body);
};

const baseDir = (xdg: string | undefined, fallback: string): string =>
  xdg !== undefined && xdg !== "" ? xdg : fallback;

const userConfigPath = (env: Record<string, string | undefined>): string =>
  path.join(
    baseDir(env.XDG_CONFIG_HOME, path.join(env.HOME ?? "", ".config")),
    APP_NAME,
    "config.toml"
  );

const userCachePath = (env: Record<string, string | undefined>): string =>
  path.join(
    baseDir(env.XDG_CACHE_HOME, path.join(env.HOME ?? "", ".cache")),
    APP_NAME
  );

const isPresetName = (value: string | undefined): value is PresetName =>
  value !== undefined && PRESET_NAMES.has(value);

const presetFlags = (
  preset: PresetName | undefined
): { preset: PresetName } | undefined =>
  preset === undefined ? undefined : { preset };

const runGit = (root: string, args: string[]): boolean => {
  const proc = Bun.spawnSync(["git", "-C", root, ...args], {
    stderr: "pipe",
    stdout: "pipe",
  });
  return proc.exitCode === 0;
};

const gitAddAndCommit = (
  root: string,
  message: string,
  files: string[]
): boolean =>
  runGit(root, ["add", "--", ...files]) &&
  runGit(root, ["commit", "-m", message]);

const defaultGitCommit = (
  root: string,
  message: string,
  files: string[]
): boolean => files.length > 0 && gitAddAndCommit(root, message, files);

const gitStatusFromOutput = (stdout: Uint8Array): "clean" | "dirty" => {
  const text = new TextDecoder().decode(stdout).trim();
  return text === "" ? "clean" : "dirty";
};

const defaultGitStatus = (root: string): "clean" | "dirty" | "not-git" => {
  const proc = Bun.spawnSync(["git", "-C", root, "status", "--porcelain"], {
    stderr: "pipe",
    stdout: "pipe",
  });
  if (proc.exitCode !== 0) {
    return "not-git";
  }
  return gitStatusFromOutput(proc.stdout);
};

const defaultRun = async (
  argv: string[],
  cwd: string
): Promise<{ code: number; stdout: string; stderr: string }> => {
  const proc = Bun.spawn(argv, { cwd, stderr: "pipe", stdout: "pipe" });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, stderr, stdout };
};

const defaultWhich = (binary: string): string | null =>
  Bun.which(binary) ?? null;

const defaultRunOsv = (): Promise<Finding[]> => Promise.resolve([]);

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

const createBunStdinChunkReader = (): (() => Promise<string | null>) => {
  const reader = Bun.stdin.stream().getReader();
  const decoder = new TextDecoder();
  return async () => {
    const { done, value } = await reader.read();
    if (done) {
      return null;
    }
    return decoder.decode(value, { stream: true });
  };
};

const isPromptChoice = (value: string): value is PromptChoice =>
  PROMPT_CHOICES.has(value);

const defaultPrompt =
  (
    stdout: { write: (s: string) => unknown },
    readLine: () => Promise<string>
  ): ApplyPrompt =>
  async ({ project, settingsCount, advisoryCount }) => {
    stdout.write(
      `${project.root}: ${settingsCount} settings, ${advisoryCount} advisories [settings|advisories|both|skip] `
    );
    const raw = await readLine();
    const line = raw.trim().toLowerCase();
    return isPromptChoice(line) ? line : "skip";
  };

const resolvePrompt = (
  deps: RunDeps | undefined,
  flags: AuditFlags,
  stdout: { write: (s: string) => unknown }
): ApplyPrompt | undefined =>
  deps?.prompt ??
  (flags.interactive
    ? defaultPrompt(
        stdout,
        deps?.readLine ?? createLineReader(createBunStdinChunkReader())
      )
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

const resolveIo = (deps: RunDeps | undefined) => ({
  cwd: deps?.cwd ?? process.cwd(),
  env: deps?.env ?? process.env,
  stderr: deps?.stderr ?? process.stderr,
  stdout: deps?.stdout ?? process.stdout,
});

const resolveRoot = (flagPath: string | undefined, cwd: string): string => {
  if (flagPath === undefined) {
    return cwd;
  }
  if (path.isAbsolute(flagPath)) {
    return flagPath;
  }
  return path.join(cwd, flagPath);
};

const resolveCache = (
  deps: RunDeps | undefined,
  env: Record<string, string | undefined>,
  now: () => number
): Cache => deps?.cache ?? createFsCache(userCachePath(env), now, CACHE_TTL_MS);

const resolveGitDeps = (deps: RunDeps | undefined) => ({
  gitCommit: deps?.gitCommit ?? defaultGitCommit,
  gitStatus: deps?.gitStatus ?? defaultGitStatus,
});

const buildAuditDeps = (
  deps: RunDeps | undefined,
  cache: Cache,
  prompt: ApplyPrompt | undefined,
  write: (filePath: string, body: string) => void,
  now: () => number
) => ({
  cache,
  currentVersions: deps?.currentVersions,
  digest: deps?.digest ?? defaultDigest,
  fixVersions: deps?.fixVersions,
  ...resolveGitDeps(deps),
  isDir,
  now,
  prompt,
  readDir,
  readFile,
  run: deps?.run ?? defaultRun,
  runOsv: deps?.runOsv ?? defaultRunOsv,
  which: deps?.which ?? defaultWhich,
  writeFile: write,
});

const resolveColor = (
  deps: RunDeps | undefined,
  env: Record<string, string | undefined>
): boolean =>
  deps?.color ??
  (env.NO_COLOR === undefined &&
    Boolean(process.stdout.isTTY) &&
    deps?.stdout === undefined);

const emitOutput = (
  flags: AuditFlags,
  result: AuditResult,
  stdout: { write: (s: string) => unknown },
  write: (filePath: string, body: string) => void,
  cwd: string,
  color: boolean
): void => {
  if (flags.report !== undefined) {
    const reportPath = path.isAbsolute(flags.report)
      ? flags.report
      : path.join(cwd, flags.report);
    write(reportPath, formatMarkdown(result));
  }
  if (flags.json) {
    stdout.write(formatJson(result));
    return;
  }
  if (flags.sarif) {
    stdout.write(formatSarif(result));
    return;
  }
  stdout.write(formatHuman(result, { color }));
};

const topicFromHelpArgs = (rest: string[]): string | undefined =>
  rest.find((arg) => !isHelpFlag(arg));

const writeHelp = (
  text: string,
  stream: { write: (s: string) => unknown }
): { exitCode: 0 } => {
  stream.write(text);
  return { exitCode: 0 };
};

const writeUsageError = (
  text: string,
  stderr: { write: (s: string) => unknown }
): { exitCode: 2 } => {
  stderr.write(text);
  return { exitCode: 2 };
};

const helpForCommand = (
  name: string,
  color: boolean,
  stdout: { write: (s: string) => unknown },
  stderr: { write: (s: string) => unknown }
): { exitCode: ExitCode } => {
  const command = commandByName(name);
  if (command === undefined) {
    return writeUsageError(formatUnknownCommand(name, color), stderr);
  }
  return writeHelp(formatCommandHelp(command, color), stdout);
};

const dispatchHelp = (
  head: string,
  rest: string[],
  color: boolean,
  stdout: { write: (s: string) => unknown },
  stderr: { write: (s: string) => unknown }
): { exitCode: ExitCode } | null => {
  if (head === "help" || isHelpFlag(head)) {
    const topic = topicFromHelpArgs(rest);
    if (topic === undefined) {
      if (head === "help" && rest.some(isHelpFlag)) {
        return helpForCommand("help", color, stdout, stderr);
      }
      return writeHelp(formatRootHelp(color), stdout);
    }
    return helpForCommand(topic, color, stdout, stderr);
  }
  if (rest.some(isHelpFlag)) {
    const command = commandByName(head);
    if (command !== undefined) {
      return writeHelp(formatCommandHelp(command, color), stdout);
    }
  }
  return null;
};

export const run = async (
  argv: string[],
  deps?: RunDeps
): Promise<{ exitCode: ExitCode }> => {
  const { cwd, env, stderr, stdout } = resolveIo(deps);
  const color = resolveColor(deps, env);

  if (argv.length === 0) {
    return writeUsageError(formatRootHelp(color), stderr);
  }

  const [head, ...rest] = argv;
  if (head === undefined) {
    return writeUsageError(formatRootHelp(color), stderr);
  }

  const helpResult = dispatchHelp(head, rest, color, stdout, stderr);
  if (helpResult !== null) {
    return helpResult;
  }

  if (head !== "audit") {
    return writeUsageError(formatUnknownCommand(head, color), stderr);
  }

  const flags = parseAuditArgs(rest);
  const root = resolveRoot(flags.path, cwd);

  const policy = loadPolicy({
    flags: presetFlags(flags.preset),
    scanToml: readFile(path.join(root, CONFIG_FILE_NAME)) ?? undefined,
    userToml: readFile(userConfigPath(env)) ?? undefined,
  });

  const now = deps?.now ?? Date.now;
  const write = deps?.writeFile ?? writeFile;
  const prompt = resolvePrompt(deps, flags, stdout);
  const result = await auditPath(root, {
    allowMajors: flags.allowMajors,
    apply: flags.apply,
    applyAdvisories: flags.applyAdvisories,
    commit: flags.commit,
    concurrency: flags.concurrency,
    deps: buildAuditDeps(
      deps,
      resolveCache(deps, env, now),
      prompt,
      write,
      now
    ),
    flags: presetFlags(flags.preset),
    force: flags.force,
    interactive: flags.interactive,
    noCache: flags.noCache,
    policy,
    refresh: flags.refresh,
  });

  if (result.skippedDirty.length > 0) {
    stderr.write(formatApplySkipped(result.skippedDirty, { color }));
  }

  emitOutput(flags, result, stdout, write, cwd, color);
  return { exitCode: result.exitCode };
};
