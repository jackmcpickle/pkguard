# pkguard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> REQUIRED: Follow TDD (`red → green`). No production code without a failing test first, except generated/config files listed in a task as scaffold. Test only at the **Seams** section. Do not commit unless the task step says to and the controller allowed commits.

**Goal:** Ship `pkguard`, a local CLI that audits package-manager security settings and advisories across monorepos and folders of many projects, and applies fixes only when explicitly asked.

**Architecture:** Bun + TypeScript library with a thin CLI. File-based settings checks need no PM binary. Advisories and migrate shell out through injected runners. Policy is layered TOML. Discovery is hybrid (git repos → workspace/PM roots). Cache lives in `~/.cache/pkguard/` (overridable). Apply is serial; audit concurrency defaults to 4.

**Tech Stack:** TypeScript, Bun (runtime + `bun test` + compile to binary), `@std/toml` or `smol-toml` for parse/stringify, no JS/TS policy files.

**Spec:** This file is the spec. Product decisions were locked in grilling. Phase 2 (GitHub Action workflow presets) is out of this plan.

## Global Constraints

- Binary / package name: `pkguard`
- Audit is default and never writes. `--apply` writes settings only. `--apply-advisories` upgrades dependencies. `-i` / `--interactive` can write after per-repo consent without also passing `--apply`.
- Apply (and interactive) is always serial. Audit default `--concurrency 4`. `--concurrency 1` is serial audit.
- Apply requires a clean git tree unless `--force`. `--commit` is opt-in, one commit per repo. Audit-only ignores dirty.
- Exit codes: `0` = every project that ran passed the gate; `1` = policy failure (settings drift or above-gate advisory); `2` = incomplete (missing binary, apply skipped-dirty, audit subprocess died). Warnings never become `1`.
- Presets: `relaxed` | `standard` | `strict`. Default `standard`.
- Advisory gate: `relaxed` = critical only; `standard` = high+critical; `strict` = moderate+. uv deprecation/quarantine always count as findings.
- Config files: user `~/.config/pkguard/config.toml` (or `$XDG_CONFIG_HOME/pkguard/config.toml`); scan-root and per-repo `.pkguard.toml`. Closer wins. Flags win over files. Per-PM tables: `[npm]`, `[pnpm]`, `[yarn]`, `[bun]`, `[uv]`. Never execute JS/TS config.
- Cache dir: `~/.cache/pkguard/` (or `$XDG_CACHE_HOME/pkguard/`). Lockfile-digest entries + shared package@version. Do not write into `uv cache` or the pnpm store. `--refresh` / `--no-cache` bypass. Settings checks never use the advisory cache.
- Lockfile-digest + TTL hit may skip a live advisory run. Package@version hits are preview only; live audit still runs. Process waits for live before finalizing that repo, exit code, and reports. Live wins; cache updates.
- Write rule: prefer the existing correct file for that PM; create it if missing; never write user-global PM config (`~/.npmrc`, user `uv.toml`).
- npm settings file: `.npmrc`. pnpm settings file: `pnpm-workspace.yaml` (not `.npmrc`, not the lockfile). Yarn Berry: `.yarnrc.yml` (not `yarn.lock`). bun: `bunfig.toml`. uv: `uv.toml` or `[tool.uv]` in `pyproject.toml` if that is where config already lives.
- Yarn v1 is unsupported: detect and flag, no apply, no audit.
- Leftover lockfiles are findings, not apply targets, unless that PM is enabled as primary.
- Node advisories: native `npm audit` / `pnpm audit` / `bun audit` / `yarn npm audit`. uv: `uv audit` (OSV). Non-uv Python: finding + OSV if migrate declined. Batch `--apply` never migrates to uv. `-i` may offer migrate.
- `--apply-advisories` upgrades only packages with a known fix, no major bumps unless preset `strict`, `--allow-majors`, or interactive opt-in. Non-uv Python report-only until migrated.
- Missing PM binary: warn, skip binary-dependent work, continue. Settings file checks still run. Preflight first.
- Human summary default; `--json` and `--sarif` for the same data; markdown report only with `--report <path>`.
- Skip walking: `node_modules`, `.git`, `dist`, `build`, `.venv`, `vendor`, `__pycache__`, `.pnpm-store`.
- Tests: Bun test runner. Tests at seams only. Fixture dirs under `tests/fixtures/`. Inject filesystem, PATH, runners, time, and cache dir — do not mock our own modules.
- v1 settings surface (all presets): (1) install scripts / trusted builds (2) lockfile discipline (3) audit enabled (4) minimum package age (5) registry / index policy (6) leftover lockfiles (7) PM pin. Presets only change strictness, not the checklist.

## Seams (test only these)

Do not test private helpers, TOML library internals, or CLI argv libraries.

1. **Policy** — `loadPolicy({ files, flags, env })` → resolved `Policy`.
2. **Discovery** — `discoverProjects(root, { fs, now })` → `Project[]`.
3. **Settings audit** — `auditSettings(project, policy)` → `Finding[]`.
4. **Preflight** — `preflight(project, { which })` → `Preflight`.
5. **Advisories** — `auditAdvisories(project, policy, { run, cache, now })` → `AdvisoryResult`.
6. **Apply settings** — `applySettings(project, findings, { fs, git, apply, force, commit })` → `ApplyResult`.
7. **Apply advisories** — `applyAdvisories(project, findings, { run, allowMajors })` → `ApplyResult`.
8. **CLI** — `run(argv, deps)` → `{ exitCode, stdout, stderr }`. This is the user-facing seam for summary, flags, interactive prompts, reports.

## Domain types (all tasks share these)

Create in `src/domain.ts` during Task 1 and extend only by adding fields that later tasks specify.

```ts
export type PackageManager =
  | "npm"
  | "pnpm"
  | "yarn"
  | "bun"
  | "uv"
  | "poetry"
  | "pip"
  | "pipenv";

export type PresetName = "relaxed" | "standard" | "strict";

export type Severity = "critical" | "high" | "moderate" | "low" | "info";

export type FindingKind =
  | "settings"
  | "advisory"
  | "leftover-lockfile"
  | "unsupported-pm"
  | "missing-binary"
  | "not-using-uv"
  | "deprecated"
  | "quarantine";

export type ManagerRole = "primary" | "leftover" | "unsupported";

export interface DetectedManager {
  name: PackageManager;
  role: ManagerRole;
  manifestPath: string;
  lockfilePath: string | null;
  configPath: string | null;
}

export interface Project {
  root: string;
  gitRoot: string | null;
  managers: DetectedManager[];
}

export interface Finding {
  kind: FindingKind;
  code: string;
  message: string;
  severity: Severity;
  path: string;
  fixable: boolean;
  manager?: PackageManager;
}

export interface Policy {
  preset: PresetName;
  enabledManagers: PackageManager[];
  overrides: Record<string, unknown>;
  perManager: Partial<Record<PackageManager, Record<string, unknown>>>;
}

export type ExitCode = 0 | 1 | 2;
```

Finding codes used by tests (do not invent aliases):

- `scripts.unrestricted`
- `lockfile.missing`
- `lockfile.leftover`
- `audit.disabled`
- `min-age.disabled`
- `registry.unpinned`
- `pm.unpinned`
- `pm.unsupported`
- `pm.missing-binary`
- `python.not-uv`

## File map

- `src/domain.ts` — types
- `src/policy.ts` — `loadPolicy`, preset tables
- `src/discover.ts` — `discoverProjects`
- `src/settings.ts` — `auditSettings`
- `src/preflight.ts` — `preflight`
- `src/advisories.ts` — `auditAdvisories`
- `src/apply-settings.ts` — `applySettings`
- `src/apply-advisories.ts` — `applyAdvisories`
- `src/cache.ts` — lockfile digest + package@version cache
- `src/report.ts` — human / json / sarif / markdown
- `src/cli.ts` — `run`
- `src/main.ts` — process entry
- `tests/*.test.ts` — one file per seam
- `tests/fixtures/` — tiny fake repos

---

### Task 1: Scaffold and domain types

**Files:**
- Create: `package.json`, `tsconfig.json`, `bunfig.toml`, `.gitignore`, `src/domain.ts`, `src/main.ts`, `src/cli.ts`, `tests/cli.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces: `src/domain.ts` exports exactly the types in Domain types. `run(argv: string[], deps?: { stdout, stderr, cwd, env })` exists and is exported from `src/cli.ts`. `src/main.ts` calls `run(process.argv.slice(2))` and `process.exit(exitCode)`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/cli.test.ts
import { expect, test } from "bun:test";
import { run } from "../src/cli";

test("mailclad with no args prints usage and exits 2", async () => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run([], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: process.cwd(),
    env: {},
  });
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).toContain("Usage: mailclad");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/cli.test.ts`
Expected: FAIL because `../src/cli` does not exist or `run` is not exported.

- [ ] **Step 3: Write minimal scaffold + implementation**

`package.json`:

```json
{
  "name": "mailclad",
  "version": "0.1.0",
  "type": "module",
  "bin": { "mailclad": "./src/main.ts" },
  "scripts": {
    "test": "bun test",
    "build": "bun build ./src/main.ts --compile --outfile dist/mailclad"
  }
}
```

`src/cli.ts` — `run([])` returns `{ exitCode: 2 }` and writes `Usage: mailclad <command>` to stderr. Do not implement `audit` yet.

`src/domain.ts` — export the types from Domain types. No runtime logic.

`src/main.ts` — import `run`, exit with its code.

`.gitignore`: `node_modules`, `dist`, `.superpowers`, `.worktrees`.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test`
Expected: PASS, output pristine.

- [ ] **Step 5: Commit**

```bash
git add package.json tsconfig.json bunfig.toml .gitignore src/domain.ts src/main.ts src/cli.ts tests/cli.test.ts
git commit -m "feat: scaffold mailclad CLI with usage exit"
```

---

### Task 2: Policy load and layered merge

**Files:**
- Create: `src/policy.ts`, `tests/policy.test.ts`
- Test: `tests/policy.test.ts`

**Interfaces:**
- Consumes: `Policy`, `PresetName`, `PackageManager` from `src/domain.ts`
- Produces:

```ts
export function loadPolicy(input: {
  userToml?: string;
  scanToml?: string;
  repoToml?: string;
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> };
}): Policy
```

Default `enabledManagers`: `["npm","pnpm","yarn","bun","uv"]`. Missing files are omitted by the caller (pass `undefined`, do not read disk in this function).

Preset meaning for later settings (store on `Policy` as data if useful, or keep in `src/policy.ts` as `PRESET_DEFAULTS`):

- `standard`: `ignoreScripts: true`, `minReleaseAgeDays: 7`, `auditLevel: "high"`, `requireLockfile: true`, `requirePmPin: true`
- `strict`: `ignoreScripts: true`, `minReleaseAgeDays: 14`, `auditLevel: "moderate"`, `requireLockfile: true`, `requirePmPin: true`
- `relaxed`: `ignoreScripts: false`, `minReleaseAgeDays: 0`, `auditLevel: "critical"`, `requireLockfile: true`, `requirePmPin: false`

`loadPolicy` merge order: user → scan → repo → flags. Closer / later wins. Per-PM tables merge on top of global for that manager only (`policy.perManager.pnpm`).

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { loadPolicy } from "../src/policy";

test("defaults to standard preset when no config given", () => {
  const policy = loadPolicy({});
  expect(policy.preset).toBe("standard");
  expect(policy.enabledManagers).toEqual(["npm", "pnpm", "yarn", "bun", "uv"]);
});

test("repo config overrides user preset and flags override repo", () => {
  const policy = loadPolicy({
    userToml: `preset = "relaxed"\n`,
    repoToml: `preset = "strict"\n`,
    flags: { preset: "standard" },
  });
  expect(policy.preset).toBe("standard");
});

test("per-manager table overrides only that manager", () => {
  const policy = loadPolicy({
    repoToml: `
preset = "standard"
[pnpm]
ignoreScripts = false
`,
  });
  expect(policy.preset).toBe("standard");
  expect(policy.perManager.pnpm?.ignoreScripts).toBe(false);
  expect(policy.perManager.npm).toBeUndefined();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/policy.test.ts`
Expected: FAIL because `src/policy.ts` does not exist.

- [ ] **Step 3: Write minimal implementation**

Parse TOML with `smol-toml`. Implement merge as specified. Do not walk the filesystem.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/policy.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/policy.ts tests/policy.test.ts package.json bun.lock
git commit -m "feat: load layered mailclad policy from TOML and flags"
```

---

### Task 3: Hybrid project discovery

**Files:**
- Create: `src/discover.ts`, `tests/discover.test.ts`, fixture trees under `tests/fixtures/discover/`
- Test: `tests/discover.test.ts`

**Interfaces:**
- Consumes: `Project`, `DetectedManager` from `src/domain.ts`
- Produces:

```ts
export function discoverProjects(
  root: string,
  opts?: { readDir?: (dir: string) => string[]; readFile?: (path: string) => string | null; isDir?: (path: string) => boolean },
): Project[]
```

If `opts` omitted, use `node:fs` / Bun file APIs. Tests pass an in-memory tree.

Rules:

- If `root` is a git repo (has `.git`) or has no nested `.git` dirs, treat `root` as one repo tree.
- If `root` contains nested directories that each have `.git`, each of those is a repo. Do not treat the parent as a project unless it itself has a PM root.
- Inside a repo, detect PM roots (not every nested `package.json` unless that package has its own config file: `.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`, `bunfig.toml`, `uv.toml`, `uv.lock`).
- Detect:
  - npm primary: `package-lock.json` or (`package.json` without pnpm/yarn/bun lock and without `packageManager` yarn/pnpm/bun)
  - pnpm primary: `pnpm-lock.yaml` or `pnpm-workspace.yaml`
  - yarn primary (Berry): `yarn.lock` plus `.yarnrc.yml` or `packageManager` starting with `yarn@` major >= 2
  - yarn unsupported: `yarn.lock` without `.yarnrc.yml` and `packageManager` yarn@1 or missing (classic)
  - bun primary: `bun.lock` / `bun.lockb` or `bunfig.toml`
  - uv primary: `uv.lock` or `[tool.uv]` in `pyproject.toml`
  - leftover: extra lockfiles beside a different primary (e.g. `package-lock.json` next to `pnpm-lock.yaml`) → manager `npm` role `leftover`
- Skip directory names: `node_modules`, `.git`, `dist`, `build`, `.venv`, `vendor`, `__pycache__`, `.pnpm-store`

- [ ] **Step 1: Write the failing test**

Build fixtures:

1. `tests/fixtures/discover/many-repos/alpha/.git` + `alpha/package-lock.json` + `alpha/package.json`
2. `tests/fixtures/discover/many-repos/beta/.git` + `beta/pnpm-lock.yaml` + `beta/package.json` + `beta/package-lock.json` (leftover npm)
3. `tests/fixtures/discover/monorepo/.git` + `monorepo/pnpm-workspace.yaml` + `monorepo/pnpm-lock.yaml` + `monorepo/packages/app/package.json` (no own config)
4. `tests/fixtures/discover/monorepo/packages/app/.npmrc` wait — put a *separate* fixture `monorepo-override/` if needed so app with `.npmrc` is its own detect. Simpler: in `monorepo`, only workspace root is a project; add `tests/fixtures/discover/nested-npmrc/.git` + root `pnpm-lock.yaml` + `packages/app/package.json` + `packages/app/.npmrc` → two PM roots (pnpm at root, npm config at app).

```ts
import { expect, test } from "bun:test";
import { discoverProjects } from "../src/discover";
import { join } from "node:path";

const FIX = join(import.meta.dir, "fixtures/discover");

test("a folder of git repos yields one project per repo", () => {
  const projects = discoverProjects(join(FIX, "many-repos"));
  const roots = projects.map((p) => p.root.split("/").at(-1)).sort();
  expect(roots).toEqual(["alpha", "beta"]);
});

test("leftover package-lock beside pnpm is leftover npm not a second apply target", () => {
  const beta = discoverProjects(join(FIX, "many-repos")).find((p) => p.root.endsWith("beta"));
  expect(beta?.managers.some((m) => m.name === "pnpm" && m.role === "primary")).toBe(true);
  expect(beta?.managers.some((m) => m.name === "npm" && m.role === "leftover")).toBe(true);
});

test("monorepo workspace packages without their own config are not separate projects", () => {
  const projects = discoverProjects(join(FIX, "monorepo"));
  expect(projects).toHaveLength(1);
  expect(projects[0]?.managers.some((m) => m.name === "pnpm" && m.role === "primary")).toBe(true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/discover.test.ts`
Expected: FAIL because `src/discover.ts` does not exist.

- [ ] **Step 3: Write minimal implementation**

Implement `discoverProjects` as specified. Create the fixture files listed.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/discover.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/discover.ts tests/discover.test.ts tests/fixtures/discover
git commit -m "feat: discover git repos and package-manager roots"
```

---

### Task 4: Settings audit for npm and pnpm

**Files:**
- Create: `src/settings.ts`, `tests/settings.test.ts`, `tests/fixtures/settings/`
- Test: `tests/settings.test.ts`

**Interfaces:**
- Consumes: `Project`, `Policy`, `Finding` ; `loadPolicy` for building policies in tests
- Produces:

```ts
export function auditSettings(
  project: Project,
  policy: Policy,
  opts?: { readFile?: (path: string) => string | null },
): Finding[]
```

Checks (emit a `Finding` with the exact `code` when the setting is missing or weaker than the preset):

npm (primary only), file `.npmrc`:

- `ignore-scripts=true` required when preset is `standard` or `strict` → else `scripts.unrestricted`
- lockfile present (`package-lock.json`) → else `lockfile.missing`
- `audit=true` or `audit-level` meeting the gate → else `audit.disabled`
- `min-release-age` >= preset days (`7` standard, `14` strict). `relaxed` does not emit `min-age.disabled`
- `registry=` present → else `registry.unpinned` at `info` for standard, `high` for strict
- `package.json` `packageManager` field starting with `npm@` when `requirePmPin` → else `pm.unpinned` (`info` standard, `high` strict)

pnpm (primary only), file `pnpm-workspace.yaml` (not `.npmrc`):

- scripts: `dangerouslyAllowAllBuilds` must not be true; prefer `onlyBuiltDependencies` present or `neverBuiltDependencies` — if neither and builds unrestricted → `scripts.unrestricted`
- `lockfile` / lockfile present (`pnpm-lock.yaml`) → else `lockfile.missing`
- `audit` / `auditLevel` meeting gate → else `audit.disabled`
- `minimumReleaseAge` in hours or string duration: standard needs >= 7 days (168 hours), strict >= 14 days
- `registry` or `registries` default → else `registry.unpinned`
- `packageManager` in package.json `pnpm@` → else `pm.unpinned`

Leftover managers: exactly one finding `lockfile.leftover` severity `high`, `fixable: false`.

If policy `enabledManagers` omits a detected leftover, still report leftover. If it omits a primary PM, skip that PM's settings checks.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { auditSettings } from "../src/settings";
import { loadPolicy } from "../src/policy";
import type { Project } from "../src/domain";

function npmProject(root: string): Project {
  return {
    root,
    gitRoot: root,
    managers: [
      {
        name: "npm",
        role: "primary",
        manifestPath: `${root}/package.json`,
        lockfilePath: `${root}/package-lock.json`,
        configPath: `${root}/.npmrc`,
      },
    ],
  };
}

test("standard preset flags npm without ignore-scripts", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});

test("standard preset is quiet on ignore-scripts when set", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
    "/p/package-lock.json": `{"lockfileVersion":3}`,
    "/p/.npmrc": `ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n`,
  };
  const findings = auditSettings(npmProject("/p"), loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.filter((f) => f.kind === "settings")).toEqual([]);
});

test("leftover npm lockfile is a leftover finding and is not fixable", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/pnpm-lock.yaml",
        configPath: "/p/pnpm-workspace.yaml",
      },
      {
        name: "npm",
        role: "leftover",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: null,
      },
    ],
  };
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@10.0.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml": "packages:\n  - '.'\nminimumReleaseAge: 10080\n",
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  const leftover = findings.find((f) => f.code === "lockfile.leftover");
  expect(leftover?.fixable).toBe(false);
  expect(leftover?.severity).toBe("high");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/settings.test.ts`
Expected: FAIL because `src/settings.ts` does not exist.

- [ ] **Step 3: Write minimal implementation**

Implement npm + pnpm + leftover only. Other PMs return no settings findings yet (Task 5).

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/settings.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/settings.ts tests/settings.test.ts
git commit -m "feat: audit npm and pnpm security settings"
```

---

### Task 5: Settings audit for yarn, bun, uv, and Yarn v1

**Files:**
- Modify: `src/settings.ts`, `tests/settings.test.ts`

**Interfaces:**
- Consumes: `auditSettings` from Task 4
- Produces: same function, additional managers

Yarn Berry (`.yarnrc.yml`): `enableScripts: false` when standard/strict; lockfile `yarn.lock`; audit not disabled; `npmRegistryServer` set; `packageManager` `yarn@` major >= 2.

Yarn v1 (`role === "unsupported"`): finding `pm.unsupported`, severity `high`, `fixable: false`, no other yarn settings checks.

bun (`bunfig.toml`): `[install] optional = false` not required; require `[install.security]` / trustedDependencies or disable scripts analog — if `install.auto` allows scripts unrestricted → `scripts.unrestricted`. Minimal: if `bunfig.toml` missing `trustedDependencies` and does not set a deny-scripts equivalent, emit `scripts.unrestricted` under standard/strict. Lockfile `bun.lock` or `bun.lockb`. Registry `install.registry`.

uv: `uv.lock` required (`lockfile.missing` if absent). `[tool.uv]` `exclude-newer` or `exclude-newer` duration meeting min age. `packageManager` N/A — `pm.unpinned` not emitted for uv. Default index must be set or implicit pypi is OK for standard; strict emits `registry.unpinned` if extra indexes exist without `index-strategy = "first-index"`.

- [ ] **Step 1: Write the failing test**

Add to `tests/settings.test.ts`:

```ts
test("yarn v1 is unsupported and not fixable", () => {
  const project: Project = {
    root: "/y",
    gitRoot: "/y",
    managers: [
      {
        name: "yarn",
        role: "unsupported",
        manifestPath: "/y/package.json",
        lockfilePath: "/y/yarn.lock",
        configPath: null,
      },
    ],
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => (p.endsWith("package.json") ? `{"name":"y"}` : null),
  });
  expect(findings).toEqual([
    expect.objectContaining({
      code: "pm.unsupported",
      fixable: false,
      severity: "high",
      kind: "unsupported-pm",
    }),
  ]);
});

test("yarn berry without enableScripts false is unrestricted under standard", () => {
  const project: Project = {
    root: "/y",
    gitRoot: "/y",
    managers: [
      {
        name: "yarn",
        role: "primary",
        manifestPath: "/y/package.json",
        lockfilePath: "/y/yarn.lock",
        configPath: "/y/.yarnrc.yml",
      },
    ],
  };
  const files: Record<string, string> = {
    "/y/package.json": `{"name":"y","packageManager":"yarn@4.5.0"}`,
    "/y/yarn.lock": "# yarn lockfile v1\n",
    "/y/.yarnrc.yml": `nodeLinker: node-modules\n`,
  };
  const findings = auditSettings(project, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/settings.test.ts`
Expected: FAIL on `pm.unsupported` / yarn scripts (not implemented).

- [ ] **Step 3: Write minimal implementation**

Extend `auditSettings` for yarn, bun, uv as specified.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/settings.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/settings.ts tests/settings.test.ts
git commit -m "feat: audit yarn, bun, uv settings and flag yarn v1"
```

---

### Task 6: Non-uv Python detection

**Files:**
- Modify: `src/discover.ts`, `src/settings.ts`, `tests/discover.test.ts`, `tests/settings.test.ts`
- Create: `tests/fixtures/discover/poetry-app/`

**Interfaces:**
- Consumes: existing discover + settings
- Produces: Poetry / pip / pipenv detected as primary managers with roles; settings emits `python.not-uv`

Detect:

- `poetry.lock` or `[tool.poetry]` in `pyproject.toml` → `poetry` primary (unless uv also present — then poetry is leftover)
- `Pipfile` / `Pipfile.lock` → `pipenv`
- `requirements.txt` or `requirements-*.txt` without uv → `pip`
- `pyproject.toml` with no `[tool.uv]` and no poetry/pipenv → `pip` primary if it has a project table

`auditSettings` for `poetry` | `pip` | `pipenv` primary: emit `python.not-uv`, kind `not-using-uv`, severity `high`, `fixable: false` (migrate is interactive-only, later task).

- [ ] **Step 1: Write the failing test**

```ts
test("poetry project is detected and flagged as not using uv", () => {
  const projects = discoverProjects(join(FIX, "poetry-app"));
  expect(projects[0]?.managers.some((m) => m.name === "poetry" && m.role === "primary")).toBe(true);
  const findings = auditSettings(projects[0]!, loadPolicy({}), {
    readFile: (p) => (p.endsWith("pyproject.toml") ? `[tool.poetry]\nname = "x"\n` : null),
  });
  expect(findings.some((f) => f.code === "python.not-uv")).toBe(true);
});
```

Fixture: `tests/fixtures/discover/poetry-app/.git` + `pyproject.toml` with `[tool.poetry]` + `poetry.lock`.

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/discover.test.ts tests/settings.test.ts`
Expected: FAIL (poetry not detected or code missing).

- [ ] **Step 3: Write minimal implementation**

Detection + one finding. Do not implement migrate.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/discover.ts src/settings.ts tests tests/fixtures/discover/poetry-app
git commit -m "feat: flag Poetry and pip projects that are not using uv"
```

---

### Task 7: Binary preflight

**Files:**
- Create: `src/preflight.ts`, `tests/preflight.test.ts`

**Interfaces:**
- Consumes: `Project`
- Produces:

```ts
export interface Preflight {
  missing: { manager: PackageManager; binary: string }[];
  warnings: Finding[];
}

export function preflight(
  project: Project,
  opts: { which: (binary: string) => string | null },
): Preflight
```

Binary map: npm→`npm`, pnpm→`pnpm`, yarn→`yarn`, bun→`bun`, uv→`uv`, poetry→`poetry`, pip→`uv` (needed only if we were to migrate; for settings-only, pip/poetry/pipenv do **not** require a binary). Only **primary** JS/uv managers require binaries for advisory later; preflight still reports missing binaries for primary npm/pnpm/yarn/bun/uv so the CLI can warn.

Missing → finding `pm.missing-binary`, kind `missing-binary`, severity `info`, `fixable: false`.

- [ ] **Step 1: Write the failing test**

```ts
import { expect, test } from "bun:test";
import { preflight } from "../src/preflight";
import type { Project } from "../src/domain";

test("missing pnpm is a warning finding and does not throw", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/pnpm-lock.yaml",
        configPath: "/p/pnpm-workspace.yaml",
      },
    ],
  };
  const result = preflight(project, { which: () => null });
  expect(result.missing).toEqual([{ manager: "pnpm", binary: "pnpm" }]);
  expect(result.warnings[0]?.code).toBe("pm.missing-binary");
});

test("leftover npm does not require the npm binary", () => {
  const project: Project = {
    root: "/p",
    gitRoot: "/p",
    managers: [
      {
        name: "pnpm",
        role: "primary",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/pnpm-lock.yaml",
        configPath: null,
      },
      {
        name: "npm",
        role: "leftover",
        manifestPath: "/p/package.json",
        lockfilePath: "/p/package-lock.json",
        configPath: null,
      },
    ],
  };
  const result = preflight(project, { which: (b) => (b === "pnpm" ? "/usr/bin/pnpm" : null) });
  expect(result.missing).toEqual([]);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/preflight.test.ts`
Expected: FAIL because module missing.

- [ ] **Step 3: Write minimal implementation**

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/preflight.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/preflight.ts tests/preflight.test.ts
git commit -m "feat: preflight required package-manager binaries"
```

---

### Task 8: CLI audit (settings + preflight + summary + exit codes)

**Files:**
- Modify: `src/cli.ts`, `tests/cli.test.ts`
- Create: `src/report.ts`, `src/audit.ts`, `tests/report.test.ts`

**Interfaces:**
- Consumes: discover, loadPolicy, auditSettings, preflight
- Produces:

```ts
// src/audit.ts
export function auditPath(root: string, input: {
  policy: Policy;
  apply: boolean;
  applyAdvisories: boolean;
  interactive: boolean;
  concurrency: number;
  deps: {
    readFile: (path: string) => string | null;
    readDir: (dir: string) => string[];
    isDir: (path: string) => boolean;
    which: (binary: string) => string | null;
  };
}): { exitCode: ExitCode; projects: Array<{ project: Project; findings: Finding[] }> }

// src/report.ts
export function formatHuman(result: ReturnType<typeof auditPath>): string
```

CLI:

```
mailclad audit [path] [--preset standard] [--apply] [--apply-advisories] [-i] [--concurrency 4] [--json] [--sarif] [--report file.md] [--force] [--commit] [--refresh] [--no-cache] [--allow-majors]
```

This task implements `mailclad audit [path]` **settings + preflight only** (ignore apply flags: if `--apply` is passed, print to stderr `apply is not implemented` and still run audit / exit 2). Default path: cwd.

Policy files: read `XDG_CONFIG_HOME/mailclad/config.toml` or `HOME/.config/mailclad/config.toml`, then `<path>/.mailclad.toml`, then each project `.mailclad.toml`.

Exit: if any settings finding has severity at/above the gate (`standard`: high+critical; leftover `high` counts), exit `1`. If any `missing-binary` and no policy failures, exit `0` (warning). If discovery finds zero projects, exit `2`.

Human summary must include: repos scanned, settings findings count, warnings count.

- [ ] **Step 1: Write the failing test**

```ts
test("audit of a fixture repo with open npm scripts exits 1 and lists the finding", async () => {
  const root = join(import.meta.dir, "fixtures/discover/many-repos/alpha");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root], {
    stdout: { write: (s: string) => stdout.push(s) },
    stderr: { write: (s: string) => stderr.push(s) },
    cwd: import.meta.dir,
    env: { HOME: join(import.meta.dir, "fixtures/empty-home") },
  });
  expect(result.exitCode).toBe(1);
  expect(stdout.join("")).toContain("scripts.unrestricted");
});
```

Ensure `alpha` fixture `package.json` / lockfile exist from Task 3; add `.npmrc` without ignore-scripts if needed so the finding is real.

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/cli.test.ts`
Expected: FAIL (`audit` not implemented or exit not 1).

- [ ] **Step 3: Write minimal implementation**

Wire discover → per-project policy merge → settings → preflight → human report → exit code. No advisories yet.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli.ts src/audit.ts src/report.ts tests/cli.test.ts tests/report.test.ts tests/fixtures
git commit -m "feat: mailclad audit reports settings findings and exit codes"
```

---

### Task 9: Advisory cache and native audit

**Files:**
- Create: `src/cache.ts`, `src/advisories.ts`, `tests/advisories.test.ts`, `tests/cache.test.ts`

**Interfaces:**

```ts
export interface Cache {
  getLockfile(digest: string): AdvisoryResult | null;
  putLockfile(digest: string, result: AdvisoryResult): void;
  getPackage(name: string, version: string): PackageAdvisory[] | null;
  putPackage(name: string, version: string, rows: PackageAdvisory[]): void;
}

export function createFsCache(dir: string, now: () => number, ttlMs: number): Cache

export interface AdvisoryResult {
  findings: Finding[];
  fromCache: boolean;
  ranLive: boolean;
}

export function auditAdvisories(
  project: Project,
  policy: Policy,
  deps: {
    cache: Cache;
    now: () => number;
    digest: (lockfileBytes: string) => string;
    readFile: (path: string) => string | null;
    run: (argv: string[], cwd: string) => Promise<{ code: number; stdout: string; stderr: string }>;
  },
): Promise<AdvisoryResult>
```

Behavior:

- If no primary JS/uv manager, return empty findings, `ranLive: false` (Python OSV is Task 10).
- If lockfile digest cache hit within TTL (default 24h): return cached findings, `fromCache: true`, `ranLive: false`.
- Else: if package@version cache has rows, caller may preview — this function still runs live. After live, `putLockfile` and `putPackage` for each package in the live result.
- Live: npm `["npm","audit","--json"]`, pnpm `["pnpm","audit","--json"]`, bun `["bun","audit","--json"]`, yarn `["yarn","npm","audit","--json"]`, uv `["uv","audit","--output-format","json","--frozen"]`.
- Map JSON severities onto `Finding` kind `advisory` (or `deprecated` / `quarantine` for uv adverse statuses). Codes: use advisory id when present else `advisory.unknown`.
- Gate filtering is **not** done here; return all findings. CLI/auditPath applies the gate for exit `1`.
- If `run` throws or `code` is neither 0 nor 1 (npm audit exits 1 on vulns), treat exit 1 with JSON as success; other codes → throw a tagged error `{ incomplete: true }` that `auditPath` turns into exit `2`.

TTL constant: `86_400_000`.

- [ ] **Step 1: Write the failing test**

```ts
test("identical lockfile digest within TTL skips the live runner", async () => {
  const calls: string[][] = [];
  const cache = createFsCache("/tmp/mailclad-test-cache", () => 1_000, 86_400_000);
  const project = /* pnpm primary with lockfilePath /p/pnpm-lock.yaml */;
  const deps = {
    cache,
    now: () => 1_000,
    digest: () => "abc",
    readFile: () => "lock",
    run: async (argv: string[]) => {
      calls.push(argv);
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
  };
  await auditAdvisories(project, loadPolicy({}), deps);
  deps.now = () => 2_000;
  const second = await auditAdvisories(project, loadPolicy({}), deps);
  expect(second.fromCache).toBe(true);
  expect(second.ranLive).toBe(false);
  expect(calls).toHaveLength(1);
});

test("package@version cache hit still runs live audit", async () => {
  const calls: string[][] = [];
  const cache = createFsCache("/tmp/mailclad-test-cache2", () => 1_000, 86_400_000);
  cache.putPackage("left-pad", "1.0.0", [{ name: "left-pad", version: "1.0.0", severity: "high", id: "GHSA-x" }]);
  // project lockfile digest unique
  const result = await auditAdvisories(project, loadPolicy({}), {
    cache,
    now: () => 1_000,
    digest: () => "unique-digest",
    readFile: () => "other-lock",
    run: async (argv) => {
      calls.push(argv);
      return { code: 0, stdout: `{"advisories":{}}`, stderr: "" };
    },
  });
  expect(result.ranLive).toBe(true);
  expect(calls.length).toBeGreaterThan(0);
});
```

Fill in `project` with a real `Project` object like earlier tasks.

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/advisories.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Use a temp dir in tests; do not touch the real `~/.cache/mailclad` from tests.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test tests/advisories.test.ts tests/cache.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cache.ts src/advisories.ts tests/advisories.test.ts tests/cache.test.ts
git commit -m "feat: cache and run native package-manager audits"
```

---

### Task 10: Wire advisories into auditPath + OSV for non-uv Python

**Files:**
- Modify: `src/audit.ts`, `src/advisories.ts`, `src/cli.ts`, `tests/cli.test.ts`, `tests/advisories.test.ts`

**Interfaces:**
- Consumes: Task 8 `auditPath`, Task 9 `auditAdvisories`
- Produces: `auditPath` runs preflight first; if binary missing, skip advisories for that manager and keep settings. If primary is poetry/pip/pipenv, call OSV via injected `run` only if `deps.runOsv` provided:

```ts
runOsv?: (lockOrRequirements: string) => Promise<Finding[]>
```

Default `runOsv` in CLI may be unimplemented stub returning `[]` plus a finding `python.not-uv` already present. Add one test that when `runOsv` returns a high advisory, exit is `1`.

Human summary adds advisory counts by severity.

`--json` prints the full result object with `exitCode`, `projects`, findings.

- [ ] **Step 1: Write the failing test**

```ts
test("json output includes advisory findings from injected runner", async () => {
  // use run() with deps that include a fake advisory runner if you extend run() deps;
  // otherwise test auditPath directly
});
```

Implement the test against `auditPath` with injected `run` that returns a critical npm audit JSON. Expect `exitCode === 1` and a finding kind `advisory`.

Also: missing binary + clean settings → `exitCode === 0` and a `pm.missing-binary` warning in the result.

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/cli.test.ts`
Expected: FAIL (advisories not wired).

- [ ] **Step 3: Write minimal implementation**

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/audit.ts src/advisories.ts src/cli.ts src/report.ts tests
git commit -m "feat: include advisories in audit summary and exit codes"
```

---

### Task 11: Apply settings

**Files:**
- Create: `src/apply-settings.ts`, `tests/apply-settings.test.ts`
- Modify: `src/cli.ts`, `src/audit.ts`

**Interfaces:**

```ts
export function applySettings(
  project: Project,
  findings: Finding[],
  policy: Policy,
  deps: {
    readFile: (path: string) => string | null;
    writeFile: (path: string, body: string) => void;
    gitStatus: (root: string) => "clean" | "dirty" | "not-git";
    gitCommit?: (root: string, message: string) => void;
    force: boolean;
    commit: boolean;
  },
): ApplyResult

export interface ApplyResult {
  written: string[];
  skipped: "dirty" | "nothing" | null;
  committed: boolean;
}
```

If dirty and not `force`, return `{ written: [], skipped: "dirty", committed: false }` — `auditPath` maps this to exit `2` when `--apply` was set.

Write only fixable settings findings. Create the correct file if missing. Do not write leftover lockfile away. Do not write `~/.npmrc`.

npm: merge keys into `.npmrc`. pnpm: merge keys into `pnpm-workspace.yaml`. yarn: `.yarnrc.yml`. bun: `bunfig.toml`. uv: existing `uv.toml` or `[tool.uv]`.

`--apply` on CLI now performs apply after audit (still serial).

- [ ] **Step 1: Write the failing test**

```ts
test("apply writes ignore-scripts to .npmrc on a clean tree", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x"}`,
    "/p/package-lock.json": `{}`,
    "/p/.npmrc": `registry=https://registry.npmjs.org/\n`,
  };
  const project = /* npm primary */;
  const findings = auditSettings(project, loadPolicy({}), { readFile: (p) => files[p] ?? null });
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
    gitStatus: () => "clean",
    force: false,
    commit: false,
  });
  expect(result.skipped).toBeNull();
  expect(files["/p/.npmrc"]).toContain("ignore-scripts=true");
});

test("apply skips a dirty tree without force", () => {
  const result = applySettings(project, findings, loadPolicy({}), {
    readFile: () => null,
    writeFile: () => {
      throw new Error("must not write");
    },
    gitStatus: () => "dirty",
    force: false,
    commit: false,
  });
  expect(result.skipped).toBe("dirty");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/apply-settings.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/apply-settings.ts src/audit.ts src/cli.ts tests/apply-settings.test.ts
git commit -m "feat: apply security settings to the correct PM config files"
```

---

### Task 12: Apply advisories, reports, concurrency flag

**Files:**
- Create: `src/apply-advisories.ts`, `tests/apply-advisories.test.ts`
- Modify: `src/cli.ts`, `src/audit.ts`, `src/report.ts`, `tests/cli.test.ts`, `tests/report.test.ts`

**Interfaces:**

```ts
export function applyAdvisories(
  project: Project,
  findings: Finding[],
  deps: {
    run: (argv: string[], cwd: string) => Promise<{ code: number; stdout: string; stderr: string }>;
    allowMajors: boolean;
    currentVersions: Record<string, string>;
    fixVersions: Record<string, string>;
  },
): Promise<ApplyResult>
```

Only upgrade when `fixVersions[name]` has the same major as `currentVersions[name]` unless `allowMajors` or policy preset is `strict`. Invoke: npm `npm install pkg@fix --save-exact` (or equivalent one package at a time). pnpm `pnpm add pkg@fix`. uv `uv lock --upgrade-package pkg`. Non-uv python: no writes.

`--json` / `--sarif` / `--report path` emit the same finalized result (after live advisories). Markdown is not written unless `--report` is passed.

`--concurrency` parsed, default 4, used for settings/advisory *audit* only (Promise pool). Apply stays serial.

- [ ] **Step 1: Write the failing test**

```ts
test("apply advisories does not cross a major version", async () => {
  const ran: string[][] = [];
  const result = await applyAdvisories(project, [/* fixable high finding for left-pad */], {
    run: async (argv) => {
      ran.push(argv);
      return { code: 0, stdout: "", stderr: "" };
    },
    allowMajors: false,
    currentVersions: { "left-pad": "1.0.0" },
    fixVersions: { "left-pad": "2.0.0" },
  });
  expect(ran).toEqual([]);
  expect(result.skipped).toBe("nothing");
});

test("format json and markdown include finding codes", () => {
  const json = formatJson(sampleResult);
  const md = formatMarkdown(sampleResult);
  expect(json).toContain("scripts.unrestricted");
  expect(md).toContain("scripts.unrestricted");
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test tests/apply-advisories.test.ts tests/report.test.ts`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Implement `formatJson`, `formatSarif`, `formatMarkdown` in `src/report.ts`. Interactive (`-i`) can be a follow-up if time: if `-i` is passed in this task, implement a `prompt` dep that receives `{ project, settingsCount, advisoryCount }` and returns `'settings' | 'advisories' | 'both' | 'skip'`. Test with a fake prompt. If not reached, implement the prompt interface and one test.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/apply-advisories.ts src/report.ts src/cli.ts src/audit.ts tests
git commit -m "feat: apply advisory upgrades and emit json sarif markdown reports"
```

---

## Phase 2 (not this plan)

GitHub Action workflow presets (`standard` / `strict` / `relaxed`) that run `mailclad audit` and fail on exit 1 (and optionally 2).

## Self-review

- Spec coverage: discovery, policy, seven settings, leftover lockfiles, yarn v1, non-uv Python, preflight, exit codes, apply safety, advisory cache rules, reports, concurrency — each maps to a task.
- Placeholder scan: Task 10’s first CLI test block is specified as `auditPath`-level; implementers must write a concrete `auditPath` test, not a stub comment.
- Type consistency: `Finding.code` literals and `loadPolicy` / `discoverProjects` / `auditSettings` / `preflight` / `auditAdvisories` / `applySettings` / `applyAdvisories` / `run` names are stable across tasks.
