# pkguard Test-Gap Plan

**Goal:** Close the test-coverage gaps between `PLAN.md` (the spec) and the current implementation. All production code exists; these tasks add tests. If a new test exposes a real bug (behavior contradicting PLAN.md), fix the production code minimally so the test passes — the spec (PLAN.md in repo root) is the authority.

**Spec:** `PLAN.md` at the repo root. Its "Global Constraints", "Seams", and per-task check tables are binding.

## Global Constraints

- Runtime/tests: Bun. Run with `bun test <file>` and `bun test` for the full suite. Full suite must pass at the end of every task.
- Test ONLY at the seams named in PLAN.md: `loadPolicy`, `discoverProjects`, `auditSettings`, `preflight`, `auditAdvisories`, `applySettings`, `applyAdvisories`, `auditPath`, CLI `run`. Do not test private helpers. Do not mock our own modules — inject `readFile`, `run`, `which`, `cache`, `now`, `writeFile`, `gitStatus` deps as existing tests do.
- Follow the existing test style in each test file (in-memory `files` records, `Project` literals, fixture dirs under `tests/fixtures/`).
- Finding codes are fixed (see PLAN.md list): `scripts.unrestricted`, `lockfile.missing`, `lockfile.leftover`, `audit.disabled`, `min-age.disabled`, `registry.unpinned`, `pm.unpinned`, `pm.unsupported`, `pm.missing-binary`, `python.not-uv`. Never invent aliases.
- Exit codes: 0 = pass, 1 = policy failure, 2 = incomplete (missing binary handled as warning ≠ 1; zero projects = 2; advisory subprocess died = 2).
- Presets: `relaxed` (critical gate, ignoreScripts false, minReleaseAgeDays 0, no pm-pin requirement), `standard` (high+ gate, 7 days), `strict` (moderate+ gate, 14 days). Strict raises `registry.unpinned` / `pm.unpinned` severity from `info` to `high`.
- Each task commits its own work with a conventional-commit message ending in the Claude co-author trailer.

---

### Task 1: bun and uv settings-audit tests

**Files:** modify `tests/settings.test.ts` (and `src/settings.ts` only if a test exposes a spec violation).

Spec (PLAN.md Task 5):
- bun (`bunfig.toml`, lockfile `bun.lock` or `bun.lockb`, registry key `install.registry`): if `bunfig.toml` lacks `trustedDependencies` and no deny-scripts equivalent, emit `scripts.unrestricted` under standard/strict. Missing lockfile → `lockfile.missing`. Registry unset → `registry.unpinned`.
- uv (`uv.toml` or `[tool.uv]` in `pyproject.toml`): missing `uv.lock` → `lockfile.missing`. `exclude-newer` must meet min age (7 days standard, 14 strict) else `min-age.disabled`. uv never emits `pm.unpinned`. Strict only: extra indexes without `index-strategy = "first-index"` → `registry.unpinned`.

Write tests (red first, per test):
1. bun primary with bare `bunfig.toml` (no trustedDependencies) under standard → `scripts.unrestricted` present.
2. bun primary fully configured (trustedDependencies, lockfile, `install.registry` set) under standard → no settings findings.
3. bun primary with no lockfile → `lockfile.missing`.
4. uv primary with `uv.lock` absent → `lockfile.missing`.
5. uv primary with compliant `exclude-newer` (meets 7 days) and lock present under standard → quiet; and confirm no `pm.unpinned` ever for uv.
6. uv primary missing/too-recent `exclude-newer` under standard → `min-age.disabled`.
7. uv under strict with an extra index and no `index-strategy = "first-index"` → `registry.unpinned`; same config under standard → no `registry.unpinned`.

Read `src/settings.ts` `auditBun`/`auditUv` first to learn the exact config keys the implementation reads (e.g. how exclude-newer is expressed) so tests target real accepted shapes; where the implementation contradicts the spec above, the spec wins — fix the code.

### Task 2: preset scenarios and per-code npm/pnpm failure tests

**Files:** modify `tests/settings.test.ts` (and `src/settings.ts` only on spec violation).

Write tests:
1. relaxed preset: npm project without ignore-scripts and without min-release-age → NO `scripts.unrestricted` and NO `min-age.disabled` (relaxed doesn't require them), and NO `pm.unpinned` (requirePmPin false).
2. strict preset: npm project with no `registry=` and no packageManager pin → `registry.unpinned` severity `high` and `pm.unpinned` severity `high`; under standard the same two are severity `info`.
3. npm individual failure cases, one assertion each under standard: missing `package-lock.json` → `lockfile.missing`; `.npmrc` with `audit=false` (or no audit config per implementation) → `audit.disabled`; no `min-release-age` → `min-age.disabled`; no `registry=` → `registry.unpinned`; no `packageManager` field → `pm.unpinned`.
4. pnpm failure cases under standard: `dangerouslyAllowAllBuilds: true` → `scripts.unrestricted`; missing `pnpm-lock.yaml` → `lockfile.missing`; audit disabled → `audit.disabled`; no `registry` → `registry.unpinned`; no `pnpm@` pin → `pm.unpinned`.
5. enabledManagers rule: policy whose `enabledManagers` omits `pnpm`; project with pnpm primary + npm leftover → no pnpm settings findings, but `lockfile.leftover` still reported. (Build the policy via `loadPolicy` with a TOML/flags override — check `src/policy.ts` for how enabledManagers is set.)

### Task 3: advisory JSON parsing for pnpm/bun/yarn and incomplete → exit 2

**Files:** modify `tests/advisories.test.ts`, `tests/cli.test.ts` (and `src/advisories.ts` / `src/audit.ts` only on spec violation).

Spec: live commands are npm `npm audit --json`, pnpm `pnpm audit --json`, bun `bun audit --json`, yarn `yarn npm audit --json`, uv `uv audit --output-format json --frozen`. Exit code 1 with JSON = success (vulns found). Other exit codes → tagged error `{ incomplete: true }` which `auditPath` maps to exit `2`.

Write tests (use injected `run` returning realistic audit JSON for each PM — read `src/advisories.ts` parsing code to produce JSON in the shape it parses, matching what the real tools emit):
1. pnpm primary project: injected `run` asserts argv is `["pnpm","audit","--json"]` and returns pnpm audit JSON with one high advisory → result has an `advisory` finding with that severity.
2. bun primary: argv `["bun","audit","--json"]`, one critical advisory parsed.
3. yarn berry primary: argv `["yarn","npm","audit","--json"]`, one high advisory parsed.
4. `run` returns exit code 2 (or throws) → `auditAdvisories` throws an error with `incomplete: true`.
5. `auditPath`-level (in `tests/cli.test.ts` or wherever auditPath is tested today): advisory runner dying yields overall `exitCode === 2`.
6. Advisory below the gate does not fail: standard preset, one `low` advisory, clean settings → exit `0`.

### Task 4: apply-settings tests for yarn, bun, uv and create-if-missing

**Files:** modify `tests/apply-settings.test.ts` (and `src/apply-settings.ts` only on spec violation).

Spec: writes go to `.yarnrc.yml` (yarn), `bunfig.toml` (bun), `uv.toml` or existing `[tool.uv]` in `pyproject.toml` (uv). Create the correct file if missing. Only fixable findings are written. Never write user-global files.

Write tests (read `src/apply-settings.ts` first for the exact keys written):
1. yarn berry project with `scripts.unrestricted` finding on a clean tree → `.yarnrc.yml` gains the scripts-off key (e.g. `enableScripts: false`), existing keys preserved.
2. bun project → `bunfig.toml` written with the scripts-restriction fix, existing content preserved.
3. uv project with existing `pyproject.toml` containing `[tool.uv]` → fix merges into `[tool.uv]` there, not a new `uv.toml`.
4. uv project with existing `uv.toml` → fix lands in `uv.toml`.
5. Create-if-missing: npm project with NO `.npmrc` in files → apply creates `.npmrc` with the fix.
6. Non-fixable findings (`lockfile.leftover`, `pm.unsupported`, `python.not-uv`) result in no writes when they are the only findings.

### Task 5: CLI and preflight edge tests

**Files:** modify `tests/cli.test.ts`, `tests/preflight.test.ts` (and `src/cli.ts` / `src/audit.ts` / `src/preflight.ts` only on spec violation).

Write tests:
1. CLI/auditPath on a directory with zero discovered projects → exit `2`. (Use an empty fixture dir, e.g. `tests/fixtures/empty-root/.gitkeep`, or an injected empty fs.)
2. `--apply --commit` happy path: clean tree, fixable finding, injected `gitCommit` succeeds → `ApplyResult.committed === true` and exactly one commit call per repo (auditPath-level with two projects sharing distinct roots if the existing test harness supports it; otherwise applySettings-level asserting `gitCommit` called once with the repo root).
3. preflight: yarn `role: "unsupported"` requires no binary (`missing` empty even when `which` returns null).
4. preflight: poetry/pip/pipenv primaries require no binary; uv primary DOES require `uv`.

### Final step (controller): run `bun test` for the whole suite; all green.
