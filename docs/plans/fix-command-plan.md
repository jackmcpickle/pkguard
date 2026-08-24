# Plan: bring back `--fix`, `audit` alias, phased output, offline mode

**Goal:** four things the Rust port dropped or never had:

1. `pkguard scan --fix` writes the safe settings back into each package manager's config file.
2. `pkguard audit` is an alias for `pkguard scan`.
3. Output shows a **settings** section then an **advisories** section per project.
4. `--no-audit` (and `audit = false` in config) skips every live package-manager call, so pkguard runs fully offline.

**Decisions already made (do not re-litigate):**

- `--fix` writes **settings files only**. It never bumps package versions and never runs a package manager. The old TS `--apply-advisories` is out of scope.
- Output is **two sections inside one per-project block**. Streaming stays as it is; we do not batch the whole run into two phases.
- Offline is `--no-audit` flag **plus** `audit = false` config key, so it can be set per repo.

**Prior art:** the TypeScript implementation is in git history at `9732387^`:
`src/apply-settings.ts`, `src/settings.ts` (the `configFix` / `setOp` / `unsetOp` call sites),
`tests/apply-settings.test.ts`. Read them before writing the Rust equivalent — the edit
key/value pairs per finding code are already worked out there and should be ported verbatim.

## Global constraints

- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt` must be clean at the end of every phase.
- **Finding codes and exit codes 0/1/2 are frozen contracts.** No new codes, no renames. `findings::codes::STATIC_FINDING_CODES` and its frozen test stay as-is.
- **`scan` without `--fix` stays read-only.** Nothing on the default path may open a file for writing. This is an existing repo rule (`AGENTS.md`) and the reason `--fix` is a separate opt-in.
- Settings checks stay organised **by check family** in `settings/checks/`, never by manager. Manager variation is data on the `Manager` enum.
- Tests go at the seams that already exist: `settings::audit_manager_settings`, `pipeline::scan`, `apply::plan_fixes` / `apply::apply_fixes` (new), `render::project_block`, and CLI integration tests in `crates/pkguard/tests/`.
- Do not mock our own modules. Inject deps the way `CommandRunner` / `CannedRunner` already do, and use `tempfile` dirs for real file IO.
- Every phase is TDD: write the failing test first, watch it fail, then make it pass.
- Regenerate `site/src/generated/catalog.json` at the end (`cargo run -q -p pkguard -- dump-catalog`). CI diffs it.

---

## Phase 1 — Fix payload on findings

**Files:** `crates/pkguard-core/src/findings.rs`, new `crates/pkguard-core/src/fix/mod.rs`.

Add the data model. This is pure data, no IO.

```rust
pub enum ConfigValue { Str(String), Bool(bool), Int(i64), List(Vec<String>), Table(BTreeMap<String, ConfigValue>) }
pub enum ConfigEdit { Set { key: String, value: ConfigValue }, Unset { key: String } }
pub enum ConfigFormat { Npmrc, Yaml, Toml, Json, BundleConfig }
pub struct SettingsFix { pub file: PathBuf, pub format: ConfigFormat, pub edits: Vec<ConfigEdit> }
```

Add `pub fix: Option<SettingsFix>` to `Finding`, `#[serde(skip_serializing_if = "Option::is_none")]`.
`setting_finding` keeps `fixable: true` but sets `fix: None`; add a `setting_finding_with_fix(...)`
builder alongside it so the ~45 call sites migrate one at a time.

Dotted keys (`install.registry`, `config.policy.advisories.audit`) mean "nested path" for
Yaml/Toml/Json and "literal key" for Npmrc/BundleConfig. Encode that in the writers, not the callers.

**Tests** (`fix/mod.rs` unit tests):

1. `SettingsFix` round-trips through serde_json with the camelCase convention the rest of `Finding` uses.
2. `Finding` without a fix serialises with no `fix` key at all (schemaVersion 2 stays backward compatible).
3. `ConfigValue::Table` and `::List` serialise as JSON object/array, not as strings.

---

## Phase 2 — Config file writers

**Files:** `crates/pkguard-core/src/format/npmrc.rs`, `yaml.rs`, new `toml.rs`, `json.rs`, `bundle_config.rs`.

One `pub fn edit(raw: &str, edits: &[ConfigEdit]) -> Result<String, EditError>` per format.
`EditError::Unparseable` means "refuse to write this file", never "clobber it".

Preservation rules, in priority order:

- **npmrc / bundle-config**: line-oriented rewrite. Keep comments, blank lines, and unrelated key order. Rewrite a key in place if present; append at the end if not. `Unset` drops the line. Port `rewriteNpmrcLine` from the TS.
- **toml**: use `toml_edit` (already a dependency) so comments and formatting survive. Do **not** parse-and-restringify with `toml`.
- **yaml**: `serde_yaml` round-trip. Comments are lost — that is the TS behaviour too and is acceptable; note it in the docs.
- **json**: `serde_json` with 2-space indent, trailing newline. Preserve key order (`preserve_order` feature) so `composer.json` diffs stay small.

**Tests** (one module per format):

1. npmrc: existing key rewritten in place, comment lines above it untouched, unrelated keys keep their order.
2. npmrc: absent key appended at the end with exactly one trailing newline; file that had no trailing newline gets one.
3. npmrc: `Unset` removes the line and leaves no blank gap.
4. toml: `install.ignoreScripts = true` created in an empty file, and updated in a file that already has `[install]` with a comment — comment survives.
5. toml: nested `tool.uv.exclude-newer` written into a `pyproject.toml` that already has `[project]`, without disturbing `[project]`.
6. yaml: `audit.level` set as a nested map; blanket `*` values are replaced not merged.
7. json: `config.policy.advisories.block = true` creates the intermediate objects; existing sibling keys keep their original order.
8. bundle-config: `BUNDLE_COOLDOWN` written in bundler's `KEY: "value"` shape.
9. Every format: unparseable input returns `EditError::Unparseable` and the caller gets no output string.
10. Every format: applying the same edits twice is idempotent (second run produces a byte-identical file).

---

## Phase 3 — Attach fixes to the checks

**Files:** all of `crates/pkguard-core/src/settings/checks/*.rs`, `settings/mod.rs`, `manager.rs`.

Add `Manager::write_target(project_root, detected) -> Option<(PathBuf, ConfigFormat)>`.
`write_config_name()` already exists and covers 7 managers; uv is the special case (`uv.toml`
if present, else `[tool.uv]` in `pyproject.toml`) and needs the detected-manager context.

Then walk the TS `configFix` call sites and port each one. Grouped by check family:

| Family | Codes gaining a fix | Notes |
|---|---|---|
| `scripts` | `scripts.unrestricted`, `scripts.pin-missing`, `scripts.bypass-enabled`, `scripts.non-strict`, `scripts.legacy-config` | pnpm's build edits also migrate legacy `allowBuilds` keys — port `pnpmBuildEdits` whole |
| `audit_gate` | `audit.disabled`, `audit.blocking-disabled`, `audit.malware-disabled` | yarn unsets legacy `audit`/`npmAudit` before setting `enableNpmAudit` |
| `min_age` | `min-age.disabled`, `min-age.non-strict`, `min-age.missing-time` | unit per manager differs: npm days, bun seconds, pnpm minutes, uv date, bundler days |
| `registry` | `registry.unpinned` | value comes from `settings.registry`, skip the fix when unset |
| `pm_pin` | `pm.unpinned` | writes `packageManager` into `package.json` |
| `integrity` | `integrity.checksum-relaxed`, `integrity.strict-ssl`, `integrity.hardened-mode` | |
| `source` | `source.git-unrestricted`, `source-fallback.enabled`, `source.non-registry` | |
| `provenance` | `provenance.ignore-after`, `provenance.no-downgrade` | |
| `lockfile` | `lockfile.trust-bypass`, `lockfile.run-verify` | `lockfile.missing` and `lockfile.leftover` stay **unfixable** — we will not generate a lockfile |

Deliberately **not** fixable, and their `fixable` flag must stay `false`:
`pm.missing-binary`, `pm.unsupported`, `pm.multiple-node`, `pm.multiple-python`, `python.not-uv`,
`lockfile.missing`, `lockfile.leftover`, `overrides.present`, `overrides.legacy-location`,
`scripts.allowlist-advisory`, `scripts.allowlist-masked`, `min-age.exclude-all`,
`registry.mismatch`, `layout.pnp`, `layout.shamefully-hoist`, `cache.path-committed`,
`advisory.unknown`, `agentic.cache-disabled`.

**Tests** (extend the existing settings tests, tempfile-backed):

1. **One consistency test that must not be skipped:** for every static finding code, assert
   `fixable == fix.is_some()`. This is the guard that stops the two from drifting.
2. Per manager (npm, pnpm, yarn, bun, uv, cargo, composer, bundler): a deliberately bad project
   produces findings whose fixes all target that manager's expected write file and format.
3. npm `scripts.unrestricted` carries exactly `set ignore-scripts=true`.
4. pnpm `scripts.unrestricted` carries the full build-edit set including the legacy-key unsets.
5. uv with `uv.toml` present targets `uv.toml`; uv with only `pyproject.toml` targets
   `pyproject.toml` and uses the `tool.uv.` key prefix.
6. Every unfixable code listed above yields `fix: None` even when the manager has a write target.
7. `registry.unpinned` with no configured registry yields `fix: None` (nothing safe to write).

---

## Phase 4 — The apply engine

**Files:** new `crates/pkguard-core/src/apply.rs`.

Two functions, separated so the plan is testable without touching disk:

```rust
pub struct PlannedChange { pub project_root: PathBuf, pub file: PathBuf, pub setting: String, pub current: String, pub next: String }
pub struct FixPlan { pub files: Vec<(PathBuf, String)>, pub changes: Vec<PlannedChange>, pub blocked: Option<Blocked> }
pub enum Blocked { DirtyGit(PathBuf), Nothing }

pub fn plan_fixes(project: &Project, findings: &[Finding]) -> FixPlan;
pub async fn apply_fixes(plan: &FixPlan, runner: &dyn CommandRunner, force: bool) -> ApplyResult;
```

Safety rules, all ported from the TS `isForbiddenWrite` / `isDirtyRoot`:

- **Never write outside the project root.** Any fix whose `file` escapes the root is dropped silently from the plan.
- **Never write `~/.npmrc`** or any path outside the scanned tree, even if a check somehow emits one.
- **Refuse to write into a dirty git tree** unless `--force`. Git status goes through `CommandRunner`
  so tests can drive it with `CannedRunner`. A non-git directory counts as writable.
- **Merge edits per file** before writing — several findings can target the same `.npmrc`, and we
  write each file exactly once.
- A file whose current value already equals the target value produces **no change row** and, if it
  is the only edit, **no write**.

**Tests** (`apply.rs` unit tests, tempfile + `CannedRunner`):

1. Two findings targeting the same `.npmrc` merge into one write with both keys set.
2. A fix pointing at `../../etc/npmrc` is dropped from the plan and nothing is written.
3. A fix pointing at `~/.npmrc` is dropped from the plan.
4. Dirty git root: `plan.blocked == DirtyGit`, `written` is empty, but `changes` is still populated so we can show what *would* happen.
5. Dirty git root with `force: true`: files are written.
6. Non-git directory: files are written without a `--force`.
7. Already-compliant file: `Blocked::Nothing`, zero writes, file mtime unchanged.
8. Unparseable target file (`EditError::Unparseable`): that file is skipped, other files in the same project still get written, and the result reports the skip.
9. Applying to a project, re-scanning it, and applying again produces zero changes on the second pass (the round-trip test that proves the fixes actually satisfy the checks).

---

## Phase 5 — Pipeline: offline mode and section-tagged findings

**Files:** `crates/pkguard-core/src/pipeline.rs`, `config.rs`.

- `ScanOptions` gains `pub no_audit: bool`.
- `ConfigFile` gains `pub audit: Option<bool>`; `ResolvedSettings` gains `pub audit: bool` (default `true`).
  Flag wins over config, per the existing layering rule.
- In `audit_project`, when audits are off: run settings as normal, then `continue` before the
  binary preflight. **No `pm.missing-binary` finding is emitted** — the binary was never needed.
- Offline runs must **not** set `incomplete`. Skipping audits on purpose is not an incomplete run,
  so a clean offline scan exits `0`.
- `ScanOptions` also gains `pub fix: bool` and `pub force: bool`; when `fix` is set, `audit_project`
  calls `apply::plan_fixes` + `apply::apply_fixes` after settings and **before** advisories, then
  **re-runs the settings checks** so the reported findings reflect the fixed state.
- `AuditEvent::ProjectFinished` gains `applied: Option<ApplyResult>`.

**Tests** (extend `pipeline.rs` tests, which already use `CannedRunner` + tempdirs):

1. `no_audit: true` on a repo with a known-vulnerable canned audit: advisory findings absent, settings findings present, exit `0`.
2. `no_audit: true` with the binary genuinely missing from PATH: **no** `pm.missing-binary` finding, and `incomplete == false`.
3. `no_audit: true` never invokes the runner — assert `CannedRunner` recorded zero `run` calls.
4. `audit = false` in `.pkguard.toml` at the repo level behaves identically to the flag.
5. `--no-audit` flag overrides `audit = true` in config (flag wins).
6. `fix: true`: the project's `.npmrc` is rewritten on disk, and the `ProjectFinished` findings no longer contain the fixed codes.
7. `fix: true` on a dirty git tree without force: file unchanged on disk, `applied.blocked == DirtyGit`.
8. `fix: false` (default) on a fixable project: file byte-identical afterwards — the read-only guarantee.

---

## Phase 6 — Output: settings and advisories sections

**Files:** `crates/pkguard/src/render.rs`.

Split `project_block`'s rows into two groups using the existing `FindingKind::is_advisory()`.
Settings group first. Group headers are dim; rows keep the current severity/manager/code/package/message
columns. **Column widths are computed across both groups** so the two sections stay aligned with
each other.

- A group with no rows is omitted entirely, along with its header.
- If only one group has rows, print it without the header — a settings-only project should look
  exactly like it does today, so existing snapshots barely move.
- When `--fix` ran, append a dim `fixed` line per project listing `file: setting current -> next`,
  and add a `N settings fixed` part to the summary line.
- When audits were skipped, the config line gains a dim ` · audits skipped` marker so nobody
  mistakes an offline run for a clean one.

**Tests** (extend `render.rs` unit tests):

1. Mixed project renders `settings` header, then its rows, then `advisories` header, then its rows, in that order.
2. Settings-only project renders with no group headers (unchanged from today's output).
3. Advisories-only project renders with no group headers.
4. Columns line up across the two groups — assert a long settings code and a short advisory code produce the same message column offset.
5. `fixed` lines render one row per change with the `current -> next` shape.
6. `audits skipped` marker appears on the config line only when audits were skipped.
7. Existing tests `project_block_renders_header_config_line_and_aligned_columns`, `clean_project_is_a_single_ok_line`, and `incomplete_project_is_flagged` still pass unmodified.

**JSON format is untouched.** `schemaVersion` stays `2`; sections are a human-rendering concern.
The new `fix` field on findings is additive and optional.

---

## Phase 7 — CLI surface

**Files:** `crates/pkguard/src/cli.rs`, `scan.rs`, `main.rs`, `catalog.rs`.

```
pkguard scan  [path] [flags]
pkguard audit [path] [flags]      # alias, identical behaviour
```

Clap: `#[command(alias = "audit")]` on the `Scan` variant. Same args struct, same handler —
not a copy.

New flags on `ScanArgs`:

| Flag | Meaning |
|---|---|
| `--fix` | Write the safe settings into each manager's config file |
| `--force` | Allow `--fix` on a dirty git tree |
| `--dry-run` | With `--fix`, show the changes and write nothing |
| `--no-audit` | Skip every live package-manager audit (offline) |

Rules:

- `--force` and `--dry-run` without `--fix` are a usage error, exit `2`, with a message saying so.
- `--fix --format json` includes an `applied` block per project; the human path prints the `fixed` lines from Phase 6.
- `--fix` does not change the exit code semantics. If findings remain after fixing, exit is still `1`.
- `catalog.rs` must expose `--fix`, `--no-audit`, and the `audit` alias so the docs site picks them up.

**Tests** (`crates/pkguard/tests/scan.rs`, `assert_cmd` + tempdirs):

1. `pkguard audit <dir>` produces byte-identical stdout to `pkguard scan <dir>`.
2. `pkguard audit --help` and `pkguard scan --help` both work and mention `--fix`.
3. `pkguard scan --fix` on a bad-`.npmrc` fixture rewrites the file and exits `0` when that was the only finding.
4. `pkguard scan` (no `--fix`) on the same fixture leaves the file byte-identical.
5. `pkguard scan --fix --dry-run` prints the change rows and leaves the file byte-identical.
6. `pkguard scan --force` without `--fix` exits `2` with a usage message.
7. `pkguard scan --dry-run` without `--fix` exits `2` with a usage message.
8. `pkguard scan --no-audit` on a fixture with no package-manager binary installed exits `0` and prints `audits skipped`.
9. `pkguard scan --fix --format json` emits valid JSON with `schemaVersion: 2` and an `applied` block.
10. `--fix` on a dirty git fixture exits non-zero-safe: file unchanged, message names `--force`.

---

## Phase 8 — Docs and catalog

**Files:** `README.md`, `AGENTS.md`, `site/src/generated/catalog.json`, `docs/`.

1. `cargo run -q -p pkguard -- dump-catalog > site/src/generated/catalog.json` — CI diffs this.
2. README usage block gains the four new flags and the `audit` alias.
3. README "How a scan runs" mermaid diagram gains the offline branch and the fix step.
4. README gets a short **What `--fix` writes** section: one row per manager naming the file it edits, plus the explicit list of what it will never do (no lockfile generation, no package upgrades, no writes outside the project root, no writes to a dirty git tree without `--force`).
5. `AGENTS.md` rule "`scan` is read-only" becomes "`scan` is read-only **unless `--fix` is passed**; the default path must never open a file for writing."
6. `npm run check --prefix site && npm run build --prefix site` must pass.

---

## Risks

- **Phase 3 is the bulk of the work** — ~45 fix sites across 8 managers, each needing the right key
  name and unit. Budget accordingly, and lean on the TS source rather than re-deriving the keys.
- **YAML comment loss** on `.yarnrc.yml` and `pnpm-workspace.yaml`. The TS had the same behaviour.
  If it turns out to matter, the fallback is `yaml_edit`-style line surgery, but do not build that
  up front.
- **The `fixable`/`fix` consistency test (Phase 3, test 1) is load-bearing.** If it gets weakened or
  skipped, the two fields drift and `--fix` silently stops fixing things it claims it can fix.
