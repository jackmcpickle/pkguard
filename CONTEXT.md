# Domain language

The words pkguard uses for its own concepts. Use these exactly — in code, in
commits, and in conversation. If a term here stops matching the code, fix one of
them.

See `AGENTS.md` for the rules that constrain changes (frozen finding codes, the
0/1/2 exit contract, catalog regeneration).

## Core

**Manager** — a package manager pkguard knows about (npm, pnpm, yarn, bun, uv,
cargo, composer, bundler, and the legacy Python three). The exhaustive
`Manager` enum in `manager.rs` is the single registry: config file, config
format, lockfile names, audit command, and write target all hang off it. A
capability never goes in a side table.
_Defined in_: `crates/pkguard-core/src/manager.rs`

**Project** — one directory pkguard audits: a root, an optional git root, and
the managers detected in it. Discovery produces these; everything downstream
consumes them.
_Defined in_: `crates/pkguard-core/src/discover.rs`

**Detected manager** — a Manager actually found in a Project, with the config
and lockfile paths discovery resolved, plus a **Role**.

**Role** — what a detected manager is to its project. `Primary` is the one in
charge. `Leftover` is a second manager's lockfile hanging around. `Unsupported`
is present but not auditable (yarn classic).

## Findings

**Finding** — one thing pkguard has to say about a project. Every finding has a
frozen **code**, a severity, a path, and a kind. Findings are the only currency
between the audit and the output.
_Defined in_: `crates/pkguard-core/src/findings.rs`

**Settings finding** — something wrong with how a manager is *configured*.
Produced by reading config files; never needs the network.

**Advisory** — a known vulnerability in an installed package, produced by
running the manager's own audit command. Advisories, deprecations, and
quarantines are the advisory kinds; everything else is a settings kind.

**Check family** — a group of related settings checks (minimum release age,
lifecycle scripts, audit gate, registry pinning, lockfiles). Checks are
organised by family, not by manager: `min_age.rs` holds every manager's age
check.
_Defined in_: `crates/pkguard-core/src/settings/checks/`

**Preset** — how strict to be: `relaxed`, `standard`, `strict`. A preset sets
the thresholds that checks read.

## Fixing

**Settings fix** — the repair attached to a fixable finding: a file, a format,
and a list of edits. Fixes travel *with* findings, so a finding and its repair
cannot drift apart.
_Defined in_: `crates/pkguard-core/src/fix/mod.rs`

**Config edit** — one `set` or `unset` of a dotted key. Format-agnostic; the
per-format writers in `format/` know how to apply one.

**Fix plan** — every fix for a project, merged per file and rendered into the
new file contents. Produced by `plan_fixes`; only `apply_fixes` reads it.

**Planned change** — one settings-level "this goes from X to Y", used for
reporting. Distinct from the file contents: a change is what the user is told,
the rendered file is what gets written.

**Apply mode** — `Write` carries the plan out; `DryRun` reports it and touches
nothing.

**Blocked** — why an apply did nothing: `Nothing` (no changes to make) or
`DirtyGit` (uncommitted work, needs `--force`).

**Skip reason** — why one file was left alone: `Forbidden` (target is outside
the project root), `Unparseable` (existing file could not be read), or
`WriteFailed`.

## Running

**Scan** — one full run: discover projects, audit each, stream results. The
`scan` function is the whole entry point.
_Defined in_: `crates/pkguard-core/src/pipeline.rs`

**Audit event** — what a scan streams: a project discovered, a manager
finished, a project finished, and finally `Done`. Streaming is deliberate —
results appear as they are ready, not batched at the end.

**Scan summary** — the run-level tally and the exit code.

**Project report** — one finished project, as the output formats consume it.
_Defined in_: `crates/pkguard/src/report.rs`

**Reporter** — an output format. Two exist: human (streams a block per project)
and JSON (accumulates one document). Both read the same project report.

## Seams

The two places core behaviour can be swapped, each with a real and a test
adapter:

**Command runner** — everything that spawns a subprocess (manager audits, git).
`TokioRunner` in production, `CannedRunner` in tests.
_Defined in_: `crates/pkguard-core/src/exec.rs`

**Clock** — everything that reads the current date (uv's `exclude-newer`, the
advisory cache TTL). `SystemClock` in production, `FixedClock` in tests.
_Defined in_: `crates/pkguard-core/src/clock.rs`
