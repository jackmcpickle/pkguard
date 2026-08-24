# Agent guide

pkguard is a Rust workspace (`crates/pkguard-core` + `crates/pkguard`) with an Astro docs site in `site/`.

`CONTEXT.md` defines the domain language — read it before naming anything.

## Setup

```bash
brew install prek && prek install   # git pre-commit hooks (cargo fmt + clippy)
```

## Commands

```bash
cargo test --workspace                              # test
cargo clippy --workspace --all-targets --all-features --locked
cargo fmt                                           # format
cargo run -p pkguard -- scan .                      # run the CLI
cargo run -q -p pkguard -- dump-catalog > site/src/generated/catalog.json  # refresh docs data
npm run check --prefix site && npm run build --prefix site                 # site
```

## Rules

- The docs site renders `site/src/generated/catalog.json`, dumped from the binary. If you change the CLI surface, `Manager`, or preset defaults, regenerate it — CI diffs it against a fresh dump.
- Finding codes and exit codes 0/1/2 are contracts; do not change them without a decision.
- `scan` is read-only **unless `--fix` is passed**; the default path must never open a file for writing.
- Managers live in one exhaustive `Manager` enum (`crates/pkguard-core/src/manager.rs`); add capabilities there, never in a side table. `Manager::ported()` must track the settings/advisories match arms.
- Settings checks are organized by check family (`settings/checks/`), not by manager.
- A manager's config file and format come from `Manager` (`config_format`, `write_target`). Never restate them in a check module.
- The core has exactly two injection seams: `CommandRunner` (subprocesses) and `Clock` (the current date). Anything else that reaches outside the process needs a decision first.
- The docs domain is pkguard.dev.
- Lints live in the workspace `[lints]` table, not in a CI flag, so a bare `cargo clippy` matches CI. `pedantic` and `nursery` are denied. Silence a lint with `#[expect(..., reason = "...")]` at the narrowest scope that works — never a bare `#[allow]`.
