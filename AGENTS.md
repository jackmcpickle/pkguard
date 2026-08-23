# Agent guide

pkguard is a Rust workspace (`crates/pkguard-core` + `crates/pkguard`) with an Astro docs site in `site/`.

## Commands

```bash
cargo test --workspace                              # test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt                                           # format
cargo run -p pkguard -- scan .                      # run the CLI
cargo run -q -p pkguard -- dump-catalog > site/src/generated/catalog.json  # refresh docs data
npm run check --prefix site && npm run build --prefix site                 # site
```

## Rules

- The docs site renders `site/src/generated/catalog.json`, dumped from the binary. If you change the CLI surface, `Manager`, or preset defaults, regenerate it — CI diffs it against a fresh dump.
- Finding codes and exit codes 0/1/2 are contracts; do not change them without a decision.
- `scan` is read-only. Nothing in the scan path may write to user files.
- Managers live in one exhaustive `Manager` enum (`crates/pkguard-core/src/manager.rs`); add capabilities there, never in a side table. `Manager::ported()` must track the settings/advisories match arms.
- Settings checks are organized by check family (`settings/checks/`), not by manager.
- The old npm package is named `mailclad` (≤ 0.1.x, Bun build) and the docs domain is still mailclad.dev; do not rename those references.
