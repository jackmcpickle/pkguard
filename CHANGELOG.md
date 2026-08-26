# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## [1.1.5](https://github.com/jackmcpickle/pkguard/compare/v1.1.4...v1.1.5) (2026-08-26)

### Bug Fixes

* **uv:** report one vulnerability once, not once per advisory database ([#36](https://github.com/jackmcpickle/pkguard/issues/36)) ([12230b3](https://github.com/jackmcpickle/pkguard/commit/12230b3580d41d04ef54e8f551d8770757926ac3))
## [1.1.4](https://github.com/jackmcpickle/pkguard/compare/v1.1.3...v1.1.4) (2026-08-26)
## [1.1.3](https://github.com/jackmcpickle/pkguard/compare/v1.1.2...v1.1.3) (2026-08-24)

### Bug Fixes

* **release:** bump the catalog version alongside Cargo.toml ([#33](https://github.com/jackmcpickle/pkguard/issues/33)) ([a235b05](https://github.com/jackmcpickle/pkguard/commit/a235b0515844f7a7f616087024b74c732dfa6ed6)), references [#24](https://github.com/jackmcpickle/pkguard/issues/24)
## [1.1.2](https://github.com/jackmcpickle/pkguard/compare/v1.1.1...v1.1.2) (2026-08-24)

### Bug Fixes

* **bun:** surface bun audit advisories, which parsed to nothing ([#32](https://github.com/jackmcpickle/pkguard/issues/32)) ([516fff8](https://github.com/jackmcpickle/pkguard/commit/516fff8affb72894782e97a02329953b47437417))
## [1.1.1](https://github.com/jackmcpickle/pkguard/compare/v1.1.0...v1.1.1) (2026-08-24)
## [1.1.0](https://github.com/jackmcpickle/pkguard/compare/v1.0.3...v1.1.0) (2026-08-24)

### Features

* **site:** improve AI readiness (79 → target 90+) ([#22](https://github.com/jackmcpickle/pkguard/issues/22)) ([b595f1b](https://github.com/jackmcpickle/pkguard/commit/b595f1b91066f959aea6d3cf0f2bda31eed476a1))
## [1.0.3](https://github.com/jackmcpickle/pkguard/compare/v1.0.2...v1.0.3) (2026-08-24)
## [1.0.2](https://github.com/jackmcpickle/pkguard/compare/v1.0.1...v1.0.2) (2026-08-24)
## [1.0.1](https://github.com/jackmcpickle/pkguard/compare/v0.1.11...v1.0.1) (2026-08-23)
## [0.1.11](https://github.com/jackmcpickle/pkguard/compare/v0.1.10...v0.1.11) (2026-08-23)
## [1.0.0](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.10...v1.0.0) (2026-08-23)

### ⚠ BREAKING CHANGES

* Rewritten in Rust (workspace in `crates/`). The command surface changed: `mailclad audit` is now `mailclad scan` (read-only), and the old apply/report flags are gone. Config is regrouped under `[policy]` and `[manager.<name>]` tables in `.mailclad.toml` / the user `config.toml`, with unknown keys rejected.
* npm distribution is dropped; install from source with `cargo install --path crates/mailclad` (Homebrew tap and release binaries to follow).

### Kept contracts

* Finding codes and exit codes (0 pass / 1 policy failure / 2 incomplete) are unchanged.
* Currently ported: streaming discovery for all managers, npm settings checks, npm advisory audit with lockfile-digest caching, human and JSON (`schemaVersion` 2) output.

## [0.1.10](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.9...v0.1.10) (2026-08-23)
## [0.1.9](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.8...v0.1.9) (2026-08-23)
## [0.1.8](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.7...v0.1.8) (2026-08-22)
## [0.1.7](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.6...v0.1.7) (2026-08-22)

### Bug Fixes

* **pnpm:** audit.level, 90-day ignoreAfter, and quoted YAML keys ([#9](https://github.com/jackmcpickle/package-manager-security/issues/9)) ([b05e79c](https://github.com/jackmcpickle/package-manager-security/commit/b05e79c82d0fbac5b36a60447a05001b2a691733))
## [0.1.6](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.5...v0.1.6) (2026-08-22)

### Features

* company registry config and agentic settings warnings ([#8](https://github.com/jackmcpickle/package-manager-security/issues/8)) ([6d95337](https://github.com/jackmcpickle/package-manager-security/commit/6d95337bf626aab35da8ea29885280ec3d7c863f))
## [0.1.5](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.4...v0.1.5) (2026-08-21)

### Features

* report config sources and add mailclad init ([#7](https://github.com/jackmcpickle/package-manager-security/issues/7)) ([ab04913](https://github.com/jackmcpickle/package-manager-security/commit/ab04913108deec243d2b9ce381639420b743e394))
## [0.1.4](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.3...v0.1.4) (2026-08-21)

### Bug Fixes

* **ci:** create GitHub release from publish after tagging ([#6](https://github.com/jackmcpickle/package-manager-security/issues/6)) ([713b38c](https://github.com/jackmcpickle/package-manager-security/commit/713b38cc5e11c2b335303a3359aadfcf9b02b85b))
* **ci:** retrigger publish after squash commit skipped workflows ([72cafe6](https://github.com/jackmcpickle/package-manager-security/commit/72cafe6158d5f75ea3bc0cee8b6d24029204bdd6))
## [0.1.3](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.2...v0.1.3) (2026-08-21)
## [0.1.2](https://github.com/jackmcpickle/package-manager-security/compare/v0.1.1...v0.1.2) (2026-08-21)
## 0.1.1 (2026-08-21)

### Features

* add Composer/PHP as a first-class package manager ([7c47f48](https://github.com/jackmcpickle/package-manager-security/commit/7c47f48416f0099ef2be1497986f3d707574639d))
* add npm publish setup, docs, and binary release workflow ([987f456](https://github.com/jackmcpickle/package-manager-security/commit/987f4563ef3ad253ddb686099a559ed159703ce9))
* apply advisory upgrades and emit json sarif markdown reports ([d11db9c](https://github.com/jackmcpickle/package-manager-security/commit/d11db9c20e233ce769b144dcb983fe15c15689cb))
* apply security settings to the correct PM config files ([80ed888](https://github.com/jackmcpickle/package-manager-security/commit/80ed888147a546aa6bfece831ccdacd50836eb8f))
* audit npm and pnpm security settings ([ae7fc9d](https://github.com/jackmcpickle/package-manager-security/commit/ae7fc9dbd523e324ec75e8f9c1d72b0e11092fb0))
* audit yarn, bun, uv settings and flag yarn v1 ([65cee9e](https://github.com/jackmcpickle/package-manager-security/commit/65cee9ecee57b81c9c851a3d2b904d31aae94dc8))
* cache and run native package-manager audits ([ed0bbb4](https://github.com/jackmcpickle/package-manager-security/commit/ed0bbb44e8e936f2e516211cc1c39763c0a34222))
* discover git repos and package-manager roots ([85b511e](https://github.com/jackmcpickle/package-manager-security/commit/85b511eaecdf1119bf8e92d88a5f029dc71a020b))
* expand PM coverage, gap checks, auto releases, and advisories ([651def9](https://github.com/jackmcpickle/package-manager-security/commit/651def9398f41367fed50800a87b3d23e2197d83))
* flag Poetry and pip projects that are not using uv ([cd696e6](https://github.com/jackmcpickle/package-manager-security/commit/cd696e65cd99c7e9d0c63a403a53d350b9823c95))
* include advisories in audit summary and exit codes ([b33075e](https://github.com/jackmcpickle/package-manager-security/commit/b33075ef6987d10154001303eec31e454fca0e6e))
* load layered pmsec policy from TOML and flags ([95e390a](https://github.com/jackmcpickle/package-manager-security/commit/95e390a91071a1554ab2ad979a04285ac474c436))
* modernise package-manager security checks for the cooldown era ([84b3bc5](https://github.com/jackmcpickle/package-manager-security/commit/84b3bc5c181bdb55d28ba7c1be67aed4b93d14eb))
* pmsec audit reports settings findings and exit codes ([72b295c](https://github.com/jackmcpickle/package-manager-security/commit/72b295cf91489bb449d715460ca6ed82192db039))
* preflight required package-manager binaries ([6beb166](https://github.com/jackmcpickle/package-manager-security/commit/6beb16643b0648bbdda75f8c6edd04572cd3ad81))
* scaffold pmsec CLI with usage exit ([652c2f3](https://github.com/jackmcpickle/package-manager-security/commit/652c2f3b49b2912c6509519837295fe6d766ca6d))
* warn when apply skips a dirty tree and add color output ([f4e93a6](https://github.com/jackmcpickle/package-manager-security/commit/f4e93a6d4eab9c9756191c8268108fac66971b43))

### Bug Fixes

* apply settings by git root and refuse unsafe writes ([6338ab9](https://github.com/jackmcpickle/package-manager-security/commit/6338ab92e4f0fe07e04d2df6428246af2630a312))
* clear bun lint failures that broke CI ([b19f776](https://github.com/jackmcpickle/package-manager-security/commit/b19f776c20c320a3b45ecfa05083f0d49ee0f7d5))
* count deprecated and quarantine findings toward the gate ([e2b7116](https://github.com/jackmcpickle/package-manager-security/commit/e2b7116c457fc45bc65a8b52494dac1dd8e4fb61))
* derive advisory versions and wire default interactive prompt ([1d52129](https://github.com/jackmcpickle/package-manager-security/commit/1d52129fcc2dc01dc6e55dc9286fccc4c13921c2))
* detect nested Python roots and parse real TOML tables ([0378bef](https://github.com/jackmcpickle/package-manager-security/commit/0378befa0e069c1ce66795641098d73b43a12544))
* honor cache flags, keep advisory apply after settings, and treat pnpm min-age as minutes ([444034e](https://github.com/jackmcpickle/package-manager-security/commit/444034e3d0d7414de617db39d40d1bbd2c8c4d61))
* ignore advisory ranges and pick the highest safe fix ([aa66999](https://github.com/jackmcpickle/package-manager-security/commit/aa6699949e8a6c6a978e4aa5576b43e8bcf1030e))
* keep --preset over repo policy and count unique git roots ([b86f914](https://github.com/jackmcpickle/package-manager-security/commit/b86f914da10840944fd3237af549ed5edf0c51ba))
* keep flags last-win and limit per-manager tables ([eccf9e4](https://github.com/jackmcpickle/package-manager-security/commit/eccf9e4a82742ce97341afe51361c9d093ee4787))
* reject Date scalars as pyproject TOML tables ([88f1b3a](https://github.com/jackmcpickle/package-manager-security/commit/88f1b3a0fe31793c4ab045ec442939716250ffe0))
* reject malformed yarn packageManager pins ([8c302fa](https://github.com/jackmcpickle/package-manager-security/commit/8c302face1622b70b467434ff584265995a031be))
* require pyproject project and tool tables to be objects ([ec5e879](https://github.com/jackmcpickle/package-manager-security/commit/ec5e879adaac41eafafd88b283d79fc45285b789))
* resolve all Ultracite lint violations and gate CI on bun lint ([988e9db](https://github.com/jackmcpickle/package-manager-security/commit/988e9db7361c4eea2853cbf4e93e38b580e004dd))
* resolve lint failures from complexity and formatting ([aebe864](https://github.com/jackmcpickle/package-manager-security/commit/aebe864af2838a0ecb0e4893896d28f130ecefa2))
* skip lockfile cache without a readable lockfile ([7a23fbc](https://github.com/jackmcpickle/package-manager-security/commit/7a23fbc02746fc74096a335034cb080db91ec0f9))
* treat .git files as repos and tighten yarn/uv detect ([b9dc438](https://github.com/jackmcpickle/package-manager-security/commit/b9dc43835e66cd386267ec879deb0819132f52c7))
* treat empty yarn audit stdout as no findings on clean repos ([2576975](https://github.com/jackmcpickle/package-manager-security/commit/257697501ea9082128cc63750c326c775fb419d6))
