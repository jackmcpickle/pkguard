# Package-manager QoL for agentic development — research, 21 August 2026

Companion to [`docs/research-2026-08-package-manager-settings.md`](./research-2026-08-package-manager-settings.md), which covers the **cooldown / install-script / provenance** era.

This note is about the other half of the config surface: **shared stores, caches, linkers, hoisting, overrides, catalogs, and lockfile coexistence**. Those knobs decide whether an AI coding agent can `install` in seconds, whether `require("foo")` succeeds when `foo` is not a declared dependency, and whether the next agent copies a dangerous workaround into `package.json`.

Checked against primary docs on 2026-08-21. The earlier note remains the source of truth for `minimumReleaseAge`, `allowBuilds`, `enableScripts`, `trustedDependencies`, and related gates.

---

## How mailclad talks about this today

mailclad walks repos, picks one **primary** JS manager, and emits settings findings with dotted codes. Settings never call the package manager; they only read committed config ([README](../README.md)).

Existing vocabulary this note maps onto:

| Code / concept | Where it lives | What it already covers |
|---|---|---|
| `lockfile.missing` | `src/settings.ts` | required lockfile absent |
| `lockfile.leftover` | `src/settings.ts` leftover path | extra JS lockfile while another manager is primary |
| `lockfile.trust-bypass` | pnpm `trustLockfile` | skip lockfile verification |
| `lockfile.run-verify` | pnpm `verifyDepsBeforeRun` | must be `error` |
| `pm.unpinned` | `package.json` `packageManager` | Corepack pin missing / wrong prefix |
| `pm.unsupported` | Yarn Classic | v1 is not an apply target |
| `pm.missing-binary` | `src/preflight.ts` | binary not on `PATH` |
| `registry.unpinned` | `.npmrc` / `pnpm-workspace.yaml` / `.yarnrc.yml` / `bunfig.toml` | registry not written |
| `scripts.unrestricted` / `scripts.legacy-config` / `scripts.allowlist-masked` | npm / pnpm / yarn / bun | install-script policy |
| `source.non-registry` | npm `allow-git` / pnpm `blockExoticSubdeps` | git/tarball sources |
| Discovery order | `src/discover.ts` `JS_PRIMARY_ORDER` | `pnpm` > `yarn` > `bun` > `npm` |

Discovery already treats a second JS lockfile as `role: "leftover"` and emits `lockfile.leftover` (`high`, not fixable). It does **not** yet read store/cache/hoist/override/catalog settings.

Severity model (from the earlier research note, still in force): explicit unsafe value → `high`; missing key whose version-default is safe → `info` (or `moderate` under `strict`); missing key whose default is unsafe → `high`. Version comes from `packageManager`; no pin assumes a current release.

---

## 1. QoL configs that help agents

These speed installs, share bytes across checkouts, and make the tree deterministic. They belong in **user / machine / CI cache** config more often than in a committed project file. A committed store path that points at `$HOME` is a portability bug.

### 1.1 Shared content-addressable store / global cache

The analogue of “the pnpm global store” exists under a different name in every manager. Agents that `rm -rf node_modules && install` on every turn waste minutes unless this is warm and on the **same filesystem** as the project (hardlinks / clonefile fail across disks).

| Manager | Official name | Config file | Default | What it does | Agent QoL |
|---|---|---|---|---|---|
| **pnpm** | `storeDir` | `pnpm-workspace.yaml` or `~/.config/pnpm/config.yaml` (plus `$PNPM_HOME/store`) | `$PNPM_HOME/store`, else XDG / `~/Library/pnpm/store` (macOS) / `~/.local/share/pnpm/store` (Linux) / `~/AppData/Local/pnpm/store` (Windows). One store per disk; a store on another disk is copied, not hard-linked. | Content-addressable store of every fetched package. `node_modules` hard-links or clones from it. | **Recommend leaving the default (or setting it once in the user config).** Shared across all local repos. Do not commit a machine-specific `storeDir`. pnpm 11.22+ still honours project-level `storeDir` / `cacheDir` even though other machine-state keys are ignored there. |
| **pnpm** | `packageImportMethod` | same | `auto` | `auto` → clone, else hardlink, else copy. `clone` is CoW (safe to edit `node_modules` without corrupting the store). `copy` is slow. | **Leave `auto`.** `copy` hurts agents. `hardlink` is fine on Linux. Changing this in-repo surprises agents that assume CoW isolation. |
| **pnpm** | `enableGlobalVirtualStore` | same | `false` (auto-off in CI). In pnpm 11, `pnpm add -g` and `pnpm dlx` use it anyway. | `node_modules` becomes symlinks into `<store>/links`, keyed by dependency-graph hash (Nix-like). Warm `rm -rf node_modules && install` is much faster. ESM does not honour `NODE_PATH`, so phantom hoists break under ESM. | **Useful on a developer / agent machine; leave off in CI and in committed config.** Agents that enable it in-repo create a layout the next agent cannot reproduce in CI. |
| **pnpm** | `frozenStore` | same | `false` (added v11.7.0) | Read-only store (Nix / OCI layer). Pair with `--offline --frozen-lockfile`. | CI / hermetic agent images. Not a laptop default. |
| **pnpm** | `verifyStoreIntegrity` | same | `true` | Re-hash store files before linking. Does **not** make an untrusted shared store safe. | Keep default. Official warning: a shared `storeDir` is a trust domain — untrusted writers can poison both contents and `index.db`. |
| **npm** | `cache` | `.npmrc` (project / `~/.npmrc` / `$PREFIX/etc/npmrc`) | POSIX `~/.npm`, Windows `%LocalAppData%\npm-cache` | Tarball + metadata cache. Not a content-addressable store; `node_modules` is still a full copy. | **Set once in the user `.npmrc` or `npm config set cache`.** A per-project `cache=` committed to git is almost always a mistake. |
| **npm** | `prefer-offline` | `.npmrc` | `false` | Skip staleness checks; still fetch cache misses. `offline` refuses the network. `cache-min` is deprecated in favour of this. | **Good for repeated agent installs** on a warm cache. `offline=true` in a committed `.npmrc` will break the first cold run. |
| **Yarn Berry** | `enableGlobalCache` | `.yarnrc.yml` | `true` | When true, cache lives under `globalFolder` and `cacheFolder` is ignored. | **Leave default `true` for agents.** Set `false` only if the team vendors `.yarn/cache` (Zero-Installs). |
| **Yarn Berry** | `cacheFolder` | `.yarnrc.yml` | `./.yarn/cache` | Project-local zip cache. Officially “relatively safe to share across projects,” but Yarn tells you to use `enableGlobalCache` for a global path. | Agents should not commit this unless Zero-Installs is an explicit policy. |
| **Yarn Berry** | `nmMode` | `.yarnrc.yml` | `classic` | `hardlinks-global` = hardlink into a global CAS (pnpm-store analogue). `hardlinks-local` = hardlink only within the project. | **`hardlinks-global` is the QoL win** on a single machine. `classic` wastes disk. Changing this changes inode identity; some tools notice. |
| **Yarn Classic (1.x)** | `cache-folder` / `YARN_CACHE_FOLDER` / `cache=` in `.npmrc` | `.yarnrc` | user-dir global cache (`yarn cache dir`) | Global tarball cache. `yarn-offline-mirror` is a **project-local** tarball dump (default `false`). | mailclad already flags Classic as `pm.unsupported`. Offline-mirror in-repo is a vendoring choice, not a store. |
| **Bun** | `[install.cache] dir` / `BUN_INSTALL_CACHE_DIR` | `bunfig.toml` or `$HOME/.bunfig.toml` | `~/.bun/install/cache` (`${name}@${version}`) | Global cache. Linux/Windows hardlink into `node_modules`; macOS `clonefile` (CoW). `[install.cache] disable=true` skips reading it. `disableManifest=true` always re-resolves latest. | **Leave enabled.** `disable` / `disableManifest` in a committed bunfig makes every agent install cold and non-deterministic. |
| **Bun** | `[install] globalStore` / `BUN_INSTALL_GLOBAL_STORE` | `bunfig.toml` | `false` | Isolated-linker analogue of pnpm’s global virtual store: share `node_modules/.bun/@…` via `/links/`. Officially “warm installs after `rm -rf node_modules` an order of magnitude faster.” | **Same recommendation as pnpm `enableGlobalVirtualStore`:** machine-local yes, committed/CI no. |

**Deno analogue.** `DENO_DIR` is the global cache (Linux `$HOME/.cache/deno`, macOS `~/Library/Caches/deno`, Windows `%LOCALAPPDATA%\deno`). Shared across projects. `--cached-only` is the offline gate. `nodeModulesDir` in `deno.json` decides whether a local `node_modules` is also written (default: only when a `package.json` exists).

**pip analogue.** Cache at `~/.cache/pip` (Linux, honours `XDG_CACHE_HOME`), `~/Library/Caches/pip` (macOS), `%LocalAppData%\pip\Cache` (Windows). Inspect with `pip cache dir`. `--no-cache-dir` is explicitly **not** recommended for layered/CI builds.

**Poetry analogue.** `cache-dir` / `POETRY_CACHE_DIR`: `$XDG_CACHE_HOME/pypoetry` or `~/.cache/pypoetry` (Linux), `~/Library/Caches/pypoetry` (macOS), `%LOCALAPPDATA%\pypoetry` (Windows). Virtualenvs default to `{cache-dir}/virtualenvs`.

**Cargo analogue.** `CARGO_HOME` (default `$HOME/.cargo`) holds the registry index and git checkouts; `cargo clean` does not purge it. `CARGO_TARGET_DIR` / `build.target-dir` is the compile-artifact cache (not a package store). `[patch]` in `Cargo.toml` is the override analogue (see §2).

**uv analogue.** Cache at `$XDG_CACHE_HOME/uv` / `$HOME/.cache/uv` or `%LOCALAPPDATA%\uv\cache`, overridable via `--cache-dir`, `UV_CACHE_DIR`, or `tool.uv.cache-dir`. Officially must be on the **same filesystem** as the venv or uv falls back to copies. `uv cache prune --ci` drops prebuilt wheels but keeps wheels built from source.

### 1.2 Deterministic trees / fewer surprises

| Manager | Setting | File | Default | Why it helps an agent |
|---|---|---|---|---|
| **pnpm** | `preferFrozenLockfile` | `pnpm-workspace.yaml` | `true` | Headless install when the lockfile satisfies `package.json`. Fast and does not rewrite the lockfile. |
| **pnpm** | `lockfile` | same | `true` | `false` means no `pnpm-lock.yaml` read or write. mailclad already emits `lockfile.missing` if the file is absent or this is `false`. |
| **pnpm** | `nodeLinker` | same | `isolated` | Isolated = symlink from `node_modules/.pnpm`. Closest to “what the lockfile actually says.” Agents that `require()` an undeclared dep fail loudly. |
| **pnpm** | `virtualStoreDir` | same | `node_modules/.pnpm` | **Must not be shared across projects** (workspaces share the root). Agents that set this to a drive root for Windows MAX_PATH should document it; another agent will assume the default. |
| **npm** | `install-strategy` | `.npmrc` | `hoisted` | `linked` installs into `node_modules/.store` and only exposes declared deps. npm **recommends `linked` for package authors** specifically to catch phantom dependencies. |
| **npm** | `package-lock` | `.npmrc` | `true` | `false` is the npm twin of pnpm `lockfile: false`. |
| **npm** | `fund` | `.npmrc` | `true` | Noise at the end of every install. **`fund=false` in user `.npmrc`** is pure QoL; not a security finding. |
| **Yarn Berry** | `nodeLinker` | `.yarnrc.yml` | `pnp` | `node-modules` is what most agents assume. `pnpm` is the CAS+symlink layout. See §2 — default PnP is the #1 agent-confusion linker. |
| **Yarn Berry** | `nmHoistingLimits` | `.yarnrc.yml` | `none` | Caps hoist height (`workspaces` / `dependencies` / `none`). Per-workspace override: `installConfig.hoistingLimits`. |
| **Bun** | `[install] linker` | `bunfig.toml` | Isolated for **new workspaces** (`configVersion=1`); hoisted for new single-package projects and pre-1.3.2 lockfiles | Isolated is the pnpm-like layout. Existing Bun repos stay hoisted unless someone writes the key. |
| **Bun** | `[install] hoist` | `bunfig.toml` | `true` (isolated linker only) | `false` skips `node_modules/.bun/node_modules`, so undeclared imports fail (root `node_modules` still visible — same caveat as pnpm). |

### 1.3 What to recommend (short)

**Machine / agent environment (do not commit):**

1. Leave each manager’s **global store/cache at its default** (or one explicit user-level path on the same disk as the worktrees).
2. Yarn Berry: keep `enableGlobalCache: true`; consider `nmMode: hardlinks-global` on Linux.
3. pnpm/Bun: `enableGlobalVirtualStore` / `install.globalStore` only on the agent host, never in the repo.
4. npm: user-level `prefer-offline=true` and `fund=false`.

**Committed project config (do commit):**

1. `packageManager` pin (mailclad `pm.unpinned`).
2. One lockfile; delete leftovers (mailclad `lockfile.leftover`).
3. Isolated / linked layouts if the project can tolerate them (`nodeLinker: isolated`, npm `install-strategy=linked`, Bun `linker = "isolated"`).
4. Do **not** commit `storeDir`, `cache`, `cacheFolder`, or `install.cache.dir` unless the team is deliberately vendoring (Yarn Zero-Installs).

---

## 2. Configs that mix agents up / create dangerous precedents

A **precedent** here means: once the file contains the workaround, the next agent treats it as the house style and copies it. mailclad’s existing leftover-lockfile and `scripts.allowlist-masked` findings are the same idea.

### 2.1 Overrides / resolutions / patches

| Manager | Name | Where | What it does | Why an agent gets confused | Audit should warn | Precedent |
|---|---|---|---|---|---|---|
| **npm** | `overrides` | root `package.json` only | Force any node in the graph (including nested object selectors and `$foo` references). Direct deps may only be overridden to the **same spec**. Values may be `npm:`, `github:`, `file:`. | The declared range in `dependencies` is no longer what gets installed. `npm ls` and the lockfile diverge from the manifest the agent just read. Nested objects are a different language from Yarn paths. | Presence of `overrides` (info/moderate). High if a value is `file:`, `github:`, or a different name (`npm:@scope/fork`). | “Just add an override” becomes the default answer to every advisory. The earlier research note already tracks `pnpm audit --fix` writing **age-gate excludes**; the same tool also writes version-scoped overrides. |
| **Yarn Berry / Classic** | `resolutions` | root `package.json` only (warning in workspaces) | Path keys (`webpack/memory-fs`, `@babel/core@npm:7.0.0/@babel/generator`). Relative `file:` / `portal:` resolve from the project root. | Agents paste npm `overrides` objects into `resolutions` (or the reverse). Classic glob `**/pkg` vs Berry’s one-level paths. | Same as overrides. Yarn’s own RFC for npm `overrides` says the two **cannot be reliably translated**. | Same copy-paste loop. |
| **pnpm** | `overrides` | `pnpm-workspace.yaml` (v11+; **no longer** `package.json#pnpm.overrides`) | `foo`, `parent>foo`, `$foo`, `-` (remove), `catalog:`. Convergence overrides require an exact version. | Agents still write `package.json#pnpm.overrides` because every pre-v11 tutorial does. v11 ignores the `pnpm` field. Selector language (`>`) is neither npm nor Yarn. | Flag `package.json#pnpm` settings on pnpm ≥ 11 as `scripts.legacy-config`-style (`legacy-config` / a new `overrides.legacy-location`). Flag `-` removals and `link:`/`file:` override values. | Once an override exists, `pnpm audit --fix` and agents keep growing it. Catalog-backed overrides (`foo: "catalog:"`) look like a pin but move when the catalog moves. |
| **Bun** | `overrides` **and** `resolutions` | root `package.json` | Accepts npm objects, pnpm `>`, Yarn paths. One parent level only. Skips pnpm `pkg@` / `-` with a warning. Nested/version-scoped rules bump `lockfileVersion` to 3. | A repo can contain **both** keys. Agents edit one and Bun still honours the other. Migration from pnpm **moves** `pnpm.overrides` into root `overrides` and leaves `pnpm-lock.yaml` on disk. | Same. Also flag dual `overrides`+`resolutions`. | Bun’s migrator teaches agents that the extra lockfile is harmless. mailclad already disagrees (`lockfile.leftover`). |
| **all (plus npm)** | `patchedDependencies` | `package.json` (npm, Yarn, Bun); pnpm historically `pnpm.patchedDependencies` / workspace yaml | Local `.patch` files applied on install. npm `keep-edit-dir` / `patch` CLI. Bun `bun patch --commit`. | The tarball hash no longer matches the registry. Agents “upgrade the package” and the patch silently fails or `allow-missing-patches` (npm CLI-only, rejected by `npm ci`) papers it over. | Presence + dangling patch (high). `allow-missing-patches` on the CLI is not an `.npmrc` key (npm ignores it there). | “We patch lodash instead of upgrading” becomes repo culture. |
| **pnpm** | `packageExtensions` | `pnpm-workspace.yaml` | Inject missing `dependencies` / `peerDependencies` into someone else’s manifest. Shared database with Yarn (`@yarnpkg/extensions`). | Looks like a real dependency. `require("react-dom")` starts working inside `react-redux` without anyone declaring it. | Info: list the extensions. High if it adds a runtime dep that the app then imports. | Agents add extensions instead of filing upstream or adding a real dependency. |
| **Cargo** | `[patch]` | `Cargo.toml` (preferred) or `.cargo/config.toml` | Replace a crate for the whole graph. Config-file `[patch]` **wins** over `Cargo.toml` and is usually **not** committed. | An agent’s `~/.cargo/config.toml` patch does not exist in CI. Two `[patch]` sources merge by proximity. | Prefer `Cargo.toml`. Warn on config-only patches. | Same as npm overrides. |

### 2.2 Hoist / linker layouts that make `require()` lie

| Setting | Official default | Agent failure mode | Audit |
|---|---|---|---|
| pnpm `shamefullyHoist` (`true` ≡ `publicHoistPattern: ['*']`) | `false` | App code can `require()` anything in the graph. The next `nodeLinker: isolated` or npm `linked` install breaks. | `layout.shamefully-hoist` **high** if `true`. |
| pnpm `hoist` / `hoistPattern` | `true` / `['*']` | Transitive packages can see each other’s undeclared deps via `node_modules/.pnpm/node_modules`. Semi-strict: **app** code still cannot. | Info unless someone then imports those names from app code. Official docs recommend narrowing `hoistPattern` to the few broken packages. |
| pnpm `publicHoistPattern` | `[]` | Selected names appear in the **root** `node_modules`. ESLint plugins historically needed this. | Info; high if `*`. |
| pnpm `nodeLinker: hoisted` | `isolated` | Flat npm-like tree. Officially justified only for React Native, AWS Lambda, `bundledDependencies`, or `--preserve-symlinks`. | `layout.hoisted` moderate/high. Agents copy it “to make webpack work.” |
| pnpm `nodeLinker: pnp` | `isolated` | No `node_modules`. Needs `symlink: false`. | Same as Yarn PnP below. |
| pnpm `nodePackageMapType: loose` | `standard` | Package maps also expose undeclared hoisted deps. | High if `loose`. |
| npm `install-strategy=hoisted` | **default** | Phantom deps work. npm itself tells authors to use `linked` to catch them. | Do not fail the default on apps; **info under `strict`** for libraries (`linked` recommended). |
| Yarn `nodeLinker: pnp` | **default** | No `node_modules`. Agents run `node script.js` and get `Cannot find module`. Need `yarn node` or `.pnp.cjs` loader. | Already implicit in mailclad tests that fixture `nodeLinker: node-modules`. New `layout.pnp` **high** (or info if `.pnp.cjs` + documented). |
| Yarn `pnpMode: loose` | `strict` | Simulates Classic hoisting; official docs: “even in loose mode, hoisted require calls are unsafe and should be discouraged.” | High if `loose`. |
| Yarn `nmHoistingLimits: none` | `none` | Classic flat hoist. `workspaces` / `dependencies` are stricter. | Info. |
| Bun `linker = "hoisted"` | default for non-workspaces / old lockfiles | Same phantom-dep story as npm. Isolated is opt-in on existing repos. | Info on old Bun projects; moderate if a **new** workspace explicitly sets hoisted. |
| Bun `hoist = true` (isolated) | `true` | `node_modules/.bun/node_modules` fallback = pnpm `hoist`. | Recommend `hoist = false` for libraries. |

### 2.3 `.npmrc` / config scope: global vs per-project

npm loads four files, later overridden by earlier: project `.npmrc`, user `~/.npmrc`, `$PREFIX/etc/npmrc`, npm builtin. Project `.npmrc` is **not** published and is ignored for `npm install -g`.

pnpm 11: **only auth + registry** still come from `.npmrc`. Hoist, linker, store, scripts, age gates live in `pnpm-workspace.yaml` or `~/.config/pnpm/config.yaml`. `npm_config_*` became `pnpm_config_*`. Project yaml **cannot** set `bin` / `globalDir` / `pnpmHomeDir` / etc. (v11.22+); `storeDir` and `cacheDir` still can. Env expansion in committed registry URLs is **ignored** (secret-exfil guard, GHSA-3qhv-2rgh-x77r).

Yarn Berry **ignores `.npmrc`**. Classic merged it.

Bun reads `$HOME/.bunfig.toml` then `./bunfig.toml`; project wins. Bun also reads a subset of `.npmrc` (`cache`, `install-strategy`, `node-linker`, `hoist`, `public-hoist-pattern`).

**Why agents get confused:** an install “works on my machine” because `~/.npmrc` has `legacy-peer-deps=true` or a custom `registry=`. CI has neither. A committed `.npmrc` that only contains `registry=` is what mailclad already wants (`registry.unpinned`). A committed `.npmrc` that also sets `ignore-scripts`, `legacy-peer-deps`, or `install-strategy` is a **policy file**, not just a registry pin.

**Audit:** keep `registry.unpinned`. Add `config.user-only` (info) when behaviour-changing keys exist only in documentation / comments pointing at user config. Flag project `.npmrc` `legacy-peer-deps=true` as `peers.legacy` **high** (npm: “not recommended”).

### 2.4 Multiple lockfiles and `packageManager` vs the actual manager

| Situation | Official behaviour | mailclad today | Gap |
|---|---|---|---|
| `package-lock.json` + `pnpm-lock.yaml` | Two independent trees. | pnpm primary (order), npm leftover → `lockfile.leftover`. | Good. |
| `bun.lock` created beside `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | Bun **migrates** the foreign lockfile on first install if `bun.lock` is missing, and **leaves the original in place**. `--yarn` / `[install.lockfile] print = "yarn"` writes a Yarn lock **in addition** to `bun.lock`. | bun primary if `bun.lock` exists; leftover on the other. | Good, but the migrator **teaches** leftover lockfiles. Message should say “Bun preserves the original on purpose; delete it.” |
| `packageManager: "pnpm@9"` but only `package-lock.json` | Corepack will refuse `npm` / `yarn` shims if `COREPACK_ENABLE_STRICT` is on (default). **npm is not shimmed by default**, so `npm i` still runs and rewrites the lockfile. | `pm.unpinned` only checks the prefix of the **detected** manager. | New `pm.mismatch`: pin name ≠ primary detected from lockfiles. |
| `packageManager` hash missing | Corepack: `name@version` required; **hash strongly recommended**. | mailclad only checks `startsWith("pnpm@")` etc. | Optional `pm.unhashed` info. |
| `devEngines.packageManager` (pnpm 11+ / Corepack) | Range allowed; resolved version stored in the lockfile. If top-level `packageManager` is absent, Corepack uses this. | Ignored. | Version-aware checks should read it as a fallback pin. |
| Yarn Classic `yarn.lock` without `.yarnrc.yml` and pin major < 2 | Classic. | `pm.unsupported`. | Good. |
| pnpm `gitBranchLockfile: true` | Lockfile named `pnpm-lock.<branch>.yaml`. | Looks like `lockfile.missing` on `pnpm-lock.yaml`. | New `lockfile.branched` if this is `true`. |

Corepack permitted managers: `yarn`, `npm`, `pnpm` (not `bun`). `COREPACK_ENABLE_STRICT=0` lets you run a different manager at the system version — the exact footgun leftover lockfiles come from.

### 2.5 `workspace:` vs `file:` vs `link:` / `portal:`

| Spec | Who | Resolves to | Publish rewrite | Agent trap |
|---|---|---|---|---|
| `workspace:` / `workspace:*` / `workspace:^` | pnpm, Yarn, Bun | **Must** be a workspace package; pnpm refuses the registry. Bare `workspace:` ≡ `workspace:*`. | Replaced with a real semver on pack/publish. | Agent “fixes” a missing workspace by changing it to `^1.0.0`, which then fetches from the registry (`linkWorkspacePackages` default is **`false`** on modern pnpm). |
| `file:../foo` | all | Path on disk. npm `install-links=true` packs it instead of symlinking (no effect on workspaces). | Stays a path unless you publish a different manifest. | Breaks on CI if the path is outside the repo. npm overrides may point `file:../local-fork`. |
| `link:` | pnpm | Symlink to an arbitrary path, including outside the workspace. | Not a publishable spec. | Invisible extra package the lockfile does not fully describe as a registry dep. |
| `portal:` | Yarn | Similar to file/link; relative paths resolve from the **project** root, not the workspace package. | — | Agents copy a `portal:` from a tutorial into a nested workspace and the path is wrong. |
| `catalog:` / `catalog:name` | pnpm (workspace yaml `catalog` / `catalogs`); Bun | Version constant. Allowed in deps **and** in pnpm `overrides`. | Stripped on publish like `workspace:`. | One catalog edit retcons every package.json. `catalogMode: strict` forbids off-catalog adds; default is `manual`. |

pnpm `saveWorkspaceProtocol` default is `rolling` (`workspace:*` / `workspace:^`). Agents that rewrite ranges to concrete versions are fighting the default.

### 2.6 Peer-dependency escape hatches

| Setting | Default (if documented) | Effect | Audit |
|---|---|---|---|
| pnpm `autoInstallPeers` | not restated on the v11 settings page; behaviour: missing non-optional peers are installed when `true` | Tree contains packages nobody listed in the app `package.json`. Conflicts print a warning and install **nothing**. | Info if `true`; the implicit install is invisible to agents reading only the root manifest. |
| pnpm `peerDependencyRules.ignoreMissing` | unset | Silences “react is missing.” | High if it contains `*` or a broad `@scope/*` used as a real runtime. |
| pnpm `peerDependencyRules.allowedVersions` | unset | “react@16 declared, react@17 is fine.” | Same class as overrides: hides a mismatch. |
| pnpm `peerDependencyRules.allowAny` | unset | Any version satisfies the named peers. | High for `*` / broad globs. |
| pnpm `strictPeerDependencies` | (fail on missing/invalid when enabled) | Opposite of the above. | Recommend `true` under `strict`. |
| npm `legacy-peer-deps` | `false` | Ignore peer deps as in npm 3–6. Officially **not recommended**. | `peers.legacy` high. |
| npm `--omit=peer` | — | Don’t unpack peers; still design a tree that could. | Different from `legacy-peer-deps`. |
| Yarn `peerDependenciesMeta.*.optional` | — | Silence unsatisfied peers. | Info. |

### 2.7 `ignore-scripts` vs allowlists

Covered in depth in the earlier note. Agent-specific addenda:

| Manager | Blunt off switch | Allowlist | Trap |
|---|---|---|---|
| npm | `ignore-scripts=true` | `package.json` `allowScripts` + `strict-allow-scripts` | mailclad already emits `scripts.allowlist-masked` when both are set (npm/cli#9450). Agents toggle `ignore-scripts` and think they disabled the allowlist tooling. |
| pnpm 11 | `ignoreScripts` / `dangerouslyAllowAllBuilds` | `allowBuilds` map; `strictDepBuilds` default `true` | Agents still write `onlyBuiltDependencies` → mailclad `scripts.legacy-config`. |
| pnpm ≤10 | `ignoreDepScripts` | `onlyBuiltDependencies` | Same keys, opposite era. |
| Yarn ≥4.14 | `enableScripts: false` (default) | `dependenciesMeta.<pkg>.built: true` | Agents set `enableScripts: true` “so esbuild works” instead of one `built: true`. |
| Bun | (scripts off unless trusted) | `package.json` `trustedDependencies` | Agents copy the whole of `node_modules` into `trustedDependencies`. |

**Precedent:** the first lifecycle exception becomes a growing allowlist with no expiry. Same pattern as `minimumReleaseAgeExclude`.

### 2.8 Catalogs

pnpm `catalog` / `catalogs` in `pnpm-workspace.yaml`; `catalog:` protocol in dependencies **and** overrides. `catalogMode`: `manual` (default) / `prefer` / `strict`. Bun accepts `catalog:` inside `overrides`.

**Why agents get confused:** `package.json` says `"lodash": "catalog:"` — there is no version in the file the agent is editing. The real pin is two directories up. A second catalog (`catalogs.react17`) means two lodashes. `strict` mode makes `pnpm add` fail in ways agents interpret as “the registry is down.”

**Audit:** info when catalogs exist; moderate if an override is `catalog:`; high if `catalogMode` is unset and versions also appear duplicated in package.json (drift).

---

## 3. Non-JS analogues (short)

| Ecosystem | Shared cache | Override / patch | Hoist-like | Notes for mailclad |
|---|---|---|---|---|
| **Deno** | `DENO_DIR`; vendor dir via `deno.json` | import-map remaps | `nodeModulesDir` auto / manual / none | Not a mailclad manager. Same “global cache vs committed vendor” fork as Yarn Zero-Installs. |
| **pip** | `cache-dir` / `PIP_CACHE_DIR` | constraints files (not a graph override) | n/a | mailclad flags pip as `python.not-uv`. |
| **Poetry** | `cache-dir` / `POETRY_CACHE_DIR` | source priorities; no npm-style override | n/a | `pm.unsupported` / `python.not-uv`. |
| **uv** | `tool.uv.cache-dir` / `UV_CACHE_DIR` | `override-dependencies` / `constraint-dependencies` in `pyproject.toml` | n/a | Already audited for `exclude-newer`, lockfile, extra indexes. Override/constraint fields are the Python `overrides` precedent — **not checked yet**. |
| **Cargo** | `CARGO_HOME` | `[patch]` / `[replace]` | n/a | `[patch]` in `.cargo/config.toml` is user-scoped and wins. mailclad already checks `minimum-release-age` in `.cargo/config.toml`. |

---

## 4. Proposed mailclad mapping

Match the existing pattern: **read committed config only**, version-aware defaults, `setting()` vs `advice()`, `ConfigEdit` auto-fix when the write is unambiguous.

### 4.1 Do **not** turn into findings

Machine QoL (`storeDir` default, `enableGlobalCache: true`, Bun cache dir, `prefer-offline` in **user** config, `fund=false`). These are host policy. A committed custom `storeDir` / `cache` / `install.cache.dir` **is** a finding (`cache.path-committed`, info/moderate): it is usually a laptop path that breaks CI and other agents.

### 4.2 New settings codes (suggested)

| Code | Trigger | Severity | Fixable? | Closest existing code |
|---|---|---|---|---|
| `layout.shamefully-hoist` | pnpm `shamefullyHoist: true` or `publicHoistPattern` contains `*` | high | yes → `false` / drop `*` | — |
| `layout.hoisted` | pnpm `nodeLinker: hoisted`; Yarn `nodeLinker: node-modules` is **not** this (that is the agent-friendly one); Bun explicit `linker = "hoisted"` on a workspace | moderate (`strict`: high) | no (needs human) | — |
| `layout.pnp` | Yarn `nodeLinker` missing or `pnp` (default); pnpm `nodeLinker: pnp` | high under standard if no `.pnp.cjs` committed; info if PnP files exist | yes → `nodeLinker: node-modules` **only if** the team wants that (mailclad fixtures already assume it) | tests already write `nodeLinker: node-modules` |
| `layout.pnp-loose` | Yarn `pnpMode: loose`; pnpm `nodePackageMapType: loose` | high | yes → `strict` / `standard` | — |
| `overrides.present` | root `overrides` / `resolutions` / pnpm yaml `overrides` | info (standard), moderate (strict) | no | same shape as “pin it explicitly” advice |
| `overrides.exotic` | override value is `file:`, `link:`, `github:`, `git+`, `-` | high | no | `source.non-registry` |
| `overrides.legacy-location` | `package.json#pnpm.overrides` / `#pnpm.patchedDependencies` on pnpm ≥ 11 | high | yes → move to yaml | `scripts.legacy-config` |
| `patches.present` | `patchedDependencies` non-empty | info | no | — |
| `patches.missing` | listed patch file absent | high | no | — |
| `peers.legacy` | npm `legacy-peer-deps=true` | high | yes → `false` | — |
| `peers.rules-broad` | pnpm `peerDependencyRules` `ignoreMissing`/`allowAny` is `*` or very broad | high | yes → drop `*` | `min-age.exclude-all` |
| `catalog.unpinned` | `catalog:` specs without `catalogMode: strict` | info | optional fix | `pm.unpinned` |
| `pm.mismatch` | `packageManager` name ≠ discovered primary | high | no | `pm.unpinned` |
| `cache.path-committed` | project config sets `storeDir` / `cache` / `cacheFolder` / `install.cache.dir` to an absolute home path | moderate | yes → unset | — |
| `lockfile.branched` | pnpm `gitBranchLockfile: true` | high | yes → `false` | `lockfile.missing` |
| `lockfile.extra-print` | Bun `[install.lockfile] print = "yarn"` | high | yes → unset | `lockfile.leftover` |

### 4.3 Policy / preset knobs

Add optional `ResolvedSettings` flags (same layering as `ignoreScripts` / `minReleaseAgeDays`):

- `forbidShamefullyHoist` (standard/strict: true)
- `forbidPnp` (standard: true — agents assume `node_modules`; strict: true)
- `warnOverrides` (standard: advice; strict: moderate)
- `forbidLegacyPeerDeps` (standard/strict: true)

Do **not** auto-fix `nodeLinker` from `pnp` → `node-modules` without a preset flag; that rewrite changes the install layout for the whole team. mailclad’s apply path already requires a clean git tree; this one still needs a human.

### 4.4 Discovery / leftover copy

Bun’s official migrator leaves `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` in place. Keep `lockfile.leftover` at `high`. Tighten the message: leftover is not “you forgot”; it is “two resolvers will fight, and the next agent will run the wrong one.” Corepack’s unshimmed `npm` makes that fight easy.

`JS_PRIMARY_ORDER` (`pnpm`, `yarn`, `bun`, `npm`) already matches “stricter linker wins.” Do not reorder.

### 4.5 What not to copy from QoL blogs

- Committing `shamefully-hoist=true` “for Jest” — use `publicHoistPattern: ['*eslint*', '*jest*']` or fix the tool.
- Committing `legacy-peer-deps=true` — that is npm’s own anti-recommendation.
- Committing `enableGlobalVirtualStore: true` — CI disables it anyway; ESM `NODE_PATH` breaks.
- Using `overrides` as the first response to `pnpm audit` / `npm audit` — prefer upgrading; treat overrides as a dated exception list (same as `minimumReleaseAgeExclude`).

---

## 5. Sources

### pnpm

- [Settings (`pnpm-workspace.yaml`)](https://pnpm.io/settings) — v11: only auth/registry from `.npmrc`; machine-state keys ignored in project yaml since 11.22; `storeDir`/`cacheDir` still allowed; env expansion in registry URLs ignored.
- [Store & lockfile settings](https://pnpm.io/settings/store) — `storeDir` defaults and per-disk rule; store trust domain; `verifyStoreIntegrity`; `frozenStore`; `lockfile`; `preferFrozenLockfile`; `gitBranchLockfile`.
- [Node-modules & hoisting settings](https://pnpm.io/settings/node-modules) — `nodeLinker`, `packageImportMethod`, `virtualStoreDir`, `enableGlobalVirtualStore`, `hoist` / `hoistPattern` / `publicHoistPattern` / `shamefullyHoist`, `nodePackageMapType`.
- [Dependency resolution settings](https://pnpm.io/settings/dependency-resolution) — `overrides`, `packageExtensions`, catalogs in overrides.
- [Catalogs](https://pnpm.io/catalogs) — `catalog:` protocol, `catalogMode`.
- [Workspaces](https://pnpm.io/workspaces) — `workspace:` protocol; `linkWorkspacePackages` default `false`; `saveWorkspaceProtocol` default `rolling`; `sharedWorkspaceLockfile` default `true`.
- [package.json](https://pnpm.io/package_json) — v11 no longer reads the `pnpm` field; `devEngines.packageManager`; `dependenciesMeta.*.injected`.
- [Auth / `.npmrc`](https://pnpm.io/npmrc) — project vs user auth files; GHSA-3qhv-2rgh-x77r env-exfil guard.

### npm

- [Config (v11)](https://docs.npmjs.com/cli/v11/using-npm/config) and [Config (v12)](https://docs.npmjs.com/cli/v12/using-npm/config) — `cache`, `prefer-offline`, `offline`, `install-strategy` (`hoisted`/`nested`/`shallow`/`linked`), `fund`, `audit`, `legacy-peer-deps`, `package-lock`, `ignore-scripts`.
- [npm-install](https://docs.npmjs.com/cli/v11/commands/npm-install/) — `linked` recommended to catch phantom deps.
- [package.json `overrides`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#overrides) — root-only; `$` references; `npm:`/`github:`/`file:` replacements.
- [npm RFC 0036 (overrides)](https://github.com/npm/rfcs/blob/main/implemented/0036-overrides.md) — explicitly not Yarn `resolutions`.
- [`.npmrc` files](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc) — project / user / global / builtin; project file not published.

### Yarn

- [`.yarnrc.yml` settings](https://yarnpkg.com/configuration/yarnrc) — `cacheFolder`, `enableGlobalCache`, `nodeLinker` (`pnp`/`pnpm`/`node-modules`), `nmHoistingLimits`, `nmMode`, `pnpMode`, `enableScripts`, `checksumBehavior`, `enableHardenedMode`.
- [Manifest `resolutions` / `packageManager` / `dependenciesMeta.built`](https://yarnpkg.com/configuration/manifest)
- [Workspaces / `workspace:` protocol](https://yarnpkg.com/features/workspaces)
- [Cache strategies](https://yarnpkg.com/features/caching) — `enableGlobalCache: false` for Zero-Installs.
- [Yarn Classic `.yarnrc`](https://classic.yarnpkg.com/en/docs/yarnrc/) — `yarn-offline-mirror`.
- [Yarn Classic `yarn cache`](https://classic.yarnpkg.com/en/docs/cli/cache/) — `cache-folder`, `YARN_CACHE_FOLDER`, `.npmrc` `cache=`.
- [Classic → Berry: `nohoist` → `nmHoistingLimits`; `.npmrc` ignored](https://yarnpkg.com/migration/guide)

### Bun

- [bunfig.toml](https://bun.com/docs/runtime/bunfig) — global vs local; `[install.cache]`; `linker`; `globalStore`; `hoist` / `publicHoistPattern`; `[install.lockfile] print`.
- [Global cache](https://bun.com/docs/pm/global-cache) — `~/.bun/install/cache`, `BUN_INSTALL_CACHE_DIR`, hardlink/`clonefile`.
- [Isolated installs](https://bun.com/docs/pm/isolated-installs) — `configVersion` default linker table; `hoist = false`.
- [`.npmrc` support](https://bun.com/docs/pm/npmrc) — `cache`, `install-strategy`, `node-linker`, hoist patterns.
- [Overrides and resolutions](https://bun.com/docs/pm/overrides)
- [Lockfile](https://bun.com/docs/pm/lockfile) — automatic migration; original lockfile preserved; `--yarn`.
- [bun install](https://bun.com/docs/pm/cli/install) — pnpm config migration into root `package.json`.
- [bun patch](https://bun.com/docs/pm/cli/patch) — `patchedDependencies`.

### Corepack / Node

- [Corepack README (nodejs/corepack)](https://github.com/nodejs/corepack/blob/main/README.md) — `packageManager` `name@version[+hash]`; `devEngines.packageManager`; npm shims off by default; `COREPACK_ENABLE_STRICT`; `COREPACK_HOME`.

### Deno / pip / Poetry / Cargo / uv

- [Deno installation / cache location](https://docs.deno.com/runtime/getting_started/installation/)
- [Deno env vars (`DENO_DIR`)](https://docs.deno.com/runtime/reference/env_variables/)
- [Deno dependency management / `nodeModulesDir`](https://docs.deno.com/runtime/fundamentals/node/)
- [pip caching](https://pip.pypa.io/en/stable/topics/caching/)
- [Poetry configuration (`cache-dir`)](https://python-poetry.org/docs/configuration/)
- [Cargo environment variables (`CARGO_HOME`, `CARGO_TARGET_DIR`)](https://doc.rust-lang.org/cargo/reference/environment-variables.html)
- [Cargo configuration (`[patch]`)](https://doc.rust-lang.org/cargo/reference/config.html)
- [uv caching](https://docs.astral.sh/uv/concepts/cache/)

### This repo

- [`docs/research-2026-08-package-manager-settings.md`](./research-2026-08-package-manager-settings.md) — cooldown / scripts / provenance (do not duplicate).
- [`src/settings.ts`](../src/settings.ts) — finding constructors and per-manager auditors.
- [`src/discover.ts`](../src/discover.ts) — `JS_PRIMARY_ORDER`, leftover lockfiles.
- [`src/domain.ts`](../src/domain.ts) — `Finding.code`, `ManagerRole`.
- [`README.md`](../README.md) — four baseline questions (scripts, age gate, lockfile, registry).
