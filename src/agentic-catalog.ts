export interface AgenticCheck {
  readonly code: string;
  readonly title: string;
  readonly description: string;
  readonly caveat: string;
}

export const AGENTIC_CATALOG: readonly AgenticCheck[] = [
  {
    caveat:
      "Shared caches belong in user config. A committed home path breaks CI and other agents. Apply only unsets an in-repo path — it never writes ~/…/store.",
    code: "cache.path-committed",
    description:
      "A project file pins storeDir, cache, cacheFolder, or install.cache.dir.",
    title: "Committed store or cache path",
  },
  {
    caveat:
      "Leave enableGlobalCache true unless the team vendors .yarn/cache (Zero-Installs).",
    code: "agentic.cache-disabled",
    description: "yarn enableGlobalCache is false.",
    title: "Global cache disabled",
  },
  {
    caveat:
      "The next agent will copy this instead of upgrading. Presence is the warning; apply never deletes a pin.",
    code: "overrides.present",
    description:
      "overrides, resolutions, or pnpm workspace overrides force a version the manifest does not show.",
    title: "Version override precedent",
  },
  {
    caveat:
      "pnpm 11 ignores package.json#pnpm. Apply can move the map to pnpm-workspace.yaml only.",
    code: "overrides.legacy-location",
    description: "package.json#pnpm.overrides on pnpm 11 or later.",
    title: "Legacy pnpm overrides location",
  },
  {
    caveat:
      "Makes require() succeed for undeclared deps. The next isolated install breaks.",
    code: "layout.shamefully-hoist",
    description:
      "pnpm shamefullyHoist is true, or publicHoistPattern contains *.",
    title: "Shameful hoist",
  },
  {
    caveat:
      "Most agents assume node_modules and run node, not yarn node. Apply to node-modules is opt-in because it changes the team layout.",
    code: "layout.pnp",
    description: "yarn or pnpm nodeLinker is pnp (yarn's default).",
    title: "Plug'n'Play linker",
  },
];
