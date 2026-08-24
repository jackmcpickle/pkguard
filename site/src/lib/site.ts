import { APP_NAME, CONFIG_FILE_NAME } from "@/lib/catalog";

export const SITE_NAME = APP_NAME;
export const SITE_URL = "https://pkguard.dev";
export const SITE_HOST = new URL(SITE_URL).host;
export const GITHUB_URL = "https://github.com/jackmcpickle/pkguard";
export const RELEASES_URL = `${GITHUB_URL}/releases`;
export const HOMEBREW_TAP = "jackmcpickle/pkguard";
export const BREW_INSTALL = `brew install ${HOMEBREW_TAP}/${APP_NAME}`;
export const BREW_TAP_AND_INSTALL = `brew tap ${HOMEBREW_TAP}\nbrew trust ${HOMEBREW_TAP}\nbrew install ${APP_NAME}`;
export const CONFIG_NAME = CONFIG_FILE_NAME;

export const AUTHOR_NAME = "Jack McNicol";
export const AUTHOR_URL = "https://github.com/jackmcpickle";
export const ISSUES_URL = `${GITHUB_URL}/issues`;
export const DISCUSSIONS_URL = `${GITHUB_URL}/discussions`;
export const CHANGELOG_URL = `${GITHUB_URL}/blob/main/CHANGELOG.md`;
export const LICENSE_NAME = "MIT";
export const LICENSE_URL = `${GITHUB_URL}/blob/main/LICENSE`;
export const SITE_OG_IMAGE = `${SITE_URL}/images/hero-tree.jpg`;

/** Bumped whenever the site copy changes. Rendered as a <time> element. */
export const SITE_UPDATED = "2026-08-24";

export const SITE_DESCRIPTION =
  "Scan package-manager settings and advisories across a folder of repos.";

export const docsSourcePath = (current: string): string => {
  if (current === "/docs") {
    return "site/src/pages/docs/index.astro";
  }
  if (current.startsWith("/docs/commands/")) {
    return "site/src/pages/docs/commands/[name].astro";
  }
  return `site/src/pages${current}.astro`;
};

export const docsEditUrl = (current: string): string =>
  `${GITHUB_URL}/edit/main/${docsSourcePath(current)}`;
