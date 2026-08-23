import { APP_NAME, CONFIG_FILE_NAME } from "@cli/app-name";
import {
  USER_CONFIG_PATH_DOCS,
  USER_CONFIG_PATH_FALLBACK,
} from "@cli/config-paths";

export const SITE_NAME = APP_NAME;
export const SITE_URL = "https://pkguard.dev";
export const SITE_HOST = "pkguard.dev";
export const GITHUB_URL = "https://github.com/jackmcpickle/pkguard";
export const NPM_URL = `https://www.npmjs.com/package/${APP_NAME}`;
export const RELEASES_URL = `${GITHUB_URL}/releases`;
export const CONFIG_NAME = CONFIG_FILE_NAME;
export { USER_CONFIG_PATH_DOCS, USER_CONFIG_PATH_FALLBACK };

export const SITE_DESCRIPTION =
  "Audit package-manager security settings and advisories across monorepos and folders of projects.";

export const docsSourcePath = (current: string): string => {
  if (current === "/docs") {
    return "site/src/pages/docs/index.astro";
  }
  if (current === "/docs/commands") {
    return "site/src/pages/docs/commands/index.astro";
  }
  if (current.startsWith("/docs/commands/")) {
    return "site/src/pages/docs/commands/[name].astro";
  }
  return `site/src/pages${current}.astro`;
};

export const docsEditUrl = (current: string): string =>
  `${GITHUB_URL}/edit/main/${docsSourcePath(current)}`;
