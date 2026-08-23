import { APP_NAME, CONFIG_FILE_NAME } from "@cli/app-name";
import {
  USER_CONFIG_PATH_DOCS,
  USER_CONFIG_PATH_FALLBACK,
} from "@cli/config-paths";

export const SITE_NAME = APP_NAME;
export const SITE_URL = "https://mailclad.dev";
export const GITHUB_URL = "https://github.com/jackmcpickle/mailclad";
export const NPM_URL = "https://www.npmjs.com/package/mailclad";
export const RELEASES_URL = `${GITHUB_URL}/releases`;
export const CONFIG_NAME = CONFIG_FILE_NAME;
export { USER_CONFIG_PATH_DOCS, USER_CONFIG_PATH_FALLBACK };

export const SITE_DESCRIPTION =
  "Audit package-manager security settings and advisories across monorepos and folders of projects.";
