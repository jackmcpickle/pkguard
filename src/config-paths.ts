import path from "node:path";

import { APP_NAME, CONFIG_FILE_NAME } from "./app-name";

const baseDir = (xdg: string | undefined, fallback: string): string =>
  xdg !== undefined && xdg !== "" ? xdg : fallback;

export const userConfigPath = (
  env: Record<string, string | undefined>
): string =>
  path.join(
    baseDir(env.XDG_CONFIG_HOME, path.join(env.HOME ?? "", ".config")),
    APP_NAME,
    "config.toml"
  );

export const userCachePath = (
  env: Record<string, string | undefined>
): string =>
  path.join(
    baseDir(env.XDG_CACHE_HOME, path.join(env.HOME ?? "", ".cache")),
    APP_NAME
  );

export const dirConfigPath = (dir: string): string =>
  path.join(dir, CONFIG_FILE_NAME);

/** Static docs form of userConfigPath: XDG wins, else ~/.config. */
export const USER_CONFIG_PATH_DOCS = `$XDG_CONFIG_HOME/${APP_NAME}/config.toml`;
export const USER_CONFIG_PATH_FALLBACK = `~/.config/${APP_NAME}/config.toml`;
