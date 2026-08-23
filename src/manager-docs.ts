import type { PackageManager } from "./domain";
import { ALL_MANAGER_NAMES, profileFor } from "./managers/profile";

export interface ManagerDoc {
  name: PackageManager;
  kind: "config" | "python-legacy";
  binary: string | null;
  auditArgv: readonly string[] | null;
  lockfileNames: readonly string[];
  configNames: readonly string[];
  writeConfigName: string | null;
}

export const MANAGER_DOCS: readonly ManagerDoc[] = ALL_MANAGER_NAMES.map(
  (name) => {
    const profile = profileFor(name);
    return {
      auditArgv: profile.auditArgv,
      binary: profile.binary,
      configNames: profile.configNames,
      kind: profile.kind,
      lockfileNames: profile.lockfileNames,
      name: profile.name,
      writeConfigName: profile.writeConfigName,
    };
  }
);
