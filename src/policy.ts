import { parse } from "smol-toml";

import type { PackageManager, Policy, PresetName } from "./domain";
import { ALL_MANAGER_NAMES, CONFIG_MANAGER_NAMES } from "./managers/profile";
import { PRESET_DEFAULTS } from "./preset-defaults";
import { isPlainObject } from "./std";

export { PRESET_DEFAULTS } from "./preset-defaults";

const CONFIG_MANAGERS = new Set<string>(CONFIG_MANAGER_NAMES);

const PACKAGE_MANAGERS = new Set<string>(ALL_MANAGER_NAMES);

const RESERVED_KEYS = new Set(["preset", "enabledManagers"]);

const isPresetName = (value: unknown): value is PresetName =>
  value === "relaxed" || value === "standard" || value === "strict";

const isConfigManager = (value: unknown): value is PackageManager =>
  typeof value === "string" && CONFIG_MANAGERS.has(value);

const isPackageManager = (value: unknown): value is PackageManager =>
  typeof value === "string" && PACKAGE_MANAGERS.has(value);

interface LayerAcc {
  preset?: PresetName;
  enabledManagers?: PackageManager[];
  overrides: Record<string, unknown>;
  perManager: Partial<Record<PackageManager, Record<string, unknown>>>;
}

interface PolicyState {
  preset: PresetName;
  enabledManagers: PackageManager[];
  overrides: Record<string, unknown>;
  tables: Partial<Record<PackageManager, Record<string, unknown>>>;
}

const applySpecialLayerKey = (
  key: string,
  value: unknown,
  acc: LayerAcc
): boolean => {
  if (key === "preset") {
    if (isPresetName(value)) {
      acc.preset = value;
    }
    return true;
  }
  if (key === "enabledManagers") {
    if (Array.isArray(value)) {
      acc.enabledManagers = value.filter(isPackageManager);
    }
    return true;
  }
  return false;
};

const applyLayerKey = (key: string, value: unknown, acc: LayerAcc): void => {
  if (applySpecialLayerKey(key, value, acc)) {
    return;
  }
  if (isConfigManager(key) && isPlainObject(value)) {
    acc.perManager[key] = { ...value };
    return;
  }
  if (!RESERVED_KEYS.has(key) && !isPackageManager(key)) {
    acc.overrides[key] = value;
  }
};

const parseLayer = (toml: string): LayerAcc => {
  const acc: LayerAcc = { overrides: {}, perManager: {} };
  try {
    const raw: unknown = parse(toml);
    if (!isPlainObject(raw)) {
      return acc;
    }
    for (const [key, value] of Object.entries(raw)) {
      applyLayerKey(key, value, acc);
    }
  } catch {
    return { overrides: {}, perManager: {} };
  }
  return acc;
};

const applyParsedLayer = (state: PolicyState, layer: LayerAcc): void => {
  const { preset, enabledManagers, overrides, perManager } = layer;
  if (preset !== undefined) {
    state.preset = preset;
  }
  if (enabledManagers !== undefined) {
    state.enabledManagers = enabledManagers;
  }
  Object.assign(state.overrides, overrides);
  for (const [name, table] of Object.entries(perManager) as [
    PackageManager,
    Record<string, unknown>,
  ][]) {
    state.tables[name] = { ...state.tables[name], ...table };
  }
};

const applyTomlLayer = (state: PolicyState, toml: string | undefined): void => {
  if (toml === undefined) {
    return;
  }
  applyParsedLayer(state, parseLayer(toml));
};

const applyFlagLayer = (
  state: PolicyState,
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> }
): Record<string, unknown> => {
  const { preset, overrides = {} } = flags ?? {};
  if (preset !== undefined) {
    state.preset = preset;
  }
  Object.assign(state.overrides, overrides);
  return overrides;
};

export const loadPolicy = (input: {
  userToml?: string;
  scanToml?: string;
  repoToml?: string;
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> };
}): Policy => {
  const state: PolicyState = {
    enabledManagers: [...CONFIG_MANAGER_NAMES],
    overrides: {},
    preset: "standard",
    tables: {},
  };
  applyTomlLayer(state, input.userToml);
  applyTomlLayer(state, input.scanToml);
  applyTomlLayer(state, input.repoToml);
  const flagOverrides = applyFlagLayer(state, input.flags);

  const perManager: Policy["perManager"] = {};
  for (const [name, table] of Object.entries(state.tables) as [
    PackageManager,
    Record<string, unknown>,
  ][]) {
    perManager[name] = { ...state.overrides, ...table, ...flagOverrides };
  }

  return {
    enabledManagers: state.enabledManagers,
    overrides: state.overrides,
    perManager,
    preset: state.preset,
  };
};

export interface PolicyLayers {
  userToml?: string;
  scanToml?: string;
  flags?: { preset?: PresetName; overrides?: Record<string, unknown> };
}

/** Full stack for one repo: user < scan < repo < flags. One parse, one merge. */
export const policyForRepo = (
  layers: PolicyLayers,
  repoToml?: string
): Policy => loadPolicy({ ...layers, repoToml });

export interface ResolvedSettings {
  agentic: boolean;
  applyAgentic: boolean;
  auditLevel: string;
  ignoreScripts: boolean;
  minReleaseAgeDays: number;
  registry: string | null;
  requireLockfile: boolean;
  requirePmPin: boolean;
}

const resolveRegistry = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
};

export const resolveSettings = (
  policy: Policy,
  manager: PackageManager
): ResolvedSettings => {
  const base = PRESET_DEFAULTS[policy.preset];
  const extra = { ...policy.overrides, ...policy.perManager[manager] };
  return {
    agentic: typeof extra.agentic === "boolean" ? extra.agentic : true,
    applyAgentic:
      typeof extra.applyAgentic === "boolean" ? extra.applyAgentic : false,
    auditLevel:
      typeof extra.auditLevel === "string" ? extra.auditLevel : base.auditLevel,
    ignoreScripts:
      typeof extra.ignoreScripts === "boolean"
        ? extra.ignoreScripts
        : base.ignoreScripts,
    minReleaseAgeDays:
      typeof extra.minReleaseAgeDays === "number"
        ? extra.minReleaseAgeDays
        : base.minReleaseAgeDays,
    registry: resolveRegistry(extra.registry),
    requireLockfile:
      typeof extra.requireLockfile === "boolean"
        ? extra.requireLockfile
        : base.requireLockfile,
    requirePmPin:
      typeof extra.requirePmPin === "boolean"
        ? extra.requirePmPin
        : base.requirePmPin,
  };
};
