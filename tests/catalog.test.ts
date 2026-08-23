import { expect, test } from "bun:test";

import { AGENTIC_CATALOG } from "../src/agentic-catalog";
import {
  COMMANDS,
  GLOBAL_FLAGS,
  commandByName,
  commandSynopsis,
} from "../src/cli-catalog";
import { MANAGER_DOCS } from "../src/manager-docs";
import { ALL_MANAGER_NAMES } from "../src/managers/profile";
import { PRESET_DEFAULTS } from "../src/preset-defaults";

test("command catalog lists audit, init, and help", () => {
  expect(COMMANDS.map((command) => command.name)).toEqual([
    "audit",
    "init",
    "help",
  ]);
  expect(
    commandByName("audit")?.flags.some((flag) => flag.names.includes("--apply"))
  ).toBe(true);
  const audit = COMMANDS.find((command) => command.name === "audit");
  expect(audit === undefined ? undefined : commandSynopsis(audit)).toBe(
    "audit [path]"
  );
  expect(GLOBAL_FLAGS.some((flag) => flag.names.includes("--version"))).toBe(
    true
  );
});

test("manager docs cover every registered manager", () => {
  expect(MANAGER_DOCS.map((manager) => manager.name)).toEqual([
    ...ALL_MANAGER_NAMES,
  ]);
});

test("preset and agentic catalogs stay populated", () => {
  expect(Object.keys(PRESET_DEFAULTS)).toEqual([
    "relaxed",
    "standard",
    "strict",
  ]);
  expect(AGENTIC_CATALOG.length).toBeGreaterThan(0);
});
