import { defineConfig } from "oxlint";
import core from "ultracite/oxlint/core";

const ignorePatterns = [
  ...(core.ignorePatterns ?? []),
  "**/.claude",
  "tests/fixtures/**",
  "site/**",
];

export default defineConfig({
  env: {
    ...core.env,
    node: true,
  },
  extends: [core],
  ignorePatterns,
  jsPlugins: ["eslint-plugin-crap"],
  rules: {
    "crap/crap": ["error", { lcovPath: "coverage/lcov.info", maxCrap: 8 }],
  },
});
