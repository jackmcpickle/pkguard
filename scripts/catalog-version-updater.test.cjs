"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const catalog = require("./catalog-version-updater.cjs");

const CATALOG = `{
  "appName": "pkguard",
  "version": "1.0.0",
  "configFileName": ".pkguard.toml",
  "presets": [
    {
      "name": "npm",
      "version": "9.0.0"
    }
  ]
}
`;

test("reads and writes the top-level catalog version only", () => {
  assert.equal(catalog.readVersion(CATALOG), "1.0.0");
  const next = catalog.writeVersion(CATALOG, "1.1.0");
  assert.equal(catalog.readVersion(next), "1.1.0");
  assert.match(next, /"name": "npm",\n {6}"version": "9\.0\.0"/);
});

test("preserves formatting outside the version line", () => {
  const next = catalog.writeVersion(CATALOG, "2.0.0");
  assert.equal(
    next,
    CATALOG.replace('"version": "1.0.0"', '"version": "2.0.0"')
  );
});

test("throws when there is no top-level version", () => {
  assert.throws(
    () => catalog.readVersion('{\n  "appName": "pkguard"\n}\n'),
    /no top-level version/
  );
});
