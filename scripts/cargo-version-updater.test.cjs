"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const lock = require("./cargo-lock-updater.cjs");
const toml = require("./cargo-version-updater.cjs");

const CARGO_TOML = `[workspace]
resolver = "2"

[workspace.package]
version = "1.0.0"
edition = "2021"

[workspace.dependencies]
pkguard-core = { path = "crates/pkguard-core", version = "1.0.0" }
serde = { version = "1", features = ["derive"] }
`;

const CARGO_LOCK = `[[package]]
name = "pkguard"
version = "1.0.0"
dependencies = [
 "pkguard-core",
]

[[package]]
name = "pkguard-core"
version = "1.0.0"

[[package]]
name = "serde"
version = "1.0.0"
`;

test("bumps the workspace package and pkguard-core versions, nothing else", () => {
  assert.equal(toml.readVersion(CARGO_TOML), "1.0.0");
  const next = toml.writeVersion(CARGO_TOML, "1.1.0");
  assert.equal(toml.readVersion(next), "1.1.0");
  // crates.io resolves the sibling crate by version, so it has to move too.
  assert.match(next, /pkguard-core = \{ path = "crates\/pkguard-core", version = "1\.1\.0" \}/);
  assert.match(next, /serde = \{ version = "1"/);
});

test("refuses to bump when the pkguard-core dependency is missing", () => {
  const without = CARGO_TOML.replace(/^pkguard-core = .*\n/m, "");
  assert.throws(
    () => toml.writeVersion(without, "1.1.0"),
    /no pkguard-core workspace dependency/
  );
});

test("reads and writes workspace crate versions in Cargo.lock", () => {
  assert.equal(lock.readVersion(CARGO_LOCK), "1.0.0");
  const next = lock.writeVersion(CARGO_LOCK, "1.1.0");
  assert.equal(lock.readVersion(next), "1.1.0");
  assert.match(next, /name = "pkguard-core"\nversion = "1.1.0"/);
  assert.match(next, /name = "serde"\nversion = "1.0.0"/);
});
