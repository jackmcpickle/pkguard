"use strict";

const WORKSPACE_VERSION = /\[workspace\.package\][^\[]*?^version = "([^"]+)"/m;

// crates.io ignores `path` and resolves the sibling crate by `version`, so the
// internal dependency has to move with the workspace version on every bump.
const INTERNAL_DEP_VERSION =
  /^(pkguard-core = \{ path = "crates\/pkguard-core", version = )"[^"]+"/m;

exports.readVersion = (contents) => {
  const match = contents.match(WORKSPACE_VERSION);
  if (match === null) {
    throw new Error("Cargo.toml has no [workspace.package] version");
  }
  return match[1];
};

exports.writeVersion = (contents, version) => {
  const bumped = contents.replace(WORKSPACE_VERSION, (full) =>
    full.replace(/version = "[^"]+"/, `version = "${version}"`)
  );
  if (!INTERNAL_DEP_VERSION.test(bumped)) {
    throw new Error("Cargo.toml has no pkguard-core workspace dependency");
  }
  return bumped.replace(INTERNAL_DEP_VERSION, `$1"${version}"`);
};
