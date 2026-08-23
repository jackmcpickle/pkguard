"use strict";

const WORKSPACE_VERSION = /\[workspace\.package\][^\[]*?^version = "([^"]+)"/m;

exports.readVersion = (contents) => {
  const match = contents.match(WORKSPACE_VERSION);
  if (match === null) {
    throw new Error("Cargo.toml has no [workspace.package] version");
  }
  return match[1];
};

exports.writeVersion = (contents, version) =>
  contents.replace(WORKSPACE_VERSION, (full) =>
    full.replace(/version = "[^"]+"/, `version = "${version}"`)
  );
