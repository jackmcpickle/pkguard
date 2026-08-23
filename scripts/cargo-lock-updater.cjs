"use strict";

const PKGUARD_VERSION = /^name = "pkguard"\nversion = "([^"]+)"/m;
const WORKSPACE_PACKAGES = /^(name = "pkguard(?:-core)?"\nversion = ")[^"]+"/gm;

exports.readVersion = (contents) => {
  const match = contents.match(PKGUARD_VERSION);
  if (match === null) {
    throw new Error("Cargo.lock has no pkguard package version");
  }
  return match[1];
};

exports.writeVersion = (contents, version) =>
  contents.replace(WORKSPACE_PACKAGES, `$1${version}"`);
