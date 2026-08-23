import assert from "node:assert/strict";
import { test } from "node:test";

import { extractChangelogNotes } from "./release-notes.mjs";

const CHANGELOG = `# Changelog

## [0.1.3](https://github.com/jackmcpickle/pkguard/compare/v0.1.2...v0.1.3) (2026-08-21)

### Bug Fixes

* emit one dirty-root warning per shared git root ([581c5da](https://example.com/581c5da))

## [0.1.2](https://github.com/jackmcpickle/pkguard/compare/v0.1.1...v0.1.2) (2026-08-21)
## 0.1.1 (2026-08-21)

### Features

* add Composer/PHP as a first-class package manager
`;

test("extracts a linked keep-a-changelog section and stops at the next heading", () => {
  assert.equal(
    extractChangelogNotes(CHANGELOG, "0.1.3"),
    `### Bug Fixes

* emit one dirty-root warning per shared git root ([581c5da](https://example.com/581c5da))`
  );
});

test("extracts an unlinked heading used by the first release", () => {
  assert.equal(
    extractChangelogNotes(CHANGELOG, "0.1.1"),
    `### Features

* add Composer/PHP as a first-class package manager`
  );
});

test("returns null for an empty section so callers can generate notes", () => {
  assert.equal(extractChangelogNotes(CHANGELOG, "0.1.2"), null);
});

test("returns null when the version is missing and does not prefix-match", () => {
  assert.equal(extractChangelogNotes(CHANGELOG, "0.1.30"), null);
  assert.equal(extractChangelogNotes(CHANGELOG, "0.1.10"), null);
});
