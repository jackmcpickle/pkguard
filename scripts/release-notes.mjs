import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const escapeRegExp = (value) => value.replaceAll(/[.*+?^${}()|[\]\\]/gu, "\\$&");

export const extractChangelogNotes = (changelog, version) => {
  const header = new RegExp(
    `^## (?:\\[${escapeRegExp(version)}\\]|${escapeRegExp(version)})(?:[\\s(\\[]|$)`,
    "u"
  );
  const body = [];
  let collecting = false;

  for (const line of changelog.split(/\r?\n/u)) {
    if (collecting) {
      if (line.startsWith("## ")) {
        break;
      }
      body.push(line);
      continue;
    }
    if (header.test(line)) {
      collecting = true;
    }
  }

  if (!collecting) {
    return null;
  }
  const notes = body.join("\n").trim();
  return notes === "" ? null : notes;
};

const invokedDirectly =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (invokedDirectly) {
  const version = process.argv[2]?.replace(/^v/u, "");
  if (version === undefined || version === "") {
    process.stderr.write("usage: node scripts/release-notes.mjs <version> [CHANGELOG.md]\n");
    process.exit(1);
  }
  const changelogPath = process.argv[3] ?? new URL("../CHANGELOG.md", import.meta.url);
  const notes = extractChangelogNotes(readFileSync(changelogPath, "utf8"), version);
  if (notes === null) {
    process.exit(2);
  }
  process.stdout.write(`${notes}\n`);
}
