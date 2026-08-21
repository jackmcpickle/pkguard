import { expect, test } from "bun:test";

import { run } from "../src/cli";

const AUDIT_FLAGS = [
  "--allow-majors",
  "--apply",
  "--apply-advisories",
  "--commit",
  "--concurrency",
  "--force",
  "--help",
  "--interactive",
  "--json",
  "--no-cache",
  "--preset",
  "--refresh",
  "--report",
  "--sarif",
  "-h",
  "-i",
] as const;

const capture = async (
  argv: string[],
  extra?: { color?: boolean; env?: Record<string, string | undefined> }
) => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  let ran = 0;
  const result = await run(argv, {
    color: extra?.color,
    cwd: process.cwd(),
    env: extra?.env ?? {},
    run: () => {
      ran += 1;
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
    },
    stderr: { write: (s: string) => stderr.push(s) },
    stdout: { write: (s: string) => stdout.push(s) },
  });
  return {
    exitCode: result.exitCode,
    ran,
    stderr: stderr.join(""),
    stdout: stdout.join(""),
  };
};

const expectRootCatalog = (text: string): void => {
  expect(text).toContain("Usage: mailclad");
  expect(text).toContain("audit [path]");
  expect(text).toContain("help [command]");
};

test("mailclad with no args prints the command catalog on stderr and exits 2", async () => {
  const result = await capture([]);
  expect(result.exitCode).toBe(2);
  expect(result.stdout).toBe("");
  expectRootCatalog(result.stderr);
  expect(result.stderr).not.toContain("\u001B[");
});

test("help, --help, and -h print the command catalog on stdout and exit 0", async () => {
  const results = await Promise.all(
    [["help"], ["--help"], ["-h"]].map((argv) => capture(argv))
  );
  for (const result of results) {
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expectRootCatalog(result.stdout);
    expect(result.ran).toBe(0);
  }
});

test("help audit and audit --help describe audit arguments and flags without running an audit", async () => {
  const results = await Promise.all(
    [
      ["help", "audit"],
      ["audit", "--help"],
      ["audit", "-h"],
    ].map((argv) => capture(argv))
  );
  for (const result of results) {
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.ran).toBe(0);
    expect(result.stdout).toContain("Usage: mailclad audit");
    expect(result.stdout).toContain("path");
    for (const flag of AUDIT_FLAGS) {
      expect(result.stdout).toContain(flag);
    }
  }
});

test("audit --json --help still prints help and does not run an audit", async () => {
  const result = await capture(["audit", "--json", "--help"]);
  expect(result.exitCode).toBe(0);
  expect(result.ran).toBe(0);
  expect(result.stdout).toContain("Usage: mailclad audit");
  expect(result.stdout).toContain("--json");
});

test("help help documents the help command", async () => {
  const result = await capture(["help", "help"]);
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toContain("Usage: mailclad help");
  expect(result.stdout).toContain("help [command]");
});

test("help --help describes the help command", async () => {
  const result = await capture(["help", "--help"]);
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toContain("Usage: mailclad help");
  expect(result.stdout).toContain("[command]");
});

test("unknown command and help topic print the catalog on stderr and exit 2", async () => {
  const results = await Promise.all(
    [["nope"], ["help", "nope"]].map((argv) => capture(argv))
  );
  for (const result of results) {
    expect(result.exitCode).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Unknown command: nope");
    expectRootCatalog(result.stderr);
  }
});

test("help uses ANSI colors when color is enabled", async () => {
  const result = await capture(["help"], { color: true });
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toContain("\u001B[");
  expect(result.stdout).toContain("Usage: mailclad");
  expect(result.stdout).toContain("audit");
});

test("help is plain when streams are injected without color", async () => {
  const result = await capture(["help"]);
  expect(result.stdout).not.toContain("\u001B[");
});

test("NO_COLOR produces plain help when color is not injected", async () => {
  const result = await capture(["help"], { env: { NO_COLOR: "1" } });
  expect(result.exitCode).toBe(0);
  expect(result.stdout).not.toContain("\u001B[");
  expectRootCatalog(result.stdout);
});
