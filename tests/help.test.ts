import { expect, test } from "bun:test";

import pkg from "../package.json" with { type: "json" };
import { run } from "../src/cli";
import type { Host } from "../src/host";
import type { FakeHostOverrides } from "./helpers/memory-fs";
import { fakeHost } from "./helpers/memory-fs";

const AUDIT_FLAGS = [
  "--allow-majors",
  "--apply",
  "--apply-advisories",
  "--apply-agentic",
  "--commit",
  "--concurrency",
  "--fix",
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

const capture = async (argv: string[], extras: FakeHostOverrides = {}) => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  let ran = 0;
  const host: Host = fakeHost({
    cwd: () => "/p",
    env: extras.env ?? {},
    extraDirs: ["/p"],
    fsMap: {},
    isTTY: extras.isTTY ?? false,
    run: () => {
      ran += 1;
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
    },
    stderr: (text) => {
      stderr.push(text);
    },
    stdout: (text) => {
      stdout.push(text);
    },
    which: () => "/usr/bin/npm",
    ...extras,
  });
  const result = await run(argv, host);
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
  expect(text).toContain("init");
  expect(text).toContain("help [command]");
};

const SEARCH_ORDER =
  "Looks for a user/tool config, then .mailclad.toml in the scan directory and each project. Closer wins; flags win over files.";

const expectHelpConfig = (text: string): void => {
  expect(text).toContain("Configuration:");
  expect(text).toContain(SEARCH_ORDER);
  expect(text).toContain("/home/.config/mailclad/config.toml");
  expect(text).toContain("/p/.mailclad.toml");
  expect(text).toContain("missing");
};

const helpHome = { HOME: "/home" } as const;

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
    expect(result.stdout).toContain("--version");
    expect(result.ran).toBe(0);
  }
});

test("--version and -V print the package.json version on stdout and exit 0", async () => {
  const results = await Promise.all(
    [["--version"], ["-V"], ["audit", "--version"]].map((argv) => capture(argv))
  );
  for (const result of results) {
    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.ran).toBe(0);
    expect(result.stdout).toBe(`${pkg.version}\n`);
  }
});

test("audit help lists agentic checks with descriptions and caveats", async () => {
  const result = await capture(["audit", "--help"]);
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toContain("Agentic checks:");
  expect(result.stdout).toContain("overrides.present");
  expect(result.stdout).toContain("cache.path-committed");
  expect(result.stdout).toContain("layout.pnp");
  expect(result.stdout).toContain("apply never deletes a pin");
  expect(result.stdout).toContain("never writes");
  expect(result.stdout).toContain("agentic = true");
  expect(result.stdout).toContain("applyAgentic = false");
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

test("help uses ANSI colors when stdout is a TTY", async () => {
  const result = await capture(["help"], { isTTY: true });
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toContain("\u001B[");
  expect(result.stdout).toContain("Usage: mailclad");
  expect(result.stdout).toContain("audit");
});

test("help is plain when streams are not a TTY", async () => {
  const result = await capture(["help"]);
  expect(result.stdout).not.toContain("\u001B[");
});

test("NO_COLOR produces plain help even on a TTY", async () => {
  const result = await capture(["help"], {
    env: { NO_COLOR: "1" },
    isTTY: true,
  });
  expect(result.exitCode).toBe(0);
  expect(result.stdout).not.toContain("\u001B[");
  expectRootCatalog(result.stdout);
});

test("root help lists init and resolved config paths as missing", async () => {
  const results = await Promise.all(
    [["help"], ["--help"], ["-h"]].map((argv) =>
      capture(argv, { env: helpHome })
    )
  );
  for (const result of results) {
    expect(result.exitCode).toBe(0);
    expectRootCatalog(result.stdout);
    expectHelpConfig(result.stdout);
  }
});

test("audit help includes search order and resolved user and cwd paths", async () => {
  const results = await Promise.all(
    [
      ["help", "audit"],
      ["audit", "--help"],
      ["audit", "-h"],
    ].map((argv) => capture(argv, { env: helpHome }))
  );
  for (const result of results) {
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Usage: mailclad audit");
    expectHelpConfig(result.stdout);
  }
});

test("help init and init --help document --local and --force", async () => {
  const results = await Promise.all(
    [
      ["help", "init"],
      ["init", "--help"],
      ["init", "-h"],
    ].map((argv) => capture(argv))
  );
  for (const result of results) {
    expect(result.exitCode).toBe(0);
    expect(result.ran).toBe(0);
    expect(result.stdout).toContain("Usage: mailclad init");
    expect(result.stdout).toContain("--local");
    expect(result.stdout).toContain("--force");
    expect(result.stdout).toContain("-h");
    expect(result.stdout).toContain("--help");
  }
});
