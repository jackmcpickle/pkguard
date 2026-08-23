import { expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import pkg from "../package.json" with { type: "json" };

const ROOT = path.join(import.meta.dir, "..");
const FIXTURE = path.join(import.meta.dir, "fixtures/discover/many-repos");
const BINARY = path.join(ROOT, "dist/mailclad");

const compileBinary = (): void => {
  const build = Bun.spawnSync(["bun", "run", "build:binary"], {
    cwd: ROOT,
    stderr: "pipe",
    stdout: "pipe",
  });
  expect(build.exitCode).toBe(0);
};

test(
  "compiled mailclad binary audits the many-repos fixture",
  () => {
    mkdirSync(path.join(FIXTURE, "alpha/.git"), { recursive: true });
    mkdirSync(path.join(FIXTURE, "beta/.git"), { recursive: true });

    compileBinary();

    const bin = mkdtempSync(path.join(tmpdir(), "mailclad-smoke-bin-"));
    writeFileSync(
      path.join(bin, "npm"),
      `#!/bin/sh\necho '{"advisories":{}}'\n`
    );
    writeFileSync(
      path.join(bin, "pnpm"),
      `#!/bin/sh\necho '{"advisories":{}}'\n`
    );
    chmodSync(path.join(bin, "npm"), 0o755);
    chmodSync(path.join(bin, "pnpm"), 0o755);

    const proc = Bun.spawnSync([BINARY, "audit", FIXTURE, "--json"], {
      cwd: ROOT,
      env: {
        ...process.env,
        HOME: path.join(import.meta.dir, "fixtures/empty-home"),
        PATH: `${bin}:${process.env.PATH ?? ""}`,
      },
      stderr: "pipe",
      stdout: "pipe",
    });
    rmSync(bin, { force: true, recursive: true });

    const stdout = new TextDecoder().decode(proc.stdout);
    expect(stdout).toContain("scripts.unrestricted");
    expect(proc.exitCode).toBe(1);
  },
  { timeout: 120_000 }
);

test(
  "compiled mailclad binary --version prints the package.json version",
  () => {
    compileBinary();
    const proc = Bun.spawnSync([BINARY, "--version"], {
      cwd: ROOT,
      stderr: "pipe",
      stdout: "pipe",
    });
    expect(proc.exitCode).toBe(0);
    expect(new TextDecoder().decode(proc.stdout)).toBe(`${pkg.version}\n`);
  },
  { timeout: 120_000 }
);
