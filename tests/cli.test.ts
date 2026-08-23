import { expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import nodePath from "node:path";

import { parse } from "smol-toml";

import { applySettings } from "../src/apply-settings";
import { auditPath } from "../src/audit";
import { createLineReader, resolveColor, run } from "../src/cli";
import type { DetectedManager, Finding, Project } from "../src/domain";
import type { Host } from "../src/host";
import { createMemoryCache } from "../src/memory-cache";
import { loadPolicy } from "../src/policy";
import type { FakeHostOverrides } from "./helpers/memory-fs";
import { fakeHost, memoryFs } from "./helpers/memory-fs";

const CRITICAL_NPM_AUDIT = JSON.stringify({
  advisories: {
    "1": {
      findings: [{ version: "1.0.0" }],
      github_advisory_id: "GHSA-crit",
      module_name: "left-pad",
      severity: "critical",
      title: "critical left-pad advisory",
    },
  },
});

const CLEAN_NPM_FILES: Record<string, string> = {
  "/p/.npmrc":
    "ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n",
  "/p/package-lock.json": `{"lockfileVersion":3}`,
  "/p/package.json": `{"name":"x","packageManager":"npm@10.9.0"}`,
};

const POETRY_FILES: Record<string, string> = {
  "/py/poetry.lock": "# poetry lock\n",
  "/py/pyproject.toml": `[tool.poetry]\nname = "x"\nversion = "0.1.0"\n`,
};

const emptyAuditRun = () => () => ({
  code: 0,
  stderr: "",
  stdout: `{"advisories":{}}`,
});

const emptyHome = (): Record<string, string | undefined> => ({
  HOME: nodePath.join(import.meta.dir, "fixtures/empty-home"),
});

const capturingHost = (
  stdout: string[] = [],
  stderr: string[] = [],
  extras: FakeHostOverrides = {}
): Host =>
  fakeHost({
    createCache: () => createMemoryCache(() => 1000, 86_400_000),
    cwd: () => import.meta.dir,
    env: emptyHome(),
    run: emptyAuditRun(),
    stderr: (text) => {
      stderr.push(text);
    },
    stdout: (text) => {
      stdout.push(text);
    },
    which: () => "/usr/bin/npm",
    ...extras,
  });

test("pkguard with no args prints usage and exits 2", async () => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run([], capturingHost(stdout, stderr));
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).toContain("Usage: pkguard");
});

test("audit of a fixture repo with open npm scripts exits 1 and lists the finding", async () => {
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root], capturingHost(stdout, stderr));
  expect(result.exitCode).toBe(1);
  expect(stdout.join("")).toContain("scripts.unrestricted");
});

test("CLI --preset wins over repo .pkguard.toml preset", async () => {
  const root = nodePath.join(import.meta.dir, "fixtures/audit/flag-wins");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(
    ["audit", root, "--preset", "relaxed"],
    capturingHost(stdout, stderr)
  );
  expect(stdout.join("")).not.toContain("scripts.unrestricted");
  expect(result.exitCode).toBe(0);
});

test("--refresh and --no-cache bypass the lockfile digest cache", async () => {
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const cache = createMemoryCache(() => 1000, 86_400_000);
  let auditCalls = 0;
  const hostFor = () =>
    capturingHost([], [], {
      createCache: () => cache,
      run: () => {
        auditCalls += 1;
        return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
      },
    });

  await run(["audit", root], hostFor());
  expect(auditCalls).toBe(1);
  await run(["audit", root], hostFor());
  expect(auditCalls).toBe(1);

  await run(["audit", root, "--refresh"], hostFor());
  expect(auditCalls).toBe(2);
  await run(["audit", root, "--no-cache"], hostFor());
  expect(auditCalls).toBe(3);

  // --refresh re-primed the cache; --no-cache must not have written it.
  await run(["audit", root], hostFor());
  expect(auditCalls).toBe(3);
});

test("auditPath critical npm audit JSON is an advisory and exits 1", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "npm-critical",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: CRITICAL_NPM_AUDIT }),
      which: () => "/usr/bin/npm",
    },
    layers: {},
    mode: { kind: "audit" },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(result.exitCode).toBe(1);
  expect(findings.some((finding) => finding.kind === "advisory")).toBe(true);
});

test("auditPath missing binary skips advisories and exits 0 when settings are clean", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  let ran = 0;
  const result = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "npm-missing",
      now: () => 1000,
      run: () => {
        ran += 1;
        return { code: 1, stderr: "", stdout: CRITICAL_NPM_AUDIT };
      },
      which: () => null,
    },
    layers: {},
    mode: { kind: "audit" },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(ran).toBe(0);
  expect(result.exitCode).toBe(0);
  expect(findings.some((finding) => finding.code === "pm.missing-binary")).toBe(
    true
  );
  expect(findings.some((finding) => finding.kind === "advisory")).toBe(false);
});

test("auditPath runOsv high advisory exits 1", async () => {
  const fs = memoryFs(POETRY_FILES, ["/py/.git"]);
  const osvFinding: Finding = {
    code: "GHSA-osv",
    fixable: false,
    kind: "advisory",
    manager: "poetry",
    message: "osv high advisory",
    path: "/py/poetry.lock",
    severity: "high",
  };
  const result = await auditPath("/py", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "poetry-osv",
      now: () => 1000,
      run: emptyAuditRun(),
      runOsv: () => [osvFinding],
      which: () => null,
    },
    layers: {},
    mode: { kind: "audit" },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(result.exitCode).toBe(1);
  expect(
    findings.some(
      (finding) => finding.kind === "advisory" && finding.severity === "high"
    )
  ).toBe(true);
});

test("--json prints the full result object with advisory findings", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(
    ["audit", root, "--json"],
    capturingHost(stdout, stderr, {
      run: () => ({ code: 1, stderr: "", stdout: CRITICAL_NPM_AUDIT }),
    })
  );
  const parsed = JSON.parse(stdout.join("")) as {
    exitCode: number;
    projects: { findings: { kind: string }[] }[];
  };
  expect(result.exitCode).toBe(1);
  expect(parsed.exitCode).toBe(1);
  expect(parsed.projects.length).toBeGreaterThan(0);
  expect(
    parsed.projects.some((row) =>
      row.findings.some((finding) => finding.kind === "advisory")
    )
  ).toBe(true);
});

test("--json --sarif --report emit the same finalized finding codes", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const home = { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") };
  const cache = createMemoryCache(() => 1000, 86_400_000);
  const written: Record<string, string> = {};
  const jsonOut: string[] = [];
  const sarifOut: string[] = [];
  const mdOut: string[] = [];

  const writeHost = (out: string[]): Host =>
    capturingHost([], [], {
      createCache: () => cache,
      env: home,
      files: {
        writeFile: (path, body) => {
          written[path] = body;
        },
      },
      stdout: (text) => {
        out.push(text);
      },
    });

  await run(["audit", root, "--json"], writeHost(jsonOut));
  await run(["audit", root, "--sarif"], writeHost(sarifOut));
  await run(["audit", root, "--report", "/out/report.md"], writeHost(mdOut));

  expect(jsonOut.join("")).toContain("scripts.unrestricted");
  expect(sarifOut.join("")).toContain("scripts.unrestricted");
  expect(written["/out/report.md"]).toContain("scripts.unrestricted");
  expect(Object.keys(written).filter((path) => path.endsWith(".md"))).toEqual([
    "/out/report.md",
  ]);
  expect(mdOut.join("")).not.toMatch(/^# /u);
});

test("interactive fake prompt can choose settings only", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const written: Record<string, string> = {};
  const prompts: { settingsCount: number; advisoryCount: number }[] = [];
  const installCalls: string[][] = [];
  const result = await run(
    ["audit", root, "-i"],
    capturingHost([], [], {
      files: {
        writeFile: (path, body) => {
          written[path] = body;
        },
      },
      gitStatus: () => "clean",
      prompt: ({ project, settingsCount, advisoryCount }) => {
        expect(project.root).toContain("alpha");
        prompts.push({ advisoryCount, settingsCount });
        return "settings" as const;
      },
      run: (argv) => {
        if (!argv.includes("audit")) {
          installCalls.push(argv);
        }
        return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
      },
    })
  );
  expect(prompts).toHaveLength(1);
  expect(prompts[0]?.settingsCount).toBeGreaterThan(0);
  expect(
    Object.values(written).some((body) => body.includes("ignore-scripts=true"))
  ).toBe(true);
  expect(installCalls).toEqual([]);
  expect(result.exitCode).not.toBe(2);
});

test("interactive -i uses default stdin prompt when none is injected", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const written: Record<string, string> = {};
  const stdout: string[] = [];
  const result = await run(
    ["audit", root, "-i"],
    capturingHost(stdout, [], {
      files: {
        writeFile: (path, body) => {
          written[path] = body;
        },
      },
      gitStatus: () => "clean",
      readStdinChunk: () => Promise.resolve("settings\n"),
    })
  );
  expect(stdout.join("")).toMatch(/settings|advisories|both|skip/iu);
  expect(
    Object.values(written).some((body) => body.includes("ignore-scripts=true"))
  ).toBe(true);
  expect(result.exitCode).not.toBe(2);
});

test("auditPath advisory runner dying yields exit code 2 (incomplete)", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "npm-incomplete",
      now: () => 1000,
      run: () => ({
        code: 2,
        stderr: "audit engine crashed",
        stdout: "",
      }),
      which: () => "/usr/bin/npm",
    },
    layers: {},
    mode: { kind: "audit" },
  });
  expect(result.exitCode).toBe(2);
});

test("auditPath below-gate advisory does not fail the standard preset gate", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const LOW_NPM_AUDIT = JSON.stringify({
    advisories: {
      "1": {
        findings: [{ version: "1.0.0" }],
        github_advisory_id: "GHSA-low",
        module_name: "left-pad",
        severity: "low",
        title: "left-pad low advisory",
      },
    },
  });
  const result = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "npm-below-gate",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: LOW_NPM_AUDIT }),
      which: () => "/usr/bin/npm",
    },
    layers: {},
    mode: { kind: "audit" },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(
    findings.some(
      (finding) => finding.kind === "advisory" && finding.severity === "low"
    )
  ).toBe(true);
  expect(result.exitCode).toBe(0);
});

test("audit of a directory with zero discovered projects exits 2", async () => {
  const root = nodePath.join(import.meta.dir, "fixtures/empty-root");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root], capturingHost(stdout, stderr));
  expect(result.exitCode).toBe(2);
});

test("applySettings with --commit calls gitCommit exactly once with the repo root", () => {
  const project: Project = {
    gitRoot: "/repo",
    managers: [
      {
        configPath: "/repo/.npmrc",
        lockfilePath: "/repo/package-lock.json",
        manifestPath: "/repo/package.json",
        name: "npm",
        role: "primary",
      } satisfies DetectedManager,
    ],
    root: "/repo",
  };
  const finding: Finding = {
    code: "scripts.unrestricted",
    fix: {
      edits: [{ key: "ignore-scripts", op: "set", value: true }],
      file: "/repo/.npmrc",
      format: "npmrc",
    },
    fixable: true,
    kind: "settings",
    manager: "npm",
    message: "scripts are not restricted",
    path: "/repo/.npmrc",
    severity: "high",
  };
  const written: Record<string, string> = {};
  const commitCalls: { root: string; message: string; files: string[] }[] = [];
  const result = applySettings(project, [finding], loadPolicy({}), {
    commit: true,
    force: false,
    gitCommit: (root, message, files) => {
      commitCalls.push({ files, message, root });
      return true;
    },
    gitStatus: () => "clean",
    readFile: (path) => (path === "/repo/.npmrc" ? "" : null),
    writeFile: (path, body) => {
      written[path] = body;
    },
  });
  expect(result.committed).toBe(true);
  expect(commitCalls).toHaveLength(1);
  expect(commitCalls[0]?.root).toBe("/repo");
  expect(Object.keys(written)).toEqual(["/repo/.npmrc"]);
});

test("stdin line reader keeps leftover lines after the first newline", async () => {
  const chunks: (string | null)[] = ["settings\nskip\n"];
  const readLine = createLineReader(() => chunks.shift() ?? null);
  expect(await readLine()).toBe("settings");
  expect(await readLine()).toBe("skip");
  expect(chunks).toEqual([]);
});

test("--apply on a dirty tree warns after the folder and shows the planned table", async () => {
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(
    ["audit", root, "--apply"],
    capturingHost(stdout, stderr, {
      files: {
        writeFile: () => {
          throw new Error("must not write on a dirty tree");
        },
      },
      gitStatus: () => "dirty",
    })
  );
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).not.toContain("apply skipped");
  const out = stdout.join("");
  const folderAt = out.indexOf(root);
  const tableAt = out.indexOf("Change to");
  const skippedAt = out.indexOf("skipped (dirty git tree)");
  const warnAt = out.indexOf("apply skipped");
  expect(out).toContain("ignore-scripts");
  expect(out).toContain("Setting");
  expect(out).toContain("Current");
  expect(out).toContain("Status");
  expect(folderAt).toBeGreaterThan(-1);
  expect(tableAt).toBeGreaterThan(folderAt);
  expect(skippedAt).toBeGreaterThan(tableAt);
  expect(warnAt).toBeGreaterThan(skippedAt);
  expect(out).toContain("--force");
});

test("--fix on a dirty tree matches --apply and does not write", async () => {
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const stdout: string[] = [];
  const result = await run(
    ["audit", root, "--fix"],
    capturingHost(stdout, [], {
      files: {
        writeFile: () => {
          throw new Error("must not write on a dirty tree");
        },
      },
      gitStatus: () => "dirty",
    })
  );
  const out = stdout.join("");
  expect(result.exitCode).toBe(2);
  expect(out).toContain("Change to");
  expect(out).toContain("skipped (dirty git tree)");
  expect(out).toContain("apply skipped");
});

const INFO_ONLY_NPM: Record<string, string> = {
  "/p/.npmrc":
    "ignore-scripts=true\naudit=true\naudit-level=high\nmin-release-age=7\n",
  "/p/package-lock.json": `{"lockfileVersion":3}`,
  "/p/package.json": `{"name":"x"}`,
};

const CLEAN_UV_FILES: Record<string, string> = {
  "/uv/pyproject.toml": `[tool.uv]\nexclude-newer = 30\n`,
  "/uv/uv.lock": `version = 1\n`,
};

const advisoryJson = (severity: string): string =>
  JSON.stringify({
    advisories: {
      "1": {
        findings: [{ version: "1.0.0" }],
        github_advisory_id: `GHSA-${severity}`,
        module_name: "left-pad",
        severity,
        title: `${severity} left-pad advisory`,
      },
    },
  });

test("info-only settings findings do not fail the standard gate", async () => {
  const fs = memoryFs(INFO_ONLY_NPM, ["/p/.git"]);
  const result = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "npm-info-only",
      now: () => 1000,
      run: emptyAuditRun(),
      which: () => "/usr/bin/npm",
    },
    layers: {},
    mode: { kind: "audit" },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(
    findings.some(
      (f) => f.code === "registry.unpinned" && f.severity === "info"
    )
  ).toBe(true);
  expect(
    findings.some((f) => f.code === "pm.unpinned" && f.severity === "info")
  ).toBe(true);
  expect(result.exitCode).toBe(0);
});

test("standard lists a moderate advisory but does not fail; strict does", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const moderate = advisoryJson("moderate");
  const standard = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "npm-moderate-std",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: moderate }),
      which: () => "/usr/bin/npm",
    },
    layers: {},
    mode: { kind: "audit" },
  });
  expect(
    standard.projects
      .flatMap((row) => row.findings)
      .some((f) => f.kind === "advisory" && f.severity === "moderate")
  ).toBe(true);
  expect(standard.exitCode).toBe(0);

  const strict = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "npm-moderate-strict",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: moderate }),
      which: () => "/usr/bin/npm",
    },
    layers: { flags: { preset: "strict" } },
    mode: { kind: "audit" },
  });
  expect(strict.exitCode).toBe(1);
});

test("relaxed fails only critical advisories; a high advisory is listed and exits 0", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "npm-relaxed-high",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: advisoryJson("high") }),
      which: () => "/usr/bin/npm",
    },
    layers: { flags: { preset: "relaxed" } },
    mode: { kind: "audit" },
  });
  expect(
    result.projects
      .flatMap((row) => row.findings)
      .some((f) => f.kind === "advisory" && f.severity === "high")
  ).toBe(true);
  expect(result.exitCode).toBe(0);
});

test("uv deprecation fails even under the relaxed preset", async () => {
  const fs = memoryFs(CLEAN_UV_FILES, ["/uv/.git"]);
  const result = await auditPath("/uv", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "uv-deprecated",
      now: () => 1000,
      run: () => ({
        code: 0,
        stderr: "",
        stdout: JSON.stringify([
          { name: "oldpkg", status: "deprecated", version: "1.0.0" },
        ]),
      }),
      which: (binary) => (binary === "uv" ? "/usr/bin/uv" : null),
    },
    layers: { flags: { preset: "relaxed" } },
    mode: { kind: "audit" },
  });
  expect(
    result.projects
      .flatMap((row) => row.findings)
      .some((f) => f.kind === "deprecated")
  ).toBe(true);
  expect(result.exitCode).toBe(1);
});

test("interactive skip writes nothing", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const result = await run(
    ["audit", root, "-i"],
    capturingHost([], [], {
      files: {
        writeFile: () => {
          throw new Error("skip must not write");
        },
      },
      gitStatus: () => "clean",
      prompt: () => "skip" as const,
    })
  );
  expect(result.exitCode).toBe(1);
});

test("interactive poetry does not offer migrate-to-uv and still uses OSV", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/poetry-app/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(import.meta.dir, "fixtures/discover/poetry-app");
  const stdout: string[] = [];
  const calls: string[][] = [];
  const written: string[] = [];
  let osvLock: string | undefined;
  const result = await run(
    ["audit", root, "-i"],
    capturingHost(stdout, [], {
      files: {
        writeFile: (path) => {
          written.push(path);
        },
      },
      gitStatus: () => "clean",
      readStdinChunk: () => Promise.resolve("skip\n"),
      run: (argv) => {
        calls.push(argv);
        return { code: 0, stderr: "", stdout: "{}" };
      },
      runOsv: (lockOrRequirements) => {
        osvLock = lockOrRequirements;
        return [];
      },
      which: () => "/usr/bin/uv",
    })
  );
  const out = stdout.join("");
  expect(out).toMatch(/settings|advisories|both|skip/iu);
  expect(out).not.toMatch(/migrate/iu);
  expect(osvLock).toContain("poetry.lock");
  expect(calls.every((argv) => argv[0] !== "uv")).toBe(true);
  expect(
    written.some((path) => path.endsWith("uv.toml") || path.endsWith("uv.lock"))
  ).toBe(false);
  expect(result.exitCode).toBe(1);
});

test("--apply on a poetry project never runs uv migrate commands", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/poetry-app/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(import.meta.dir, "fixtures/discover/poetry-app");
  const calls: string[][] = [];
  const written: string[] = [];
  await run(
    ["audit", root, "--apply"],
    capturingHost([], [], {
      files: {
        writeFile: (path) => {
          written.push(path);
        },
      },
      gitStatus: () => "clean",
      run: (argv) => {
        calls.push(argv);
        return { code: 0, stderr: "", stdout: "{}" };
      },
      which: () => "/usr/bin/uv",
    })
  );
  expect(calls.every((argv) => argv[0] !== "uv")).toBe(true);
  expect(
    written.some((path) => path.endsWith("uv.toml") || path.endsWith("uv.lock"))
  ).toBe(false);
});

test("XDG_CONFIG_HOME wins over ~/.config/pkguard when CLI loads user config", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const home = mkdtempSync(nodePath.join(tmpdir(), "pkguard-home-"));
  const xdg = mkdtempSync(nodePath.join(tmpdir(), "pkguard-xdg-"));
  mkdirSync(nodePath.join(home, ".config", "pkguard"), { recursive: true });
  mkdirSync(nodePath.join(xdg, "pkguard"), { recursive: true });
  writeFileSync(
    nodePath.join(home, ".config", "pkguard", "config.toml"),
    `preset = "standard"\n`
  );
  writeFileSync(
    nodePath.join(xdg, "pkguard", "config.toml"),
    `preset = "relaxed"\n`
  );
  const stdout: string[] = [];
  const result = await run(
    ["audit", root],
    capturingHost(stdout, [], {
      env: { HOME: home, XDG_CONFIG_HOME: xdg },
    })
  );
  expect(stdout.join("")).not.toContain("scripts.unrestricted");
  expect(result.exitCode).toBe(0);
  rmSync(home, { force: true, recursive: true });
  rmSync(xdg, { force: true, recursive: true });
});

test("omitting --report does not write a markdown file", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const written: string[] = [];
  await run(
    ["audit", root],
    capturingHost([], [], {
      files: {
        writeFile: (path) => {
          written.push(path);
        },
      },
    })
  );
  expect(written.filter((path) => path.endsWith(".md"))).toEqual([]);
});

test("--report creates missing parent directories and writes markdown", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const outDir = mkdtempSync(nodePath.join(tmpdir(), "pkguard-report-"));
  const reportPath = nodePath.join(outDir, "nested", "deep", "report.md");
  const result = await run(
    ["audit", root, "--report", reportPath],
    capturingHost()
  );
  expect(existsSync(reportPath)).toBe(true);
  expect(readFileSync(reportPath, "utf-8")).toContain("scripts.unrestricted");
  expect(result.exitCode).toBe(1);
  rmSync(outDir, { force: true, recursive: true });
});

test("--concurrency 1 runs advisory audits serially; default and invalid values may overlap", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/beta/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(import.meta.dir, "fixtures/discover/many-repos");

  const maxFor = async (extra: string[]) => {
    let inFlight = 0;
    let max = 0;
    await run(
      ["audit", root, ...extra],
      capturingHost([], [], {
        run: async () => {
          inFlight += 1;
          max = Math.max(max, inFlight);
          await Bun.sleep(25);
          inFlight -= 1;
          return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
        },
      })
    );
    return max;
  };

  expect(await maxFor(["--concurrency", "1"])).toBe(1);
  expect(await maxFor([])).toBeGreaterThan(1);
  expect(await maxFor(["--concurrency", "0"])).toBeGreaterThan(1);
  expect(await maxFor(["--concurrency", "nope"])).toBeGreaterThan(1);
});

const AGENTIC_NPM_FILES: Record<string, string> = {
  "/repo/.npmrc":
    "ignore-scripts=true\nallow-scripts-pin=true\naudit=true\naudit-level=high\nmin-release-age=1\nregistry=https://registry.npmjs.org/\ncache=/Users/me/.npm\n",
  "/repo/package-lock.json": `{"lockfileVersion":3}`,
  "/repo/package.json": `{"name":"x","packageManager":"npm@11.0.0"}`,
};

test("--apply does not unset a committed cache path", async () => {
  const files = { ...AGENTIC_NPM_FILES };
  await run(
    ["audit", "/repo", "--apply"],
    capturingHost([], [], {
      extraDirs: ["/repo/.git"],
      fsMap: files,
      gitStatus: () => "clean",
      which: () => "/usr/bin/npm",
    })
  );
  expect(files["/repo/.npmrc"]).toContain("cache=/Users/me/.npm");
});

test("--apply-agentic unsets a committed cache path", async () => {
  const files = { ...AGENTIC_NPM_FILES };
  await run(
    ["audit", "/repo", "--apply-agentic"],
    capturingHost([], [], {
      extraDirs: ["/repo/.git"],
      fsMap: files,
      gitStatus: () => "clean",
      which: () => "/usr/bin/npm",
    })
  );
  expect(files["/repo/.npmrc"]).not.toContain("cache=");
});

test("--apply-agentic does not write ordinary settings fixes", async () => {
  const files: Record<string, string> = {
    "/repo/.npmrc":
      "cache=/Users/me/.npm\nregistry=https://registry.npmjs.org/\n",
    "/repo/package-lock.json": `{"lockfileVersion":3}`,
    "/repo/package.json": `{"name":"x","packageManager":"npm@11.0.0"}`,
  };
  await run(
    ["audit", "/repo", "--apply-agentic"],
    capturingHost([], [], {
      extraDirs: ["/repo/.git"],
      fsMap: files,
      gitStatus: () => "clean",
      which: () => "/usr/bin/npm",
    })
  );
  expect(files["/repo/.npmrc"]).not.toContain("ignore-scripts");
  expect(files["/repo/.npmrc"]).not.toContain("min-release-age");
  expect(files["/repo/.npmrc"]).not.toContain("cache=");
});

test("--apply on a clean tree shows applied rows after the folder", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const stdout: string[] = [];
  const result = await run(
    ["audit", root, "--apply"],
    capturingHost(stdout, [], {
      files: {
        writeFile: () => {},
      },
      gitStatus: () => "clean",
    })
  );
  const out = stdout.join("");
  const folderAt = out.indexOf(root);
  const tableAt = out.indexOf("Change to");
  const appliedAt = out.indexOf("applied");
  expect(result.exitCode).not.toBe(2);
  expect(out).toContain("ignore-scripts");
  expect(out).toContain("true");
  expect(folderAt).toBeGreaterThan(-1);
  expect(tableAt).toBeGreaterThan(folderAt);
  expect(appliedAt).toBeGreaterThan(tableAt);
  expect(out).not.toContain("apply skipped");
  expect(out).not.toContain("skipped (dirty git tree)");
});

test("--apply --force --commit through run() writes on a dirty tree and commits", async () => {
  mkdirSync(
    nodePath.join(import.meta.dir, "fixtures/discover/many-repos/alpha/.git"),
    {
      recursive: true,
    }
  );
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const written: Record<string, string> = {};
  const commits: { root: string; files: string[] }[] = [];
  const result = await run(
    ["audit", root, "--apply", "--force", "--commit"],
    capturingHost([], [], {
      files: {
        writeFile: (path, body) => {
          written[path] = body;
        },
      },
      gitCommit: (gitRoot, _message, files) => {
        commits.push({ files, root: gitRoot });
        return true;
      },
      gitStatus: () => "dirty",
    })
  );
  expect(
    Object.values(written).some((body) => body.includes("ignore-scripts=true"))
  ).toBe(true);
  expect(commits).toHaveLength(1);
  expect(commits[0]?.root).toBe(root);
  expect(result.exitCode).not.toBe(2);
});

test("two primaries with one missing binary still audit the other", async () => {
  const files: Record<string, string> = {
    ...CLEAN_NPM_FILES,
    "/p/pyproject.toml": `[tool.uv]\nexclude-newer = 30\n`,
    "/p/uv.lock": `version = 1\n`,
  };
  const fs = memoryFs(files, ["/p/.git"]);
  const calls: string[][] = [];
  const result = await auditPath("/p", {
    concurrency: 4,
    deps: {
      ...fs,
      cache: createMemoryCache(() => 1000, 86_400_000),
      digest: () => "two-primary",
      now: () => 1000,
      run: (argv) => {
        calls.push(argv);
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify([
            { name: "oldpkg", status: "deprecated", version: "1.0.0" },
          ]),
        };
      },
      which: (binary) => (binary === "uv" ? "/usr/bin/uv" : null),
    },
    layers: {},
    mode: { kind: "audit" },
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(
    findings.some((f) => f.code === "pm.missing-binary" && f.manager === "npm")
  ).toBe(true);
  expect(findings.some((f) => f.kind === "deprecated")).toBe(true);
  expect(calls).toEqual([
    ["uv", "audit", "--output-format", "json", "--frozen"],
  ]);
});

test("stdout uses ANSI colors when color is enabled and none by default", async () => {
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const colored: string[] = [];
  await run(["audit", root], capturingHost(colored, [], { isTTY: true }));
  expect(colored.join("")).toContain("\u001B[");
  expect(colored.join("")).toContain("scripts.unrestricted");

  const plain: string[] = [];
  await run(["audit", root], capturingHost(plain));
  expect(plain.join("")).not.toContain("\u001B[");
});

test("resolveColor honors the host's isTTY", () => {
  expect(resolveColor(fakeHost({ env: {}, isTTY: true }))).toBe(true);
  expect(resolveColor(fakeHost({ env: {}, isTTY: false }))).toBe(false);
  expect(resolveColor(fakeHost({ env: { NO_COLOR: "1" }, isTTY: true }))).toBe(
    false
  );
});

const SEARCH_ORDER =
  "Looks for a user/tool config, then .pkguard.toml in the scan directory and each project. Closer wins; flags win over files.";

const expectConfigLine = (
  text: string,
  label: string,
  filePath: string,
  status: "found" | "missing"
): void => {
  const line = text
    .split("\n")
    .find((row) => row.includes(label) && row.includes(filePath));
  expect(line).toBeDefined();
  expect(line).toContain(status);
};

test("audit human stdout lists user, scan, and repo config paths as found or missing", async () => {
  const root = nodePath.join(import.meta.dir, "fixtures/audit/flag-wins");
  const home = nodePath.join(import.meta.dir, "fixtures/empty-home");
  const stdout: string[] = [];
  const result = await run(
    ["audit", root],
    capturingHost(stdout, [], { env: { HOME: home } })
  );
  const out = stdout.join("");
  expect(result.exitCode).not.toBe(2);
  expect(out).toContain("Configuration:");
  expect(out).toContain(SEARCH_ORDER);
  expectConfigLine(
    out,
    "user",
    nodePath.join(home, ".config", "pkguard", "config.toml"),
    "missing"
  );
  expectConfigLine(out, "scan", nodePath.join(root, ".pkguard.toml"), "found");
  expectConfigLine(out, "repo", nodePath.join(root, ".pkguard.toml"), "found");
});

test("--json keeps JSON on stdout and prints Configuration on stderr", async () => {
  const root = nodePath.join(import.meta.dir, "fixtures/audit/flag-wins");
  const home = nodePath.join(import.meta.dir, "fixtures/empty-home");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(
    ["audit", root, "--json"],
    capturingHost(stdout, stderr, { env: { HOME: home } })
  );
  const parsed = JSON.parse(stdout.join("")) as { exitCode: number };
  expect(typeof parsed.exitCode).toBe("number");
  expect(result.exitCode).not.toBe(2);
  expect(stdout.join("")).not.toContain("Configuration:");
  expect(stderr.join("")).toContain("Configuration:");
  expectConfigLine(
    stderr.join(""),
    "user",
    nodePath.join(home, ".config", "pkguard", "config.toml"),
    "missing"
  );
  expectConfigLine(
    stderr.join(""),
    "scan",
    nodePath.join(root, ".pkguard.toml"),
    "found"
  );
});

const expectStarterToml = (body: string): void => {
  const parsed = parse(body) as { preset?: unknown };
  expect(parsed.preset).toBe("standard");
  expect(body).toContain("# [pnpm]");
  expect(body).toContain("# enabledManagers");
};

test("init writes user config under XDG_CONFIG_HOME", async () => {
  const home = mkdtempSync(nodePath.join(tmpdir(), "pkguard-init-home-"));
  const xdg = mkdtempSync(nodePath.join(tmpdir(), "pkguard-init-xdg-"));
  const stdout: string[] = [];
  const target = nodePath.join(xdg, "pkguard", "config.toml");
  const result = await run(
    ["init"],
    capturingHost(stdout, [], {
      cwd: () => home,
      env: { HOME: home, XDG_CONFIG_HOME: xdg },
    })
  );
  expect(result.exitCode).toBe(0);
  expect(existsSync(target)).toBe(true);
  expect(stdout.join("")).toContain(target);
  expectStarterToml(readFileSync(target, "utf-8"));
  rmSync(home, { force: true, recursive: true });
  rmSync(xdg, { force: true, recursive: true });
});

test("init writes user config under HOME when XDG_CONFIG_HOME is unset", async () => {
  const home = mkdtempSync(nodePath.join(tmpdir(), "pkguard-init-home-"));
  const stdout: string[] = [];
  const target = nodePath.join(home, ".config", "pkguard", "config.toml");
  const result = await run(
    ["init"],
    capturingHost(stdout, [], {
      cwd: () => home,
      env: { HOME: home },
    })
  );
  expect(result.exitCode).toBe(0);
  expect(existsSync(target)).toBe(true);
  expect(stdout.join("")).toContain(target);
  expectStarterToml(readFileSync(target, "utf-8"));
  rmSync(home, { force: true, recursive: true });
});

test("init --local writes .pkguard.toml in cwd", async () => {
  const cwd = mkdtempSync(nodePath.join(tmpdir(), "pkguard-init-local-"));
  const stdout: string[] = [];
  const target = nodePath.join(cwd, ".pkguard.toml");
  const result = await run(
    ["init", "--local"],
    capturingHost(stdout, [], {
      cwd: () => cwd,
      env: emptyHome(),
    })
  );
  expect(result.exitCode).toBe(0);
  expect(existsSync(target)).toBe(true);
  expect(stdout.join("")).toContain(target);
  expectStarterToml(readFileSync(target, "utf-8"));
  rmSync(cwd, { force: true, recursive: true });
});

test("init refuses to overwrite an existing file without --force", async () => {
  const xdg = mkdtempSync(nodePath.join(tmpdir(), "pkguard-init-refuse-"));
  mkdirSync(nodePath.join(xdg, "pkguard"), { recursive: true });
  const target = nodePath.join(xdg, "pkguard", "config.toml");
  writeFileSync(target, `preset = "relaxed"\n`);
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(
    ["init"],
    capturingHost(stdout, stderr, {
      cwd: () => xdg,
      env: { HOME: xdg, XDG_CONFIG_HOME: xdg },
    })
  );
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).toContain(target);
  expect(readFileSync(target, "utf-8")).toBe(`preset = "relaxed"\n`);
  rmSync(xdg, { force: true, recursive: true });
});

test("init --force overwrites an existing file", async () => {
  const xdg = mkdtempSync(nodePath.join(tmpdir(), "pkguard-init-force-"));
  mkdirSync(nodePath.join(xdg, "pkguard"), { recursive: true });
  const target = nodePath.join(xdg, "pkguard", "config.toml");
  writeFileSync(target, `preset = "relaxed"\n`);
  const stdout: string[] = [];
  const result = await run(
    ["init", "--force"],
    capturingHost(stdout, [], {
      cwd: () => xdg,
      env: { HOME: xdg, XDG_CONFIG_HOME: xdg },
    })
  );
  expect(result.exitCode).toBe(0);
  expect(stdout.join("")).toContain(target);
  expectStarterToml(readFileSync(target, "utf-8"));
  rmSync(xdg, { force: true, recursive: true });
});

test("init refuses an existing unreadable file without --force", async () => {
  const target = "/xdg/pkguard/config.toml";
  const stderr: string[] = [];
  const result = await run(
    ["init"],
    capturingHost([], stderr, {
      cwd: () => "/proj",
      env: { HOME: "/home", XDG_CONFIG_HOME: "/xdg" },
      extraDirs: ["/proj"],
      files: {
        exists: (filePath) => filePath === target,
        readFile: () => null,
        writeFile: () => {
          throw new Error("must not overwrite an existing unreadable file");
        },
      },
      fsMap: {},
    })
  );
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).toContain(target);
});

test("init rejects an unknown flag and does not write", async () => {
  const xdg = mkdtempSync(nodePath.join(tmpdir(), "pkguard-init-unknown-"));
  const stdout: string[] = [];
  const stderr: string[] = [];
  const target = nodePath.join(xdg, "pkguard", "config.toml");
  const result = await run(
    ["init", "--focre"],
    capturingHost(stdout, stderr, {
      cwd: () => xdg,
      env: { HOME: xdg, XDG_CONFIG_HOME: xdg },
    })
  );
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).toContain("--focre");
  expect(existsSync(target)).toBe(false);
  rmSync(xdg, { force: true, recursive: true });
});

test("init --local --force overwrites cwd .pkguard.toml", async () => {
  const cwd = mkdtempSync(nodePath.join(tmpdir(), "pkguard-init-local-force-"));
  const target = nodePath.join(cwd, ".pkguard.toml");
  writeFileSync(target, `preset = "relaxed"\n`);
  const stdout: string[] = [];
  const result = await run(
    ["init", "--local", "--force"],
    capturingHost(stdout, [], {
      cwd: () => cwd,
      env: emptyHome(),
    })
  );
  expect(result.exitCode).toBe(0);
  expectStarterToml(readFileSync(target, "utf-8"));
  rmSync(cwd, { force: true, recursive: true });
});
