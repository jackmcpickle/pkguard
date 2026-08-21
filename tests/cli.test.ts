import { afterAll, expect, test } from "bun:test";
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

import { applySettings } from "../src/apply-settings";
import { auditPath } from "../src/audit";
import { createFsCache } from "../src/cache";
import { createLineReader, run } from "../src/cli";
import type { DetectedManager, Finding, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { memoryFs } from "./helpers/memory-fs";

const cacheDir = mkdtempSync(nodePath.join(tmpdir(), "mailclad-task10-cache-"));
afterAll(() => {
  rmSync(cacheDir, { force: true, recursive: true });
});

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

test("mailclad with no args prints usage and exits 2", async () => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run([], {
    cwd: process.cwd(),
    env: {},
    stderr: { write: (s: string) => stderr.push(s) },
    stdout: { write: (s: string) => stdout.push(s) },
  });
  expect(result.exitCode).toBe(2);
  expect(stderr.join("")).toContain("Usage: mailclad");
  expect(stderr.join("")).toContain("audit [path]");
  expect(stderr.join("")).toContain("help [command]");
});

test("audit of a fixture repo with open npm scripts exits 1 and lists the finding", async () => {
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root], {
    cache: createFsCache(
      nodePath.join(cacheDir, "alpha"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    stderr: { write: (s: string) => stderr.push(s) },
    stdout: { write: (s: string) => stdout.push(s) },
    which: () => "/usr/bin/npm",
  });
  expect(result.exitCode).toBe(1);
  expect(stdout.join("")).toContain("scripts.unrestricted");
});

test("CLI --preset wins over repo .mailclad.toml preset", async () => {
  const root = nodePath.join(import.meta.dir, "fixtures/audit/flag-wins");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root, "--preset", "relaxed"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "flag-wins"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    stderr: { write: (s: string) => stderr.push(s) },
    stdout: { write: (s: string) => stdout.push(s) },
    which: () => "/usr/bin/npm",
  });
  expect(stdout.join("")).not.toContain("scripts.unrestricted");
  expect(result.exitCode).toBe(0);
});

test("--refresh and --no-cache bypass the lockfile digest cache", async () => {
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const cache = createFsCache(
    nodePath.join(cacheDir, "cache-flags"),
    () => 1000,
    86_400_000
  );
  let auditCalls = 0;
  const depsFor = () => ({
    cache,
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: () => {
      auditCalls += 1;
      return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
    },
    stderr: { write: () => {} },
    stdout: { write: () => {} },
    which: () => "/usr/bin/npm",
  });

  await run(["audit", root], depsFor());
  expect(auditCalls).toBe(1);
  await run(["audit", root], depsFor());
  expect(auditCalls).toBe(1);

  await run(["audit", root, "--refresh"], depsFor());
  expect(auditCalls).toBe(2);
  await run(["audit", root, "--no-cache"], depsFor());
  expect(auditCalls).toBe(3);

  // --refresh re-primed the cache; --no-cache must not have written it.
  await run(["audit", root], depsFor());
  expect(auditCalls).toBe(3);
});

test("auditPath critical npm audit JSON is an advisory and exits 1", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(cacheDir, () => 1000, 86_400_000),
      digest: () => "npm-critical",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: CRITICAL_NPM_AUDIT }),
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({}),
  });
  const findings = result.projects.flatMap((row) => row.findings);
  expect(result.exitCode).toBe(1);
  expect(findings.some((finding) => finding.kind === "advisory")).toBe(true);
});

test("auditPath missing binary skips advisories and exits 0 when settings are clean", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  let ran = 0;
  const result = await auditPath("/p", {
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "missing"),
        () => 1000,
        86_400_000
      ),
      digest: () => "npm-missing",
      now: () => 1000,
      run: () => {
        ran += 1;
        return { code: 1, stderr: "", stdout: CRITICAL_NPM_AUDIT };
      },
      which: () => null,
    },
    interactive: false,
    policy: loadPolicy({}),
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
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "osv"),
        () => 1000,
        86_400_000
      ),
      digest: () => "poetry-osv",
      now: () => 1000,
      run: emptyAuditRun(),
      runOsv: () => [osvFinding],
      which: () => null,
    },
    interactive: false,
    policy: loadPolicy({}),
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
  const result = await run(["audit", root, "--json"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "json"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: () => ({ code: 1, stderr: "", stdout: CRITICAL_NPM_AUDIT }),
    stderr: { write: (s: string) => stderr.push(s) },
    stdout: { write: (s: string) => stdout.push(s) },
    which: () => "/usr/bin/npm",
  });
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
  const cache = createFsCache(
    nodePath.join(cacheDir, "reports"),
    () => 1000,
    86_400_000
  );
  const written: Record<string, string> = {};
  const jsonOut: string[] = [];
  const sarifOut: string[] = [];
  const mdOut: string[] = [];

  await run(["audit", root, "--json"], {
    cache,
    cwd: import.meta.dir,
    env: home,
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: (s: string) => jsonOut.push(s) },
    which: () => "/usr/bin/npm",
    writeFile: (path, body) => {
      written[path] = body;
    },
  });
  await run(["audit", root, "--sarif"], {
    cache,
    cwd: import.meta.dir,
    env: home,
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: (s: string) => sarifOut.push(s) },
    which: () => "/usr/bin/npm",
    writeFile: (path, body) => {
      written[path] = body;
    },
  });
  await run(["audit", root, "--report", "/out/report.md"], {
    cache,
    cwd: import.meta.dir,
    env: home,
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: (s: string) => mdOut.push(s) },
    which: () => "/usr/bin/npm",
    writeFile: (path, body) => {
      written[path] = body;
    },
  });

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
  const result = await run(["audit", root, "-i"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "interactive"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
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
    stderr: { write: () => {} },
    stdout: { write: () => {} },
    which: () => "/usr/bin/npm",
    writeFile: (path, body) => {
      written[path] = body;
    },
  });
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
  const result = await run(["audit", root, "-i"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "default-prompt"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    gitStatus: () => "clean",
    readLine: () => "settings",
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: (s: string) => stdout.push(s) },
    which: () => "/usr/bin/npm",
    writeFile: (path, body) => {
      written[path] = body;
    },
  });
  expect(stdout.join("")).toMatch(/settings|advisories|both|skip/iu);
  expect(
    Object.values(written).some((body) => body.includes("ignore-scripts=true"))
  ).toBe(true);
  expect(result.exitCode).not.toBe(2);
});

test("auditPath advisory runner dying yields exit code 2 (incomplete)", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "incomplete"),
        () => 1000,
        86_400_000
      ),
      digest: () => "npm-incomplete",
      now: () => 1000,
      run: () => ({
        code: 2,
        stderr: "audit engine crashed",
        stdout: "",
      }),
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({}),
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
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "below-gate"),
        () => 1000,
        86_400_000
      ),
      digest: () => "npm-below-gate",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: LOW_NPM_AUDIT }),
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({}),
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
  const result = await run(["audit", root], {
    cache: createFsCache(
      nodePath.join(cacheDir, "empty-root"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    stderr: { write: (s: string) => stderr.push(s) },
    stdout: { write: (s: string) => stdout.push(s) },
    which: () => "/usr/bin/npm",
  });
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

test("--apply on a dirty tree warns on stderr and exits 2", async () => {
  const root = nodePath.join(
    import.meta.dir,
    "fixtures/discover/many-repos/alpha"
  );
  const stdout: string[] = [];
  const stderr: string[] = [];
  const result = await run(["audit", root, "--apply"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "dirty-warn"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    gitStatus: () => "dirty",
    run: emptyAuditRun(),
    stderr: { write: (s: string) => stderr.push(s) },
    stdout: { write: (s: string) => stdout.push(s) },
    which: () => "/usr/bin/npm",
    writeFile: () => {
      throw new Error("must not write on a dirty tree");
    },
  });
  expect(result.exitCode).toBe(2);
  const err = stderr.join("");
  expect(err).toContain("apply skipped");
  expect(err).toContain("dirty");
  expect(err).toContain("--force");
  expect(err).toContain(root);
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
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "info-only"),
        () => 1000,
        86_400_000
      ),
      digest: () => "npm-info-only",
      now: () => 1000,
      run: emptyAuditRun(),
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({}),
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
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "mod-std"),
        () => 1000,
        86_400_000
      ),
      digest: () => "npm-moderate-std",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: moderate }),
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({}),
  });
  expect(
    standard.projects
      .flatMap((row) => row.findings)
      .some((f) => f.kind === "advisory" && f.severity === "moderate")
  ).toBe(true);
  expect(standard.exitCode).toBe(0);

  const strict = await auditPath("/p", {
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "mod-strict"),
        () => 1000,
        86_400_000
      ),
      digest: () => "npm-moderate-strict",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: moderate }),
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({ flags: { preset: "strict" } }),
  });
  expect(strict.exitCode).toBe(1);
});

test("relaxed fails only critical advisories; a high advisory is listed and exits 0", async () => {
  const fs = memoryFs(CLEAN_NPM_FILES, ["/p/.git"]);
  const result = await auditPath("/p", {
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "relaxed-high"),
        () => 1000,
        86_400_000
      ),
      digest: () => "npm-relaxed-high",
      now: () => 1000,
      run: () => ({ code: 1, stderr: "", stdout: advisoryJson("high") }),
      which: () => "/usr/bin/npm",
    },
    interactive: false,
    policy: loadPolicy({ flags: { preset: "relaxed" } }),
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
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "uv-depr"),
        () => 1000,
        86_400_000
      ),
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
    interactive: false,
    policy: loadPolicy({ flags: { preset: "relaxed" } }),
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
  const result = await run(["audit", root, "-i"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "interactive-skip"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    gitStatus: () => "clean",
    prompt: () => "skip" as const,
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: () => {} },
    which: () => "/usr/bin/npm",
    writeFile: () => {
      throw new Error("skip must not write");
    },
  });
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
  const result = await run(["audit", root, "-i"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "no-migrate-i"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    gitStatus: () => "clean",
    readLine: () => "skip",
    run: (argv) => {
      calls.push(argv);
      return { code: 0, stderr: "", stdout: "{}" };
    },
    runOsv: (lockOrRequirements) => {
      osvLock = lockOrRequirements;
      return [];
    },
    stderr: { write: () => {} },
    stdout: { write: (s: string) => stdout.push(s) },
    which: () => "/usr/bin/uv",
    writeFile: (path) => {
      written.push(path);
    },
  });
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
  await run(["audit", root, "--apply"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "no-migrate"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    gitStatus: () => "clean",
    run: (argv) => {
      calls.push(argv);
      return { code: 0, stderr: "", stdout: "{}" };
    },
    stderr: { write: () => {} },
    stdout: { write: () => {} },
    which: () => "/usr/bin/uv",
    writeFile: (path) => {
      written.push(path);
    },
  });
  expect(calls.every((argv) => argv[0] !== "uv")).toBe(true);
  expect(
    written.some((path) => path.endsWith("uv.toml") || path.endsWith("uv.lock"))
  ).toBe(false);
});

test("XDG_CONFIG_HOME wins over ~/.config/mailclad when CLI loads user config", async () => {
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
  const home = mkdtempSync(nodePath.join(tmpdir(), "mailclad-home-"));
  const xdg = mkdtempSync(nodePath.join(tmpdir(), "mailclad-xdg-"));
  mkdirSync(nodePath.join(home, ".config", "mailclad"), { recursive: true });
  mkdirSync(nodePath.join(xdg, "mailclad"), { recursive: true });
  writeFileSync(
    nodePath.join(home, ".config", "mailclad", "config.toml"),
    `preset = "standard"\n`
  );
  writeFileSync(
    nodePath.join(xdg, "mailclad", "config.toml"),
    `preset = "relaxed"\n`
  );
  const stdout: string[] = [];
  const result = await run(["audit", root], {
    cache: createFsCache(
      nodePath.join(cacheDir, "xdg"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: home, XDG_CONFIG_HOME: xdg },
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: (s: string) => stdout.push(s) },
    which: () => "/usr/bin/npm",
  });
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
  await run(["audit", root], {
    cache: createFsCache(
      nodePath.join(cacheDir, "no-report"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: () => {} },
    which: () => "/usr/bin/npm",
    writeFile: (path) => {
      written.push(path);
    },
  });
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
  const outDir = mkdtempSync(nodePath.join(tmpdir(), "mailclad-report-"));
  const reportPath = nodePath.join(outDir, "nested", "deep", "report.md");
  const result = await run(["audit", root, "--report", reportPath], {
    cache: createFsCache(
      nodePath.join(cacheDir, "report-mkdir"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: () => {} },
    which: () => "/usr/bin/npm",
  });
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
    await run(["audit", root, ...extra], {
      cache: createFsCache(
        nodePath.join(cacheDir, `conc-${extra.join("-") || "default"}`),
        () => 1000,
        86_400_000
      ),
      cwd: import.meta.dir,
      env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
      run: async () => {
        inFlight += 1;
        max = Math.max(max, inFlight);
        await Bun.sleep(25);
        inFlight -= 1;
        return { code: 0, stderr: "", stdout: `{"advisories":{}}` };
      },
      stderr: { write: () => {} },
      stdout: { write: () => {} },
      which: () => "/usr/bin/npm",
    });
    return max;
  };

  expect(await maxFor(["--concurrency", "1"])).toBe(1);
  expect(await maxFor([])).toBeGreaterThan(1);
  expect(await maxFor(["--concurrency", "0"])).toBeGreaterThan(1);
  expect(await maxFor(["--concurrency", "nope"])).toBeGreaterThan(1);
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
  const result = await run(["audit", root, "--apply", "--force", "--commit"], {
    cache: createFsCache(
      nodePath.join(cacheDir, "force-commit"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    gitCommit: (gitRoot, _message, files) => {
      commits.push({ files, root: gitRoot });
      return true;
    },
    gitStatus: () => "dirty",
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: () => {} },
    which: () => "/usr/bin/npm",
    writeFile: (path, body) => {
      written[path] = body;
    },
  });
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
    apply: false,
    applyAdvisories: false,
    concurrency: 4,
    deps: {
      ...fs,
      cache: createFsCache(
        nodePath.join(cacheDir, "two-primary"),
        () => 1000,
        86_400_000
      ),
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
    interactive: false,
    policy: loadPolicy({}),
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
  await run(["audit", root], {
    cache: createFsCache(
      nodePath.join(cacheDir, "color-on"),
      () => 1000,
      86_400_000
    ),
    color: true,
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: (s: string) => colored.push(s) },
    which: () => "/usr/bin/npm",
  });
  expect(colored.join("")).toContain("\u001B[");
  expect(colored.join("")).toContain("scripts.unrestricted");

  const plain: string[] = [];
  await run(["audit", root], {
    cache: createFsCache(
      nodePath.join(cacheDir, "color-off"),
      () => 1000,
      86_400_000
    ),
    cwd: import.meta.dir,
    env: { HOME: nodePath.join(import.meta.dir, "fixtures/empty-home") },
    run: emptyAuditRun(),
    stderr: { write: () => {} },
    stdout: { write: (s: string) => plain.push(s) },
    which: () => "/usr/bin/npm",
  });
  expect(plain.join("")).not.toContain("\u001B[");
});
