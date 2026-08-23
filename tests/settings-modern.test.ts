import { expect, test } from "bun:test";

import { applySettings } from "../src/apply-settings";
import type { PackageManager, Project } from "../src/domain";
import { loadPolicy } from "../src/policy";
import { auditSettings } from "../src/settings";

const CONFIG_NAME: Record<string, string> = {
  bun: "bunfig.toml",
  cargo: ".cargo/config.toml",
  npm: ".npmrc",
  pnpm: "pnpm-workspace.yaml",
  uv: "pyproject.toml",
  yarn: ".yarnrc.yml",
};

const LOCK_NAME: Record<string, string> = {
  bun: "bun.lock",
  cargo: "Cargo.lock",
  npm: "package-lock.json",
  pnpm: "pnpm-lock.yaml",
  uv: "uv.lock",
  yarn: "yarn.lock",
};

const MANIFEST_NAME: Partial<Record<PackageManager, string>> = {
  cargo: "Cargo.toml",
  uv: "pyproject.toml",
};

const project = (name: PackageManager, root = "/p"): Project => {
  const manifest = MANIFEST_NAME[name] ?? "package.json";
  return {
    gitRoot: root,
    managers: [
      {
        configPath: `${root}/${CONFIG_NAME[name]}`,
        lockfilePath: `${root}/${LOCK_NAME[name]}`,
        manifestPath: `${root}/${manifest}`,
        name,
        role: "primary",
      },
    ],
    root,
  };
};

const codes = (
  name: PackageManager,
  files: Record<string, string>,
  policy = loadPolicy({})
): string[] =>
  auditSettings(project(name), policy, {
    readFile: (p) => files[p] ?? null,
  }).map((f) => f.code);

const find = (
  name: PackageManager,
  files: Record<string, string>,
  code: string,
  policy = loadPolicy({})
) =>
  auditSettings(project(name), policy, {
    readFile: (p) => files[p] ?? null,
  }).find((f) => f.code === code);

const pnpmSecureBaseline =
  "trustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\nverifyDepsBeforeRun: error\n";

/** A pnpm project whose only interesting content is the workspace yaml. */
const pnpmFiles = (version: string, yaml: string): Record<string, string> => ({
  "/p/package.json": `{"name":"x","packageManager":"pnpm@${version}"}`,
  "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
  "/p/pnpm-workspace.yaml": `registry: "https://registry.npmjs.org/"\naudit:\n  level: high\n${pnpmSecureBaseline}${yaml}`,
});

/** Like pnpmFiles but without the pkguard security baseline — for gap tests. */
const pnpmFilesInsecure = (
  version: string,
  yaml: string
): Record<string, string> => ({
  "/p/package.json": `{"name":"x","packageManager":"pnpm@${version}"}`,
  "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
  "/p/pnpm-workspace.yaml": `registry: "https://registry.npmjs.org/"\naudit:\n  level: high\nminimumReleaseAge: 1440\nallowBuilds: {}\n${yaml}`,
});

const yarnFiles = (version: string, yaml: string): Record<string, string> => ({
  "/p/.yarnrc.yml": `npmRegistryServer: "https://registry.npmjs.org/"\nnodeLinker: node-modules\n${yaml}`,
  "/p/package.json": `{"name":"x","packageManager":"yarn@${version}"}`,
  "/p/yarn.lock": "",
});

const bunFiles = (install: string): Record<string, string> => ({
  "/p/bun.lock": `{"lockfileVersion":1}`,
  "/p/bunfig.toml": `trustedDependencies = ["foo"]\n\n[install]\nregistry = "https://registry.npmjs.org/"\n${install}`,
  "/p/package.json": `{"name":"x","trustedDependencies":["foo"]}`,
});

const npmFiles = (manifest: string, npmrc: string): Record<string, string> => ({
  "/p/.npmrc": `audit=true\naudit-level=high\nmin-release-age=7\nregistry=https://registry.npmjs.org/\n${npmrc}`,
  "/p/package-lock.json": `{"lockfileVersion":3}`,
  "/p/package.json": manifest,
});

// --- pnpm 11 build settings -------------------------------------------------

test("pnpm 11 allowBuilds satisfies the script check", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 1440\nallowBuilds:\n  esbuild: true\n"
  );
  expect(codes("pnpm", files)).toEqual([]);
});

test("pnpm 11 flags the removed onlyBuiltDependencies family", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 1440\nonlyBuiltDependencies:\n  - esbuild\n"
  );
  const finding = find("pnpm", files, "scripts.legacy-config");
  expect(finding?.severity).toBe("high");
  expect(finding?.message).toContain("onlyBuiltDependencies");
});

test("pnpm 10 still accepts the legacy build allowlist", () => {
  const files = pnpmFiles(
    "10.0.0",
    "minimumReleaseAge: 1440\nonlyBuiltDependencies:\n  - esbuild\n"
  );
  expect(codes("pnpm", files)).toEqual([]);
});

test("pnpm dangerouslyAllowAllBuilds is high regardless of version", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 1440\ndangerouslyAllowAllBuilds: true\n"
  );
  expect(find("pnpm", files, "scripts.unrestricted")?.severity).toBe("high");
});

test("pnpm relying on the safe build default is info, not high", () => {
  const files = pnpmFiles("11.7.0", "minimumReleaseAge: 1440\n");
  const finding = find("pnpm", files, "scripts.unrestricted");
  expect(finding?.severity).toBe("info");
  expect(finding?.fixable).toBe(true);
});

test("pnpm 9 without any allowlist is still high", () => {
  const files = pnpmFiles("9.0.0", "minimumReleaseAge: 1440\n");
  expect(find("pnpm", files, "scripts.unrestricted")?.severity).toBe("high");
});

test("pnpm strictDepBuilds: false is flagged", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 1440\nallowBuilds: {}\nstrictDepBuilds: false\n"
  );
  expect(codes("pnpm", files)).toContain("scripts.non-strict");
});

test("pnpm blockExoticSubdeps: false is flagged", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 1440\nallowBuilds: {}\nblockExoticSubdeps: false\n"
  );
  expect(codes("pnpm", files)).toContain("source.non-registry");
});

// --- pnpm pkguard security gaps -----------------------------------------------

test("pnpm 11 flags missing trustPolicy", () => {
  const files = pnpmFilesInsecure("11.7.0", "");
  expect(codes("pnpm", files)).toContain("provenance.no-downgrade");
});

test("pnpm 11 flags trustPolicy other than no-downgrade", () => {
  const files = pnpmFilesInsecure("11.7.0", "trustPolicy: off\n");
  expect(codes("pnpm", files)).toContain("provenance.no-downgrade");
});

test("pnpm 10.20 skips trustPolicy check", () => {
  const files = pnpmFilesInsecure("10.20.0", "");
  expect(codes("pnpm", files)).not.toContain("provenance.no-downgrade");
});

test("pnpm 11 flags trustLockfile: true", () => {
  const files = pnpmFilesInsecure("11.7.0", "trustLockfile: true\n");
  expect(codes("pnpm", files)).toContain("lockfile.trust-bypass");
});

test("pnpm 11 accepts absent trustLockfile", () => {
  const files = pnpmFilesInsecure("11.7.0", "trustPolicy: no-downgrade\n");
  expect(codes("pnpm", files)).not.toContain("lockfile.trust-bypass");
});

test("pnpm 11 flags verifyDepsBeforeRun not error", () => {
  const files = pnpmFilesInsecure("11.7.0", "trustPolicy: no-downgrade\n");
  expect(codes("pnpm", files)).toContain("lockfile.run-verify");
});

test("pnpm 11 accepts verifyDepsBeforeRun: error", () => {
  const files = pnpmFilesInsecure(
    "11.7.0",
    "trustPolicy: no-downgrade\nverifyDepsBeforeRun: error\n"
  );
  expect(codes("pnpm", files)).not.toContain("lockfile.run-verify");
});

test("pnpm 10.11 skips verifyDepsBeforeRun check", () => {
  const files = pnpmFilesInsecure("10.11.0", "trustPolicy: no-downgrade\n");
  expect(codes("pnpm", files)).not.toContain("lockfile.run-verify");
});

test("apply writes pnpm pkguard security keys", () => {
  const files = pnpmFilesInsecure("11.7.0", "trustLockfile: true\n");
  const target = project("pnpm");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  const written = files["/p/pnpm-workspace.yaml"] ?? "";
  expect(written).toContain("trustPolicy: no-downgrade");
  expect(written).toContain("trustLockfile: false");
  expect(written).toContain("verifyDepsBeforeRun: error");
  expect(written).toContain("trustPolicyIgnoreAfter: 129600");
});

test("pnpm boolean audit: true without a level is audit.disabled", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@11.16.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "registry: https://registry.npmjs.org/\naudit: true\nminimumReleaseAge: 1440\nallowBuilds: {}\ntrustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\nverifyDepsBeforeRun: error\n",
  };
  expect(codes("pnpm", files)).toContain("audit.disabled");
});

test("pnpm audit.level meeting the gate is quiet", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@11.16.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "registry: https://registry.npmjs.org/\naudit:\n  level: high\nminimumReleaseAge: 1440\nallowBuilds: {}\ntrustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\nverifyDepsBeforeRun: error\n",
  };
  expect(codes("pnpm", files)).not.toContain("audit.disabled");
});

test("pnpm apply writes audit.level instead of boolean audit", () => {
  const files: Record<string, string> = {
    "/p/package.json": `{"name":"x","packageManager":"pnpm@11.16.0"}`,
    "/p/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    "/p/pnpm-workspace.yaml":
      "registry: https://registry.npmjs.org/\nminimumReleaseAge: 1440\nallowBuilds: {}\ntrustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\nverifyDepsBeforeRun: error\n",
  };
  const target = project("pnpm");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  const written = files["/p/pnpm-workspace.yaml"] ?? "";
  expect(written).toContain("level: high");
  expect(written).not.toContain("audit: true");
});

test("pnpm 11 flags missing trustPolicyIgnoreAfter", () => {
  const files = pnpmFilesInsecure("11.7.0", "trustPolicy: no-downgrade\n");
  expect(codes("pnpm", files)).toContain("provenance.ignore-after");
});

test("pnpm 10.26 skips trustPolicyIgnoreAfter", () => {
  const files = pnpmFilesInsecure("10.26.0", "trustPolicy: no-downgrade\n");
  expect(codes("pnpm", files)).not.toContain("provenance.ignore-after");
});

test("pnpm trustPolicyIgnoreAfter below 90 days is flagged", () => {
  const files = pnpmFilesInsecure(
    "11.7.0",
    "trustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 1440\n"
  );
  expect(codes("pnpm", files)).toContain("provenance.ignore-after");
});

test("pnpm trustPolicyIgnoreAfter of 90 days is quiet", () => {
  const files = pnpmFilesInsecure(
    "11.7.0",
    "trustPolicy: no-downgrade\ntrustPolicyIgnoreAfter: 129600\n"
  );
  expect(codes("pnpm", files)).not.toContain("provenance.ignore-after");
});

// --- release-age gates ------------------------------------------------------

test("pnpm 11 inherits minimumReleaseAge 1440, which clears a 1-day bar", () => {
  const files = pnpmFiles("11.7.0", "allowBuilds: {}\n");
  const policy = loadPolicy({ flags: { overrides: { minReleaseAgeDays: 1 } } });
  expect(codes("pnpm", files, policy)).toEqual([]);
});

test("pnpm 11 default of 1440 minutes clears the standard 1-day bar", () => {
  const files = pnpmFiles("11.7.0", "allowBuilds: {}\n");
  expect(codes("pnpm", files)).not.toContain("min-age.disabled");
});

test("pnpm minimumReleaseAgeStrict: false is flagged", () => {
  const files = pnpmFiles(
    "11.7.0",
    "allowBuilds: {}\nminimumReleaseAge: 1440\nminimumReleaseAgeStrict: false\n"
  );
  expect(codes("pnpm", files)).toContain("min-age.non-strict");
});

test("a wildcard minimumReleaseAgeExclude voids the gate", () => {
  const files = pnpmFiles(
    "11.7.0",
    'allowBuilds: {}\nminimumReleaseAge: 1440\nminimumReleaseAgeExclude:\n  - "*"\n'
  );
  expect(codes("pnpm", files)).toContain("min-age.exclude-all");
});

test("a named minimumReleaseAgeExclude is left alone", () => {
  const files = pnpmFiles(
    "11.7.0",
    "allowBuilds: {}\nminimumReleaseAge: 1440\nminimumReleaseAgeExclude:\n  - typescript\n"
  );
  expect(codes("pnpm", files)).not.toContain("min-age.exclude-all");
});

test("strict preset wants minimumReleaseAgeIgnoreMissingTime off", () => {
  const files = pnpmFiles(
    "11.7.0",
    "allowBuilds: {}\nminimumReleaseAge: 20160\n"
  );
  const strict = loadPolicy({ flags: { preset: "strict" } });
  expect(codes("pnpm", files, strict)).toContain("min-age.missing-time");
  expect(codes("pnpm", files)).not.toContain("min-age.missing-time");
});

test("relaxed preset skips every release-age check", () => {
  const files = pnpmFiles(
    "11.7.0",
    'allowBuilds: {}\nminimumReleaseAge: 0\nminimumReleaseAgeStrict: false\nminimumReleaseAgeExclude:\n  - "*"\n'
  );
  const relaxed = loadPolicy({ flags: { preset: "relaxed" } });
  expect(
    codes("pnpm", files, relaxed).filter((c) => c.startsWith("min-age"))
  ).toEqual([]);
});

// --- yarn -------------------------------------------------------------------

test("yarn 4.15 relying on the enableScripts default is info, not high", () => {
  const files = yarnFiles("4.15.0", "npmMinimalAgeGate: 1440\n");
  const finding = find("yarn", files, "scripts.unrestricted");
  expect(finding?.severity).toBe("info");
  expect(finding?.fixable).toBe(true);
});

test("yarn enableScripts: true is high even on 4.15", () => {
  const files = yarnFiles(
    "4.15.0",
    "npmMinimalAgeGate: 1440\nenableScripts: true\n"
  );
  expect(find("yarn", files, "scripts.unrestricted")?.severity).toBe("high");
});

test("yarn 4.13 predates the scripts-off default so an absent key is high", () => {
  const files = yarnFiles("4.13.0", "npmMinimalAgeGate: 1440\n");
  expect(find("yarn", files, "scripts.unrestricted")?.severity).toBe("high");
});

test("yarn npmMinimalAgeGate accepts duration strings", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nnpmMinimalAgeGate: 7d\napprovedGitRepositories: []\n"
  );
  expect(codes("yarn", files)).toEqual([]);
});

test("yarn 4.15 inherits a 1w gate, which clears the standard bar but not strict", () => {
  const files = yarnFiles("4.15.0", "enableScripts: false\n");
  expect(codes("yarn", files)).not.toContain("min-age.disabled");
  const strict = loadPolicy({ flags: { preset: "strict" } });
  expect(codes("yarn", files, strict)).toContain("min-age.disabled");
});

test("yarn 4.11 predates the gate so an absent key fails", () => {
  const files = yarnFiles("4.11.0", "enableScripts: false\n");
  expect(codes("yarn", files)).toContain("min-age.disabled");
});

test("a wildcard npmPreapprovedPackages voids the gate", () => {
  const files = yarnFiles(
    "4.15.0",
    'enableScripts: false\nnpmPreapprovedPackages:\n  - "*"\n'
  );
  expect(codes("yarn", files)).toContain("min-age.exclude-all");
});

test("yarn checksumBehavior other than throw is flagged", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nchecksumBehavior: update\n"
  );
  expect(codes("yarn", files)).toContain("integrity.checksum-relaxed");
});

test("yarn enableStrictSsl: false and enableHardenedMode: false are flagged", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nenableStrictSsl: false\nenableHardenedMode: false\n"
  );
  const found = codes("yarn", files);
  expect(found).toContain("integrity.strict-ssl");
  expect(found).toContain("integrity.hardened-mode");
});

test("yarn 4.15 with approvedGitRepositories: [] passes git source check", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nnpmMinimalAgeGate: 1440\napprovedGitRepositories: []\n"
  );
  expect(codes("yarn", files)).not.toContain("source.git-unrestricted");
});

test("yarn 4.15 missing approvedGitRepositories is high under standard", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nnpmMinimalAgeGate: 1440\n"
  );
  expect(find("yarn", files, "source.git-unrestricted")?.severity).toBe("high");
});

test("yarn 4.15 with wildcard approvedGitRepositories is high", () => {
  const files = yarnFiles(
    "4.15.0",
    'enableScripts: false\nnpmMinimalAgeGate: 1440\napprovedGitRepositories:\n  - "*"\n'
  );
  expect(find("yarn", files, "source.git-unrestricted")?.severity).toBe("high");
});

test("yarn 4.15 with explicit git allowlist is not flagged", () => {
  const files = yarnFiles(
    "4.15.0",
    'enableScripts: false\nnpmMinimalAgeGate: 1440\napprovedGitRepositories:\n  - "https://github.com/myorg/*"\n'
  );
  expect(codes("yarn", files)).not.toContain("source.git-unrestricted");
});

test("yarn 4.13 predates approvedGitRepositories so missing key is high", () => {
  const files = yarnFiles(
    "4.13.0",
    "enableScripts: false\nnpmMinimalAgeGate: 1440\n"
  );
  expect(find("yarn", files, "source.git-unrestricted")?.severity).toBe("high");
});

test("yarn git source check skipped when ignoreScripts policy is off", () => {
  const files = yarnFiles("4.15.0", "npmMinimalAgeGate: 1440\n");
  const relaxed = loadPolicy({ flags: { preset: "relaxed" } });
  expect(codes("yarn", files, relaxed)).not.toContain(
    "source.git-unrestricted"
  );
});

// --- bun --------------------------------------------------------------------

test("bun minimumReleaseAge is read as seconds", () => {
  expect(codes("bun", bunFiles("minimumReleaseAge = 86400\n"))).toEqual([]);
  // 43200 seconds is twelve hours; bun counts seconds, not minutes.
  expect(codes("bun", bunFiles("minimumReleaseAge = 43200\n"))).toContain(
    "min-age.disabled"
  );
});

test("bun with no minimumReleaseAge is flagged", () => {
  expect(codes("bun", bunFiles(""))).toContain("min-age.disabled");
});

test("a wildcard minimumReleaseAgeExcludes voids the bun gate", () => {
  const files = bunFiles(
    'minimumReleaseAge = 86400\nminimumReleaseAgeExcludes = ["*"]\n'
  );
  expect(codes("bun", files)).toContain("min-age.exclude-all");
});

// --- npm --------------------------------------------------------------------

test("an enforced allowScripts policy replaces blanket ignore-scripts", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0","allowScripts":{"esbuild@0.2.5":true}}`,
    "strict-allow-scripts=true\nallow-scripts-pin=true\n"
  );
  expect(codes("npm", files)).toEqual([]);
});

test("allowScripts without strict-allow-scripts is only advisory", () => {
  const files = npmFiles(
    `{"name":"x","allowScripts":{"esbuild@0.2.5":true}}`,
    ""
  );
  const found = codes("npm", files);
  expect(found).toContain("scripts.unrestricted");
  expect(found).toContain("scripts.allowlist-advisory");
});

test("ignore-scripts masking an allowScripts policy is reported", () => {
  const files = npmFiles(
    `{"name":"x","allowScripts":{"esbuild@0.2.5":true}}`,
    "ignore-scripts=true\n"
  );
  const found = codes("npm", files);
  expect(found).not.toContain("scripts.unrestricted");
  expect(found).toContain("scripts.allowlist-masked");
});

test("npm allow-git=all is flagged", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0"}`,
    "ignore-scripts=true\nallow-git=all\n"
  );
  expect(codes("npm", files)).toContain("source.non-registry");
});

test("npm allow-file=all is flagged", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0"}`,
    "ignore-scripts=true\nallow-file=all\n"
  );
  expect(codes("npm", files)).toContain("source.non-registry");
});

test("npm allow-directory=all is flagged", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0"}`,
    "ignore-scripts=true\nallow-directory=all\n"
  );
  expect(codes("npm", files)).toContain("source.non-registry");
});

test("npm missing allow-scripts-pin is flagged under standard", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0"}`,
    "ignore-scripts=true\n"
  );
  expect(codes("npm", files)).toContain("scripts.pin-missing");
});

test("npm allow-scripts-pin=true passes the pin check", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0"}`,
    "ignore-scripts=true\nallow-scripts-pin=true\n"
  );
  expect(codes("npm", files)).not.toContain("scripts.pin-missing");
});

test("npm dangerously-allow-all-scripts=true emits scripts.bypass-enabled", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0"}`,
    "ignore-scripts=true\ndangerously-allow-all-scripts=true\n"
  );
  expect(codes("npm", files)).toContain("scripts.bypass-enabled");
});

test("npm script bypass and pin findings are skipped under relaxed", () => {
  const files = npmFiles(`{"name":"x","packageManager":"npm@11.17.0"}`, "");
  const relaxed = loadPolicy({ flags: { preset: "relaxed" } });
  const found = codes("npm", files, relaxed);
  expect(found).not.toContain("scripts.pin-missing");
  expect(found).not.toContain("scripts.bypass-enabled");
});

// --- cargo ------------------------------------------------------------------

const cargoFiles = (install: string): Record<string, string> => ({
  "/p/.cargo/config.toml": `[install]\n${install}`,
  "/p/Cargo.lock": "# cargo\n",
  "/p/Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
});

test("cargo minimum-release-age accepts duration strings", () => {
  expect(codes("cargo", cargoFiles('minimum-release-age = "1d"\n'))).toEqual(
    []
  );
  expect(
    codes("cargo", cargoFiles('minimum-release-age = "1 week"\n'))
  ).toEqual([]);
  expect(codes("cargo", cargoFiles('minimum-release-age = "12h"\n'))).toContain(
    "min-age.disabled"
  );
});

test("cargo without minimum-release-age emits min-age.disabled under standard", () => {
  const files = {
    "/p/.cargo/config.toml": "[install]\n",
    "/p/Cargo.lock": "# cargo\n",
    "/p/Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
  };
  expect(codes("cargo", files)).toContain("min-age.disabled");
});

test("cargo without Cargo.lock emits lockfile.missing under standard", () => {
  const files = {
    "/p/.cargo/config.toml": '[install]\nminimum-release-age = "1d"\n',
    "/p/Cargo.toml": '[package]\nname = "x"\nversion = "0.1.0"\n',
  };
  expect(codes("cargo", files)).toContain("lockfile.missing");
});

// --- uv ---------------------------------------------------------------------

const uvFiles = (toolUv: string): Record<string, string> => ({
  "/p/pyproject.toml": `[project]\nname = "x"\n\n[tool.uv]\n${toolUv}`,
  "/p/uv.lock": "version = 1\n",
});

test("uv exclude-newer accepts uv's own duration spelling", () => {
  const audit = `\n\n[tool.uv.audit]\nmalware-check = true\n`;
  expect(codes("uv", uvFiles(`exclude-newer = "1 days"\n${audit}`))).toEqual(
    []
  );
  expect(codes("uv", uvFiles(`exclude-newer = "1 week"\n${audit}`))).toEqual(
    []
  );
  expect(
    codes("uv", uvFiles(`exclude-newer = "12 hours"\n${audit}`))
  ).toContain("min-age.disabled");
});

test("a wildcard exclude-newer-package voids the uv gate", () => {
  const files = uvFiles(
    `exclude-newer = "1 days"\n\n[tool.uv.exclude-newer-package]\n"*" = false\n`
  );
  expect(codes("uv", files)).toContain("min-age.exclude-all");
});

test("exclude-newer-package fix drops only blanket keys and keeps any value type", () => {
  const files = uvFiles(
    `exclude-newer = "1 days"\n\n[tool.uv.exclude-newer-package]\n"*" = false\nleft-pad = true\nrequests = { exclude-newer = "2 days" }\n`
  );
  const found = find("uv", files, "min-age.exclude-all");
  expect(found?.fix?.edits).toEqual([
    {
      key: "tool.uv.exclude-newer-package",
      op: "set",
      value: {
        "left-pad": true,
        requests: { "exclude-newer": "2 days" },
      },
    },
  ]);
});

test("uv with audit malware-check true passes", () => {
  const files = uvFiles(
    `exclude-newer = "1 days"\n\n[tool.uv.audit]\nmalware-check = true\n`
  );
  expect(codes("uv", files)).not.toContain("audit.malware-disabled");
});

test("uv missing malware-check is flagged", () => {
  const files = uvFiles(`exclude-newer = "1 days"\n`);
  expect(codes("uv", files)).toContain("audit.malware-disabled");
});

test("uv malware-check false is flagged", () => {
  const files = uvFiles(
    `exclude-newer = "1 days"\n\n[tool.uv.audit]\nmalware-check = false\n`
  );
  expect(codes("uv", files)).toContain("audit.malware-disabled");
});

test("uv malware-check in uv.toml is honored", () => {
  const files: Record<string, string> = {
    "/p/pyproject.toml": `[project]\nname = "x"\n`,
    "/p/uv.lock": "version = 1\n",
    "/p/uv.toml": `exclude-newer = "1 days"\n\n[audit]\nmalware-check = true\n`,
  };
  expect(codes("uv", files)).not.toContain("audit.malware-disabled");
});

// --- apply ------------------------------------------------------------------

test("apply keeps existing allowBuilds entries of any type and does not overwrite them", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 1440\ndangerouslyAllowAllBuilds: true\nallowBuilds:\n  esbuild: yes\nonlyBuiltDependencies:\n  - esbuild\n  - core-js\n"
  );
  const target = project("pnpm");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.some((f) => f.code === "scripts.unrestricted")).toBe(true);
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  const written = files["/p/pnpm-workspace.yaml"] ?? "";
  expect(written).toContain("esbuild: yes");
  expect(written).toContain("core-js: true");
  expect(written).not.toContain("esbuild: true");
  expect(written).not.toContain("onlyBuiltDependencies");
});

test("apply migrates the pnpm legacy build allowlist into allowBuilds", () => {
  const files = pnpmFiles(
    "11.7.0",
    "minimumReleaseAge: 1440\nonlyBuiltDependencies:\n  - esbuild\nneverBuiltDependencies:\n  - core-js\n"
  );
  const target = project("pnpm");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  const written = files["/p/pnpm-workspace.yaml"] ?? "";
  expect(written).toContain("esbuild: true");
  expect(written).toContain("core-js: false");
  expect(written).not.toContain("onlyBuiltDependencies");
  expect(written).not.toContain("neverBuiltDependencies");
});

test("apply writes npm non-registry and script pin keys", () => {
  const files = npmFiles(
    `{"name":"x","packageManager":"npm@11.17.0"}`,
    "allow-git=all\nallow-file=all\nallow-directory=all\ndangerously-allow-all-scripts=true\n"
  );
  const target = project("npm");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  const written = files["/p/.npmrc"] ?? "";
  expect(written).toContain("allow-git=none");
  expect(written).toContain("allow-file=none");
  expect(written).toContain("allow-directory=none");
  expect(written).toContain("allow-scripts-pin=true");
  expect(written).toContain("dangerously-allow-all-scripts=false");
});

test("apply strips wildcard entries from a pnpm exclude list", () => {
  const files = pnpmFiles(
    "11.7.0",
    'allowBuilds: {}\nminimumReleaseAge: 1440\nminimumReleaseAgeExclude:\n  - "*"\n  - typescript\n'
  );
  const target = project("pnpm");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  const written = files["/p/pnpm-workspace.yaml"] ?? "";
  expect(written).toContain("typescript");
  expect(written).not.toContain('"*"');
});

test("apply sets approvedGitRepositories: [] on yarn", () => {
  const files = yarnFiles(
    "4.15.0",
    "enableScripts: false\nnpmMinimalAgeGate: 1440\n"
  );
  const target = project("yarn");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.map((f) => f.code)).toContain("source.git-unrestricted");
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(files["/p/.yarnrc.yml"]).toContain("approvedGitRepositories: []");
});

test("apply sets audit malware-check on uv", () => {
  const files = uvFiles(`exclude-newer = "1 days"\n`);
  const target = project("uv");
  const findings = auditSettings(target, loadPolicy({}), {
    readFile: (p) => files[p] ?? null,
  });
  expect(findings.map((f) => f.code)).toContain("audit.malware-disabled");
  applySettings(target, findings, loadPolicy({}), {
    commit: false,
    force: false,
    gitStatus: () => "clean",
    readFile: (p) => files[p] ?? null,
    writeFile: (p, b) => {
      files[p] = b;
    },
  });
  expect(files["/p/pyproject.toml"]).toContain("malware-check = true");
});

test("pnpm min-age finding carries minutes and legacy migration unsets only present keys", () => {
  const files = pnpmFiles(
    "11.7.0",
    "onlyBuiltDependencies:\n  - esbuild\nneverBuiltDependencies:\n  - core-js\n"
  );
  const legacy = find("pnpm", files, "scripts.legacy-config");
  expect(legacy?.fix).toEqual({
    edits: [
      { key: "dangerouslyAllowAllBuilds", op: "set", value: false },
      { key: "onlyBuiltDependencies", op: "unset" },
      { key: "neverBuiltDependencies", op: "unset" },
      {
        key: "allowBuilds",
        op: "set",
        value: { "core-js": false, esbuild: true },
      },
    ],
    file: "/p/pnpm-workspace.yaml",
    format: "yaml",
  });
});

test("yarn min-age finding carries minutes", () => {
  const files = yarnFiles("3.2.0", "enableScripts: false\n");
  const found = find("yarn", files, "min-age.disabled");
  expect(found?.fix).toEqual({
    edits: [{ key: "npmMinimalAgeGate", op: "set", value: 1440 }],
    file: "/p/.yarnrc.yml",
    format: "yaml",
  });
});

test("bun min-age finding carries seconds", () => {
  const files = bunFiles("");
  const found = find("bun", files, "min-age.disabled");
  expect(found?.fix).toEqual({
    edits: [{ key: "install.minimumReleaseAge", op: "set", value: 86_400 }],
    file: "/p/bunfig.toml",
    format: "toml",
  });
});

test("cargo min-age finding carries a duration string", () => {
  const files = cargoFiles("");
  const found = find("cargo", files, "min-age.disabled");
  expect(found?.fix).toEqual({
    edits: [{ key: "install.minimum-release-age", op: "set", value: "1d" }],
    file: "/p/.cargo/config.toml",
    format: "toml",
  });
});

test("uv min-age finding writes the computed path with a dotted key prefix", () => {
  const files = uvFiles("");
  const found = find("uv", files, "min-age.disabled");
  expect(found?.fix?.file).toBe("/p/pyproject.toml");
  expect(found?.fix?.format).toBe("toml");
  expect(found?.fix?.edits).toEqual([
    expect.objectContaining({
      key: "tool.uv.exclude-newer",
      op: "set",
    }),
  ]);
  const value = found?.fix?.edits[0];
  expect(value?.op === "set" ? typeof value.value : "").toBe("string");
});
