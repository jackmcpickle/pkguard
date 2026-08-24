import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ARTIFACTS = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"];
const SHA256_RE = /^[0-9a-f]{64}$/u;

const normalizeVersion = (version) => {
  const normalized = version?.replace(/^v/u, "") ?? "";
  if (normalized === "") {
    throw new Error("version is required");
  }
  return normalized;
};

const requireSha256 = (sha256, artifact) => {
  const digest = sha256?.[artifact] ?? "";
  if (!SHA256_RE.test(digest)) {
    throw new Error(`${artifact} sha256 must be 64 lowercase hex characters`);
  }
  return digest;
};

export const renderHomebrewFormula = ({ version, sha256 }) => {
  const release = normalizeVersion(version);
  const hashes = Object.fromEntries(
    ARTIFACTS.map((artifact) => [artifact, requireSha256(sha256, artifact)])
  );

  return `class Pkguard < Formula
  desc "Scan package-manager settings and advisories across a folder of repos"
  homepage "https://pkguard.dev"
  version "${release}"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/jackmcpickle/pkguard/releases/download/v${release}/pkguard-darwin-arm64"
      sha256 "${hashes["darwin-arm64"]}"
    end
    on_intel do
      url "https://github.com/jackmcpickle/pkguard/releases/download/v${release}/pkguard-darwin-x64"
      sha256 "${hashes["darwin-x64"]}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/jackmcpickle/pkguard/releases/download/v${release}/pkguard-linux-arm64"
      sha256 "${hashes["linux-arm64"]}"
    end
    on_intel do
      url "https://github.com/jackmcpickle/pkguard/releases/download/v${release}/pkguard-linux-x64"
      sha256 "${hashes["linux-x64"]}"
    end
  end

  def install
    binary = Dir["pkguard-*"].first
    odie "pkguard binary missing" if binary.nil?

    chmod 0755, binary
    bin.install binary => "pkguard"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pkguard --version")
  end
end
`;
};

const invokedDirectly =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (invokedDirectly) {
  const [version, darwinArm64, darwinX64, linuxArm64, linuxX64] = process.argv.slice(2);
  if (
    version === undefined ||
    darwinArm64 === undefined ||
    darwinX64 === undefined ||
    linuxArm64 === undefined ||
    linuxX64 === undefined
  ) {
    process.stderr.write(
      "usage: node scripts/homebrew-formula.mjs <version> <darwin-arm64> <darwin-x64> <linux-arm64> <linux-x64>\n"
    );
    process.exit(1);
  }
  try {
    process.stdout.write(
      renderHomebrewFormula({
        version,
        sha256: {
          "darwin-arm64": darwinArm64,
          "darwin-x64": darwinX64,
          "linux-arm64": linuxArm64,
          "linux-x64": linuxX64,
        },
      })
    );
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}
