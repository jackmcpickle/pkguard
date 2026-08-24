import assert from "node:assert/strict";
import { test } from "node:test";

import { renderHomebrewFormula } from "./homebrew-formula.mjs";

const SHA256 = {
  "darwin-arm64": "9d9617e91283d48f6db7d75ea7963ad26aa3c3c8ea5a124bf9eaae8caf8c916e",
  "darwin-x64": "688c75e2adf07e76586aeef775b45f722a3f8ec76ed22412dc884d1dc6673ffa",
  "linux-arm64": "d62144803678a7e1d41171792084670f4a0077efabf9406946c5447240e90802",
  "linux-x64": "a2958ae4f07bff1126da0160ba9551867d818b497f6b5f9fa31ea94cd25887d9",
};

test("renders the tap formula for a release", () => {
  assert.equal(
    renderHomebrewFormula({ version: "1.0.1", sha256: SHA256 }),
    `class Pkguard < Formula
  desc "Scan package-manager settings and advisories across a folder of repos"
  homepage "https://pkguard.dev"
  version "1.0.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/jackmcpickle/pkguard/releases/download/v1.0.1/pkguard-darwin-arm64"
      sha256 "9d9617e91283d48f6db7d75ea7963ad26aa3c3c8ea5a124bf9eaae8caf8c916e"
    end
    on_intel do
      url "https://github.com/jackmcpickle/pkguard/releases/download/v1.0.1/pkguard-darwin-x64"
      sha256 "688c75e2adf07e76586aeef775b45f722a3f8ec76ed22412dc884d1dc6673ffa"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/jackmcpickle/pkguard/releases/download/v1.0.1/pkguard-linux-arm64"
      sha256 "d62144803678a7e1d41171792084670f4a0077efabf9406946c5447240e90802"
    end
    on_intel do
      url "https://github.com/jackmcpickle/pkguard/releases/download/v1.0.1/pkguard-linux-x64"
      sha256 "a2958ae4f07bff1126da0160ba9551867d818b497f6b5f9fa31ea94cd25887d9"
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
`
  );
});

test("strips a leading v from the version", () => {
  const formula = renderHomebrewFormula({ version: "v1.0.1", sha256: SHA256 });
  assert.match(formula, /version "1\.0\.1"/);
  assert.match(formula, /download\/v1\.0\.1\/pkguard-darwin-arm64/);
});

test("rejects a missing version", () => {
  assert.throws(() => renderHomebrewFormula({ version: "", sha256: SHA256 }), {
    name: "Error",
    message: /version/u,
  });
});

test("rejects a missing or malformed sha256", () => {
  assert.throws(
    () => renderHomebrewFormula({ version: "1.0.1", sha256: { ...SHA256, "linux-x64": "" } }),
    { name: "Error", message: /linux-x64/u }
  );
  assert.throws(
    () =>
      renderHomebrewFormula({
        version: "1.0.1",
        sha256: { ...SHA256, "darwin-arm64": "not-a-hash" },
      }),
    { name: "Error", message: /darwin-arm64/u }
  );
});
