import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "bun:test";

import { dacsVerifyConvergenceAdapter } from "../conformance/pathos-convergence-adapter.ts";
import { bundleHash, type AttestationBundle } from "../src/dacs5/index.ts";

const fixtureNames = [
  "attestation-bundle-0004.json",
  "attestation-bundle-0004-seller.json",
  "attestation-bundle-htlc9.json",
] as const;

test("pathos convergence adapter reports dacs-verify hash and decision for shared bundle fixtures", () => {
  for (const fixtureName of fixtureNames) {
    const fixture = JSON.parse(readFileSync(join(import.meta.dir, "..", "conformance", "fixtures", fixtureName), "utf8")) as AttestationBundle;
    const result = dacsVerifyConvergenceAdapter.verify(fixture as unknown as Record<string, unknown>);

    expect(result).toEqual({
      decision: "pass",
      hash: bundleHash(fixture),
    });
  }
});
