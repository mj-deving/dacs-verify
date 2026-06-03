import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test, expect } from "bun:test";

import { DOMAIN_SEPARATOR_REGISTRY } from "../src/signing.ts";
import { bundleHash, verifyBundle, type AttestationBundle, type BundleSignature } from "../src/dacs5/index.ts";
import { keypairFromSeed, signArtifact, type Keypair } from "../examples/issuer-kit.ts";
import {
  ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF,
  buildAttestationBundle0004,
  buildAttestationBundle0004Seller,
  buildAttestationBundleHtlc9,
} from "../examples/attestation-bundle-0004.ts";

const fixturePath = join(import.meta.dir, "..", "conformance", "fixtures", "attestation-bundle-0004.json");
const fixtureText = readFileSync(fixturePath, "utf8");
const fixture = JSON.parse(fixtureText) as AttestationBundle;
const emitted = buildAttestationBundle0004();
const sellerFixturePath = join(import.meta.dir, "..", "conformance", "fixtures", "attestation-bundle-0004-seller.json");
const sellerFixtureText = readFileSync(sellerFixturePath, "utf8");
const sellerFixture = JSON.parse(sellerFixtureText) as AttestationBundle;
const sellerEmitted = buildAttestationBundle0004Seller();
const htlc9FixturePath = join(import.meta.dir, "..", "conformance", "fixtures", "attestation-bundle-htlc9.json");
const htlc9FixtureText = readFileSync(htlc9FixturePath, "utf8");
const htlc9Fixture = JSON.parse(htlc9FixtureText) as AttestationBundle;
const htlc9Emitted = buildAttestationBundleHtlc9();

const buyer = keypairFromSeed("a1".repeat(32));
const seller = keypairFromSeed("c3".repeat(32));
const keyMap = new Map<string, Uint8Array>([
  ["did:demos:buyer", buyer.publicKeyRaw],
  ["did:demos:seller", seller.publicKeyRaw],
]);
const resolve = (claim: string): Uint8Array | undefined => keyMap.get(claim);

function signBundle(base: Omit<AttestationBundle, "signatures">, signers: [string, Keypair][]): AttestationBundle {
  const signingDoc = { ...base, signatures: [] };
  const separator = DOMAIN_SEPARATOR_REGISTRY["dacs-5-bundle"];
  const signatures: BundleSignature[] = signers.map(([party, kp]) => ({
    party,
    algorithm: "ed25519",
    value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, kp.privateKey, ["signatures"]),
  }));
  return { ...base, signatures };
}

test("DACS-VERIFY-0004 fixture is byte-stable and verifies", () => {
  expect(fixtureText).toBe(JSON.stringify(emitted.bundle, null, 2) + "\n");
  expect(bundleHash(fixture)).toBe(emitted.bundleHash);
  expect(verifyBundle(fixture, resolve)).toBe("pass");
});

test("DACS-VERIFY-0004 seller-side divergent fixture is byte-stable and verifies", () => {
  expect(sellerFixtureText).toBe(JSON.stringify(sellerEmitted.bundle, null, 2) + "\n");
  expect(sellerFixture.jobId).toBe(fixture.jobId);
  expect(bundleHash(sellerFixture)).toBe(sellerEmitted.bundleHash);
  expect(sellerEmitted.bundleHash).not.toBe(emitted.bundleHash);
  expect(verifyBundle(sellerFixture, resolve)).toBe("pass");
});

test("completed bundle missing seller signature is rejected", () => {
  const missingSeller: AttestationBundle = {
    ...fixture,
    signatures: fixture.signatures.filter((s) => s.party !== "did:demos:seller"),
  };
  expect(verifyBundle(missingSeller, resolve)).toBe("fail");
});

test("aborted-by-self bundle may carry one valid signature", () => {
  const { signatures: _signatures, ...base } = fixture;
  const aborted = signBundle({ ...base, outcome: "aborted-by-self" }, [["did:demos:buyer", buyer]]);
  expect(verifyBundle(aborted, resolve)).toBe("pass");
});

test("aborted-by-self bundle without signatures is rejected", () => {
  const aborted: AttestationBundle = { ...fixture, outcome: "aborted-by-self", signatures: [] };
  expect(verifyBundle(aborted, resolve)).toBe("fail");
});

test("HTLC-9 fixture is byte-stable, verifies, and carries reveal state", () => {
  expect(htlc9FixtureText).toBe(JSON.stringify(htlc9Emitted.bundle, null, 2) + "\n");
  expect(bundleHash(htlc9Fixture)).toBe(htlc9Emitted.bundleHash);
  expect(verifyBundle(htlc9Fixture, resolve)).toBe("pass");
  const phase = htlc9Fixture.phaseSummary.find((p) => p.kind === "pay-cross-chain-htlc");
  expect(phase?.outcome).toBe("fail");
  expect(phase?.errorClass).toBe("settlement-atomicity");
  expect(phase?.txRefs?.some((tx) => tx.kind === "htlc-reveal" && tx.txHash === ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF)).toBe(true);
});

test("malformed resolved key returns error", () => {
  expect(verifyBundle(fixture, (claim) => claim === "did:demos:buyer" ? new Uint8Array([1, 2, 3]) : resolve(claim))).toBe("error");
});

test("tampered signature returns fail", () => {
  const first = fixture.signatures[0]!;
  const tampered: AttestationBundle = {
    ...fixture,
    signatures: [
      { ...first, value: first.value.slice(0, -1) + (first.value.endsWith("A") ? "B" : "A") },
      ...fixture.signatures.slice(1),
    ],
  };
  expect(verifyBundle(tampered, resolve)).toBe("fail");
});
