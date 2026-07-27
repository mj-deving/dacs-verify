import { describe, expect, test } from "bun:test";
import { createHash, createPrivateKey, sign } from "node:crypto";

import { canonicalize, withoutSignature } from "../src/canonicalize.ts";
import {
  evaluateEvidenceBoundSettlementVector,
  verifyEvidenceBoundFaultBundle,
  type EvidenceBoundFaultBundleInput,
} from "../src/dacs5/evidenceBoundFaultBundle.ts";
import { sha256Hex } from "../src/hash.ts";
import { buildSignedBytes } from "../src/signing.ts";

const fixturePath = new URL("../conformance/fixtures/evidence-bound-fault-bundle-forge.json", import.meta.url);
const vectorPath = new URL("../conformance/vectors/bundle-settlement-evidence-bijection-v0.4.json", import.meta.url);
const fixture = JSON.parse(await Bun.file(fixturePath).text()) as EvidenceBoundFaultBundleInput & {
  readonly artifactContentHash: string;
  readonly bundleHash: string;
  readonly fixtureHash: string;
  readonly schemaVersion: number;
};
const vectors = JSON.parse(await Bun.file(vectorPath).text()) as {
  readonly count: number;
  readonly hash: string;
  readonly vectors: readonly {
    readonly name: string;
    readonly input: Parameters<typeof evaluateEvidenceBoundSettlementVector>[0];
    readonly want: { readonly disposition: string; readonly reasonCode: string };
  }[];
};

describe("DACS Forge EvidenceBoundFaultAttestationBundle independent cross-run", () => {
  test("accepts the deterministic serialized Forge fixture", () => {
    const { fixtureHash: _fixtureHash, ...fixtureScope } = fixture;
    expect(sha256Hex(canonicalize(fixtureScope))).toBe(fixture.fixtureHash);
    expect(sha256Hex(fixture.artifactCanonicalJson)).toBe(fixture.artifactContentHash);
    expect(verifyEvidenceBoundFaultBundle(fixture)).toEqual({
      decision: "accepted",
      code: "ok",
      bundleHash: fixture.bundleHash,
    });
  });

  test("independently matches all 19 candidate SEB vectors", () => {
    expect(vectors.vectors).toHaveLength(vectors.count);
    expect(sha256Hex(canonicalize(vectors.vectors))).toBe(vectors.hash);
    for (const vector of vectors.vectors) {
      const expectedDecision = vector.want.disposition === "verified"
        ? "accepted" as const
        : vector.want.disposition === "rejected"
          ? "rejected" as const
          : "indeterminate" as const;
      expect(evaluateEvidenceBoundSettlementVector(vector.input), vector.name).toEqual({
        decision: expectedDecision,
        code: vector.want.reasonCode,
      });
    }
  });

  test("rejects legacy downgrade and a fault-domain signature replay", () => {
    const downgraded = mutateArtifact((bundle) => {
      delete bundle.evidenceBoundFaultBundleVersion;
      bundle.faultBundleVersion = "1";
    });
    expect(verifyEvidenceBoundFaultBundle({ ...fixture, artifactCanonicalJson: downgraded }))
      .toMatchObject({ decision: "rejected", code: "unsupported-discriminator" });

    const replay = mutateArtifact((bundle) => {
      bundle.signatures = signFixtureScope(bundle, "dacs-fault-bundle:v1:");
    });
    expect(verifyEvidenceBoundFaultBundle({ ...fixture, artifactCanonicalJson: replay }))
      .toMatchObject({ decision: "rejected", code: "signature-domain-or-value-mismatch" });
  });

  test("rejects a deterministic omission before unrelated uncertainty", () => {
    const omitted = mutateArtifact((bundle) => {
      (bundle.settlementEvidence as unknown[]).pop();
    });
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      artifactCanonicalJson: omitted,
      unrelatedAuthorityDisposition: "indeterminate",
    })).toMatchObject({ decision: "rejected", code: "exact-cardinality" });
  });

  test("binds resolved evidence bytes to their signed reference", () => {
    const [ref, authority] = Object.entries(fixture.resolvedEvidenceByRef)[0]!;
    const tamperedEvidence = JSON.parse(authority.artifactCanonicalJson) as Record<string, unknown>;
    tamperedEvidence.jobId = "other-job";
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      resolvedEvidenceByRef: {
        ...fixture.resolvedEvidenceByRef,
        [ref]: { ...authority, artifactCanonicalJson: canonicalize(tamperedEvidence) },
      },
    })).toMatchObject({ decision: "rejected", code: "resolved-evidence-content-hash-mismatch" });
  });

  test("rejects a signed phase summary that differs from execution authority", () => {
    const wrongPhase = mutateArtifact((bundle) => {
      (bundle.phaseSummary as Record<string, unknown>[])[0]!.index = 99;
      bundle.signatures = signFixtureScope(bundle, "dacs-evidence-bound-fault-bundle:v1:");
    });
    expect(verifyEvidenceBoundFaultBundle({ ...fixture, artifactCanonicalJson: wrongPhase }))
      .toMatchObject({ decision: "rejected", code: "phase-authority-mismatch" });
  });

  test("binds supplied public keys to raw-key claims", () => {
    const [buyerClaim, sellerClaim] = Object.keys(fixture.publicKeys);
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      publicKeys: {
        ...fixture.publicKeys,
        [sellerClaim!]: fixture.publicKeys[buyerClaim!]!,
      },
    })).toMatchObject({ decision: "rejected", code: "invalid-resolved-evidence-signer-key" });
  });

  test("keeps deterministic malformed-input rejection ahead of missing-key uncertainty", () => {
    const [missingClaim] = Object.keys(fixture.publicKeys);
    const { [missingClaim!]: _missing, ...remainingKeys } = fixture.publicKeys;
    const malformedSignature = mutateArtifact((bundle) => {
      (bundle.signatures as Record<string, unknown>[])[1]!.value = "A";
    });
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      artifactCanonicalJson: malformedSignature,
      publicKeys: remainingKeys,
    })).toMatchObject({ decision: "rejected", code: "invalid-signature-encoding" });
  });

  test("rejects malformed serialized authority inputs without throwing", () => {
    const [firstClaim] = Object.keys(fixture.publicKeys);
    expect(verifyEvidenceBoundFaultBundle({ ...fixture, artifactCanonicalJson: "null" }))
      .toMatchObject({ decision: "rejected", code: "invalid-shape" });
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      publicKeys: { ...fixture.publicKeys, [firstClaim!]: null as never },
    })).toMatchObject({ decision: "rejected", code: "invalid-signer-key" });
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      resolvedEvidenceByRef: { ...fixture.resolvedEvidenceByRef, "{}": null as never },
    })).toMatchObject({ decision: "rejected", code: "invalid-resolved-evidence-authority" });
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      expectedPhaseKeys: null as never,
    })).toMatchObject({ decision: "rejected", code: "invalid-authority-input" });
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      unrelatedAuthorityDisposition: "unknown" as never,
    })).toMatchObject({ decision: "rejected", code: "invalid-authority-input" });
  });

  test("binds copy role and resolved-evidence signer to external authority", () => {
    const wrongRole = mutateArtifact((bundle) => {
      bundle.anchoredByRole = "seller";
    });
    expect(verifyEvidenceBoundFaultBundle({ ...fixture, artifactCanonicalJson: wrongRole }))
      .toMatchObject({ decision: "rejected", code: "invalid-anchor-role" });

    const bundle = JSON.parse(fixture.artifactCanonicalJson) as Record<string, any>;
    const [buyerClaim] = Object.keys(fixture.publicKeys);
    bundle.settlementEvidence[0].signer = buyerClaim;
    bundle.phaseSummary[0].attestationRef.signer = buyerClaim;
    const changedRef = canonicalize(bundle.settlementEvidence[0]);
    const [authority] = Object.values(fixture.resolvedEvidenceByRef);
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      artifactCanonicalJson: canonicalize(bundle),
      resolvedEvidenceByRef: { [changedRef]: authority! },
    })).toMatchObject({ decision: "rejected", code: "invalid-resolved-evidence-signature" });
  });

  test("keeps missing signer and unrelated authority reads indeterminate", () => {
    const [firstClaim] = Object.keys(fixture.publicKeys);
    const { [firstClaim!]: _missing, ...remainingKeys } = fixture.publicKeys;
    expect(verifyEvidenceBoundFaultBundle({ ...fixture, publicKeys: remainingKeys }))
      .toMatchObject({ decision: "indeterminate", code: "signer-key-unavailable" });
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      unrelatedAuthorityDisposition: "indeterminate",
    })).toMatchObject({ decision: "indeterminate", code: "unrelated-authority-indeterminate" });
  });

  test("rejects signed evidence whose outcome is not terminal", () => {
    const bundle = JSON.parse(fixture.artifactCanonicalJson) as Record<string, any>;
    const originalAuthority = Object.values(fixture.resolvedEvidenceByRef)[0]!;
    const evidence = JSON.parse(originalAuthority.artifactCanonicalJson) as Record<string, any>;
    evidence.outcome = "pending";
    const replacement = signEvidenceArtifact(
      evidence,
      "dacs4:delivery-evidence:01J00000000000000000000000:pending",
      "3:deliver-storage-program",
    );
    bundle.settlementEvidence = [replacement.reference];
    bundle.phaseSummary[0].attestationRef = replacement.reference;
    bundle.signatures = signFixtureScope(bundle, "dacs-evidence-bound-fault-bundle:v1:");

    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      artifactCanonicalJson: canonicalize(bundle),
      resolvedEvidenceByRef: {
        [canonicalize(replacement.reference)]: replacement.authority,
      },
    })).toMatchObject({ decision: "rejected", code: "invalid-resolved-evidence-outcome" });
  });

  test("uses per-reference execution authority before mapping uncertainty", () => {
    const bundle = JSON.parse(fixture.artifactCanonicalJson) as Record<string, any>;
    const originalAuthority = Object.values(fixture.resolvedEvidenceByRef)[0]!;
    const evidence = JSON.parse(originalAuthority.artifactCanonicalJson) as Record<string, any>;
    const phase3 = signEvidenceArtifact(
      evidence,
      "dacs4:delivery-evidence:01J00000000000000000000000:3",
      "3:deliver-storage-program",
    );
    const phase4 = signEvidenceArtifact(
      { ...evidence, observedAt: evidence.observedAt + 1, deliverableContentHash: "9".repeat(64) },
      "dacs4:delivery-evidence:01J00000000000000000000000:4",
      "4:deliver-storage-program",
    );
    bundle.phaseSummary = [
      { index: 3, kind: "deliver-storage-program", outcome: "ok", attestationRef: phase4.reference },
      { index: 4, kind: "deliver-storage-program", outcome: "ok", attestationRef: phase3.reference },
    ];
    bundle.settlementEvidence = [phase3.reference, phase4.reference];
    bundle.signatures = signFixtureScope(bundle, "dacs-evidence-bound-fault-bundle:v1:");
    const authorities = {
      [canonicalize(phase3.reference)]: phase3.authority,
      [canonicalize(phase4.reference)]: phase4.authority,
    };
    const input = {
      ...fixture,
      artifactCanonicalJson: canonicalize(bundle),
      expectedPhaseKeys: ["3:deliver-storage-program", "4:deliver-storage-program"],
      resolvedEvidenceByRef: authorities,
    };
    expect(verifyEvidenceBoundFaultBundle(input))
      .toMatchObject({ decision: "rejected", code: "pointer-agreement" });

    expect(verifyEvidenceBoundFaultBundle({
      ...input,
      resolvedEvidenceByRef: {
        ...authorities,
        [canonicalize(phase3.reference)]: { ...phase3.authority, phaseKey: null },
      },
    })).toMatchObject({ decision: "rejected", code: "pointer-agreement" });
  });

  test("rejects impossible partial phase mappings and null-index pointer conflicts", () => {
    const originalAuthority = Object.values(fixture.resolvedEvidenceByRef)[0]!;
    const evidence = JSON.parse(originalAuthority.artifactCanonicalJson) as Record<string, any>;
    const payKnown = signEvidenceArtifact(
      { ...evidence, phase: "pay-dem" },
      "dacs4:payment-evidence:01J00000000000000000000000:2",
      "2:pay-dem",
    );
    const payUnknown = signEvidenceArtifact(
      { ...evidence, phase: "pay-dem", observedAt: evidence.observedAt + 1 },
      "dacs4:payment-evidence:01J00000000000000000000000:unknown",
      null,
    );
    const impossible = JSON.parse(fixture.artifactCanonicalJson) as Record<string, any>;
    impossible.phaseSummary = [
      { index: 2, kind: "pay-dem", outcome: "ok" },
      { index: 3, kind: "deliver-storage-program", outcome: "ok" },
    ];
    impossible.settlementEvidence = [payKnown.reference, payUnknown.reference];
    impossible.signatures = signFixtureScope(impossible, "dacs-evidence-bound-fault-bundle:v1:");
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      artifactCanonicalJson: canonicalize(impossible),
      expectedPhaseKeys: ["2:pay-dem", "3:deliver-storage-program"],
      resolvedEvidenceByRef: {
        [canonicalize(payKnown.reference)]: payKnown.authority,
        [canonicalize(payUnknown.reference)]: payUnknown.authority,
      },
    })).toMatchObject({ decision: "rejected", code: "exact-bijection" });

    const deliveryUnknown = signEvidenceArtifact(
      evidence,
      "dacs4:delivery-evidence:01J00000000000000000000000:unknown",
      null,
    );
    const pointerConflict = JSON.parse(fixture.artifactCanonicalJson) as Record<string, any>;
    pointerConflict.phaseSummary = [
      { index: 2, kind: "pay-dem", outcome: "ok", attestationRef: deliveryUnknown.reference },
      { index: 3, kind: "deliver-storage-program", outcome: "ok" },
    ];
    pointerConflict.settlementEvidence = [payKnown.reference, deliveryUnknown.reference];
    pointerConflict.signatures = signFixtureScope(pointerConflict, "dacs-evidence-bound-fault-bundle:v1:");
    expect(verifyEvidenceBoundFaultBundle({
      ...fixture,
      artifactCanonicalJson: canonicalize(pointerConflict),
      expectedPhaseKeys: ["2:pay-dem", "3:deliver-storage-program"],
      resolvedEvidenceByRef: {
        [canonicalize(payKnown.reference)]: payKnown.authority,
        [canonicalize(deliveryUnknown.reference)]: deliveryUnknown.authority,
      },
    })).toMatchObject({ decision: "rejected", code: "pointer-agreement" });
  });
});

function mutateArtifact(mutate: (bundle: Record<string, any>) => void): string {
  const bundle = JSON.parse(fixture.artifactCanonicalJson) as Record<string, any>;
  mutate(bundle);
  return canonicalize(bundle);
}

function signFixtureScope(bundle: Record<string, any>, domain: string) {
  const scope = withoutSignature(bundle, "signatures", "anchoredByRole");
  const bundleHash = sha256Hex(canonicalize(scope));
  return [
    ["buyer", "reference-dacs-template-buyer-v1"],
    ["seller", "reference-dacs-template-listing-v1"],
  ].map(([role, seedLabel]) => {
    const party = (bundle.parties as Record<string, string>[]).find((entry) => entry.role === role)!;
    return {
      party: party.primaryClaim,
      algorithm: "ed25519",
      value: sign(null, buildSignedBytes(domain, bundleHash), privateKeyFor(seedLabel!)).toString("base64url"),
    };
  });
}

function signEvidenceArtifact(
  evidence: Record<string, any>,
  anchorLocator: string,
  phaseKey: string | null,
) {
  const signer = evidence.signature.signer as string;
  const scope = withoutSignature(evidence, "signature");
  const contentHash = sha256Hex(canonicalize(scope));
  const artifactCanonicalJson = canonicalize({
    ...scope,
    signature: {
      algorithm: "ed25519",
      signer,
      value: sign(
        null,
        buildSignedBytes("dacs-evidence:v1:", contentHash),
        privateKeyFor("reference-dacs-template-listing-v1"),
      ).toString("base64url"),
    },
  });
  return {
    reference: {
      anchor: { kind: "storage-program", locator: anchorLocator },
      contentHash,
      signer,
    },
    authority: { artifactCanonicalJson, phaseKey },
  } as const;
}

function privateKeyFor(seedLabel: string) {
  const seed = createHash("sha256").update(seedLabel).digest();
  return createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
}
