import { test, expect } from "bun:test";
import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex, contentHash } from "../src/hash.ts";
import type { IdentityBundle, BundleRequirement } from "../src/dacs1.ts";
import {
  dacsXSeparator,
  verifyDisputeFlow,
  disputeRecordHash,
} from "../src/dacsx/index.ts";
import type { DisputeRecord, DisputeOutcome, ArbitrationRule, RemedyDecision, DisputeFlowInput } from "../src/dacsx/index.ts";
import { keypairFromSeed, signArtifact } from "../examples/issuer-kit.ts";

const NOW = 1_780_000_000_000;
const buyer = keypairFromSeed("a1".repeat(32));
const arbitrator = keypairFromSeed("b2".repeat(32));

const buyerClaim = "did:demos:buyer";
const arbitratorClaim = "did:arbitrator:court";
const jobId = "job-flow";
const bundleHash = contentHash({ bundleVersion: "1", jobId, outcome: "divergent" });
const knownBundles = [{ jobId, bundleHash }];

const requirement: BundleRequirement = {
  requirementVersion: "1",
  required: [{ scheme: "arbitrator-accreditation", verificationRequired: true }],
  primaryClaimSelector: "did",
};
const agreedRule: ArbitrationRule = { requirement, arbitrators: [arbitratorClaim], policyVersion: 1 };
const ruleRef = sha256Hex(canonicalize(agreedRule));

const arbitratorBundle: IdentityBundle = {
  bundleVersion: "1",
  presentedBy: arbitratorClaim,
  presentedAt: NOW,
  claims: [
    { ref: arbitratorClaim, verifiedBy: { anchor: { kind: "sr1-root", locator: "x" }, contentHash: sha256Hex("a"), recipeVersion: 1 }, issuedAt: NOW - 1000 },
    { ref: "arbitrator-accreditation:iso", verifiedBy: { anchor: { kind: "sr1-root", locator: "y" }, contentHash: sha256Hex("b"), recipeVersion: 1 }, issuedAt: NOW - 1000 },
  ],
  presentation: {},
};

function makeRecord(signer = buyer): DisputeRecord {
  const unsigned: Omit<DisputeRecord, "signature"> = {
    dacsXVersion: "1",
    disputeId: "d1",
    initiator: buyerClaim,
    disputed: [{ jobId, bundleHash }],
    contestedClaim: "divergent-bundle",
    requestedRemedy: "refund",
    arbitration: { ruleRef },
    openedAt: NOW,
  };
  return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
}

function makeOutcome(record: DisputeRecord, signer = arbitrator, remedy: RemedyDecision = { kind: "refund-ordered", amount: "5", asset: "usdc" }): DisputeOutcome {
  const unsigned: Omit<DisputeOutcome, "signature"> = {
    dacsXVersion: "1",
    disputeId: "d1",
    disputeRecordHash: disputeRecordHash(record),
    arbitrator: arbitratorClaim,
    remedy,
    decidedAt: NOW + 1000,
  };
  return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-outcome"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
}

function baseInput(): DisputeFlowInput {
  const record = makeRecord();
  return {
    record,
    initiatorPublicKeyRaw: buyer.publicKeyRaw,
    knownBundles,
    arbitratorBundle,
    agreedRule,
    now: NOW + 1000,
    outcome: makeOutcome(record),
    arbitratorPublicKeyRaw: arbitrator.publicKeyRaw,
    priorReputation: { jobId, weight: 1 },
  };
}

// ── ISC-33 / ISC-34: the four decisions + happy path ─────────────────────────
test("ISC-34: happy-path dispute flow returns PASS and reweights reputation to 0", () => {
  const res = verifyDisputeFlow(baseInput());
  expect(res.decision).toBe("pass");
  expect(res.reweighted?.effectiveWeight).toBe(0);
  expect(res.reweighted?.priorWeight).toBe(1);
  expect(res.reweighted?.adjudicated).toBe(true);
  expect(res.steps.every((s) => s.ok)).toBe(true);
});

test("ISC-33: an open dispute with no outcome yet returns INDETERMINATE", () => {
  const input = baseInput();
  delete input.outcome;
  delete input.arbitratorPublicKeyRaw;
  expect(verifyDisputeFlow(input).decision).toBe("indeterminate");
});

test("ISC-33: a bad dispute-record returns FAIL", () => {
  const input = baseInput();
  input.initiatorPublicKeyRaw = arbitrator.publicKeyRaw; // wrong key for the record
  expect(verifyDisputeFlow(input).decision).toBe("fail");
});

test("ISC-33: a malformed public key returns ERROR, not a false-negative FAIL", () => {
  // A non-32-byte key is unparseable input the verifier cannot evaluate. The
  // key-length guard throws → the flow surfaces `error` (the 4-value model's
  // can't-verify class), NOT `fail` (verified-invalid). Guards against the
  // classic false-negative where malformed input is reported as invalid.
  const input = baseInput();
  input.initiatorPublicKeyRaw = new Uint8Array([1, 2, 3]);
  expect(verifyDisputeFlow(input).decision).toBe("error");
});

test("ISC-33: a structurally unparseable artifact returns ERROR (a step threw uncaught)", () => {
  // A claim reference with no scheme makes schemeOf() throw deep inside
  // matchRequirement — the verifier cannot evaluate the input at all, so the
  // flow surfaces `error` (distinct from a definite `fail`).
  const input = baseInput();
  input.arbitratorBundle = {
    ...arbitratorBundle,
    claims: [{ ref: "no-scheme-here", issuedAt: NOW - 1000, verifiedBy: { anchor: { kind: "sr1-root", locator: "x" }, contentHash: sha256Hex("a"), recipeVersion: 1 } }],
  };
  expect(verifyDisputeFlow(input).decision).toBe("error");
});

// ── ISC-35: adversarial suite ────────────────────────────────────────────────
test("ISC-35: swapped arbitration rule → FAIL", () => {
  const input = baseInput();
  input.agreedRule = { requirement: { requirementVersion: "1", required: [{ scheme: "self-signed", verificationRequired: false }] }, arbitrators: [arbitratorClaim], policyVersion: 1 };
  const res = verifyDisputeFlow(input);
  expect(res.decision).toBe("fail");
  expect(res.steps.find((s) => s.name === "arbitrator-credential")?.ok).toBe(false);
});

test("ISC-35: outcome signed by the wrong key → FAIL", () => {
  const input = baseInput();
  input.arbitratorPublicKeyRaw = buyer.publicKeyRaw; // outcome was signed by arbitrator, verify w/ buyer
  expect(verifyDisputeFlow(input).decision).toBe("fail");
});

test("ISC-35: outcome with a non-canonical refund amount → FAIL", () => {
  const input = baseInput();
  const record = input.record;
  input.outcome = makeOutcome(record, arbitrator, { kind: "refund-ordered", amount: "5.00", asset: "usdc" });
  expect(verifyDisputeFlow(input).decision).toBe("fail");
});

test("ISC-35: dispute pinned to an unknown bundle → FAIL", () => {
  const input = baseInput();
  input.knownBundles = [{ jobId: "other-job", bundleHash }];
  expect(verifyDisputeFlow(input).decision).toBe("fail");
});

test("ISC-44: HTLC-9 asymmetric-settlement dispute closes via correction amendment (flow PASS, reputation voided)", () => {
  const input = baseInput();
  input.outcome = makeOutcome(input.record, arbitrator, {
    kind: "correction-ordered",
    correctedOutcome: "failure",
    reason: "dest-revealed-source-unclaimed",
    revealTxRef: "polygon-amoy:0xreveal",
  });
  const res = verifyDisputeFlow(input);
  expect(res.decision).toBe("pass");
  expect(res.reweighted?.effectiveWeight).toBe(0);
});
