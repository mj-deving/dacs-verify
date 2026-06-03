import { test, expect } from "bun:test";
import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex, contentHash } from "../src/hash.ts";
import { isRegisteredSeparator, verifyArtifactSignatureWithSeparator } from "../src/signing.ts";
import type { IdentityBundle, BundleRequirement } from "../src/dacs1.ts";
import {
  DACS_X_SEPARATORS,
  dacsXSeparator,
  verifyDisputeRecord,
  verifyArbitratorCredential,
  verifyDisputeOutcome,
  validateRemedy,
  reputationReweight,
  disputeRecordHash,
} from "../src/dacsx/index.ts";
import type { DisputeRecord, DisputeOutcome, ArbitrationRule, RemedyDecision } from "../src/dacsx/index.ts";
import { keypairFromSeed, signArtifact } from "../examples/issuer-kit.ts";

// ── Shared fixtures (deterministic seeds) ────────────────────────────────────
const NOW = 1_780_000_000_000;
const buyer = keypairFromSeed("aa".repeat(32));
const arbitrator = keypairFromSeed("bb".repeat(32));
const attacker = keypairFromSeed("cc".repeat(32));

const buyerClaim = "did:demos:buyer";
const arbitratorClaim = "did:arbitrator:court";
const jobId = "job-1";
const bundleHash = contentHash({ bundleVersion: "1", jobId, outcome: "divergent" });
const sellerBundleHash = contentHash({ bundleVersion: "1", jobId, outcome: "seller-divergent" });
const disputedRefs = [{ jobId, bundleHash }, { jobId, bundleHash: sellerBundleHash }];
const knownBundles = disputedRefs;

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
    { ref: "arbitrator-accreditation:iso-17000", verifiedBy: { anchor: { kind: "sr1-root", locator: "y" }, contentHash: sha256Hex("b"), recipeVersion: 1 }, issuedAt: NOW - 1000 },
  ],
  presentation: {},
};

function makeRecord(signer = buyer, over: Partial<Omit<DisputeRecord, "signature">> = {}): DisputeRecord {
  const unsigned: Omit<DisputeRecord, "signature"> = {
    dacsXVersion: "1",
    disputeId: "d1",
    initiator: buyerClaim,
    disputed: disputedRefs,
    contestedClaim: "divergent-bundle",
    requestedRemedy: "refund",
    arbitration: { ruleRef },
    openedAt: NOW,
    ...over,
  };
  return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
}

function makeOutcome(record: DisputeRecord, signer = arbitrator, remedy: RemedyDecision = { kind: "refund-ordered", amount: "5", asset: "usdc" }, over: Partial<Omit<DisputeOutcome, "signature">> = {}): DisputeOutcome {
  const unsigned: Omit<DisputeOutcome, "signature"> = {
    dacsXVersion: "1",
    disputeId: "d1",
    disputeRecordHash: disputeRecordHash(record),
    arbitrator: arbitratorClaim,
    remedy,
    decidedAt: NOW + 1000,
    ...over,
  };
  return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-outcome"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
}

// ── ISC-19 / ISC-39: SIG-4 namespace, disjoint from the §7.7 registry ────────
test("ISC-19/39: DACS-X separators use the dacs-x-* namespace and are NOT in the §7.7 registry", () => {
  for (const sep of Object.values(DACS_X_SEPARATORS)) {
    expect(sep.startsWith("dacs-x-")).toBe(true);
    expect(isRegisteredSeparator(sep)).toBe(false);
  }
});

// ── ISC-21 / ISC-23: dispute-record signature ────────────────────────────────
test("ISC-21: a valid DisputeRecord verifies against the initiator's key", () => {
  const record = makeRecord(buyer);
  expect(verifyDisputeRecord(record, buyer.publicKeyRaw, knownBundles).ok).toBe(true);
});

test("ISC-23: a DisputeRecord signed by the wrong key is rejected", () => {
  const record = makeRecord(attacker); // attacker signs, but we verify against buyer's key
  expect(verifyDisputeRecord(record, buyer.publicKeyRaw, knownBundles).ok).toBe(false);
});

// ── ISC-22: bundle pinning ───────────────────────────────────────────────────
test("ISC-22: a DisputeRecord pinned to a different bundle hash is rejected", () => {
  const record = makeRecord(buyer, { disputed: [{ jobId, bundleHash }, { jobId, bundleHash: "00".repeat(32) }] });
  const res = verifyDisputeRecord(record, buyer.publicKeyRaw, knownBundles);
  expect(res.ok).toBe(false);
  if (!res.ok) expect(res.reason).toContain("bundle hash mismatch");
});

test("ISC-22: divergent-bundle disputes require two hashes for the same job", () => {
  const single = makeRecord(buyer, { disputed: [{ jobId, bundleHash }] });
  const duplicate = makeRecord(buyer, { disputed: [{ jobId, bundleHash }, { jobId, bundleHash }] });
  const crossJob = makeRecord(buyer, { disputed: [{ jobId, bundleHash }, { jobId: "job-2", bundleHash: sellerBundleHash }] });

  expect(verifyDisputeRecord(single, buyer.publicKeyRaw, knownBundles).ok).toBe(false);
  expect(verifyDisputeRecord(duplicate, buyer.publicKeyRaw, knownBundles).ok).toBe(false);
  expect(verifyDisputeRecord(crossJob, buyer.publicKeyRaw, [...knownBundles, { jobId: "job-2", bundleHash: sellerBundleHash }]).ok).toBe(false);
});

test("ISC-22: a DisputeRecord with no disputed bundles is rejected", () => {
  const record = makeRecord(buyer, { disputed: [] });
  expect(verifyDisputeRecord(record, buyer.publicKeyRaw, knownBundles).ok).toBe(false);
});

// ── ISC-24 / ISC-25: arbitrator credentialing ────────────────────────────────
test("ISC-24: arbitrator credential verifies via reused DACS-1/2 matchRequirement", () => {
  const record = makeRecord(buyer);
  expect(verifyArbitratorCredential(arbitratorBundle, record, agreedRule, NOW).ok).toBe(true);
});

test("ISC-25: a post-hoc arbitration-rule swap is rejected (rule-ref mismatch)", () => {
  const record = makeRecord(buyer);
  const swapped: ArbitrationRule = {
    requirement: { requirementVersion: "1", required: [{ scheme: "self-signed", verificationRequired: false }] },
    arbitrators: [arbitratorClaim],
    policyVersion: 1,
  };
  const res = verifyArbitratorCredential(arbitratorBundle, record, swapped, NOW);
  expect(res.ok).toBe(false);
  if (!res.ok) expect(res.reason).toContain("rule-ref mismatch");
});

test("ISC-24: an arbitrator outside the agreed allow-set is rejected", () => {
  const record = makeRecord(buyer);
  const other: IdentityBundle = { ...arbitratorBundle, presentedBy: "did:arbitrator:rogue" };
  // rule-ref still matches (same agreedRule); allow-set check rejects.
  const res = verifyArbitratorCredential(other, record, agreedRule, NOW);
  expect(res.ok).toBe(false);
});

// ── ISC-26 / ISC-27 / ISC-32: dispute-outcome signature & binding ────────────
test("ISC-26: a valid arbitrator-signed DisputeOutcome verifies", () => {
  const record = makeRecord(buyer);
  const outcome = makeOutcome(record);
  expect(verifyDisputeOutcome(outcome, arbitrator.publicKeyRaw, record).ok).toBe(true);
});

test("ISC-27: a DisputeOutcome whose disputeRecordHash mismatches is rejected", () => {
  const record = makeRecord(buyer);
  const outcome = makeOutcome(record, arbitrator, { kind: "refund-ordered", amount: "5", asset: "usdc" }, { disputeRecordHash: "00".repeat(32) });
  const res = verifyDisputeOutcome(outcome, arbitrator.publicKeyRaw, record);
  expect(res.ok).toBe(false);
  if (!res.ok) expect(res.reason).toContain("disputeRecordHash");
});

test("ISC-32: cross-artifact replay — a dispute-record signature does NOT verify as a dispute-outcome", () => {
  const unsigned = { disputeId: "d1", payload: 1 };
  const sig = signArtifact(dacsXSeparator("dacs-x-dispute-record"), unsigned, arbitrator.privateKey);
  const res = verifyArtifactSignatureWithSeparator({
    separator: dacsXSeparator("dacs-x-dispute-outcome"), // verify under the OTHER separator
    doc: { ...unsigned, signature: sig },
    publicKeyRaw: arbitrator.publicKeyRaw,
    signatureRaw: new Uint8Array(Buffer.from(sig, "base64url")),
    signatureFields: ["signature"],
  });
  expect(res.ok).toBe(false);
});

// ── ISC-28 / ISC-29 / ISC-30: remedy validation ──────────────────────────────
test("ISC-28: refund remedy enforces CD-1 canonical + §9.3 positivity", () => {
  expect(validateRemedy({ kind: "refund-ordered", amount: "5", asset: "usdc" }).ok).toBe(true);
  expect(validateRemedy({ kind: "refund-ordered", amount: "5.0", asset: "usdc" }).ok).toBe(false); // not CD-1 canonical
  expect(validateRemedy({ kind: "refund-ordered", amount: "0", asset: "usdc" }).ok).toBe(false); // not > 0
  expect(validateRemedy({ kind: "refund-ordered", amount: "-1", asset: "usdc" }).ok).toBe(false);
  expect(validateRemedy({ kind: "refund-ordered", amount: "5", asset: "" }).ok).toBe(false); // missing asset
});

test("ISC-29: reputation-correction enforces a CD-1, bounded [0,1] multiplier", () => {
  expect(validateRemedy({ kind: "reputation-corrected", weightMultiplier: "0.5", favors: "initiator" }).ok).toBe(true);
  expect(validateRemedy({ kind: "reputation-corrected", weightMultiplier: "1.5", favors: "initiator" }).ok).toBe(false); // > 1
  expect(validateRemedy({ kind: "reputation-corrected", weightMultiplier: "0.50", favors: "initiator" }).ok).toBe(false); // not canonical
});

test("ISC-30: no-fault remedy is valid", () => {
  expect(validateRemedy({ kind: "no-fault" }).ok).toBe(true);
});

test("ISC-42: correction-ordered remedy (HTLC-9 seam) requires outcome=failure + reason + revealTxRef", () => {
  expect(validateRemedy({ kind: "correction-ordered", correctedOutcome: "failure", reason: "dest-revealed-source-unclaimed", revealTxRef: "polygon-amoy:0xreveal" }).ok).toBe(true);
  // MUST NOT close as a refund/success — that double-pays the payee already paid on the dest chain (§9.8)
  expect(validateRemedy({ kind: "correction-ordered", correctedOutcome: "success", reason: "x", revealTxRef: "y" } as unknown as RemedyDecision).ok).toBe(false);
  // missing htlc-reveal txRef rejected
  expect(validateRemedy({ kind: "correction-ordered", correctedOutcome: "failure", reason: "dest-revealed-source-unclaimed", revealTxRef: "" }).ok).toBe(false);
});

test("ISC-43: correction-ordered reweight voids the contribution (HTLC-9 failure), prior preserved", () => {
  const record = makeRecord(buyer);
  const corr = makeOutcome(record, arbitrator, { kind: "correction-ordered", correctedOutcome: "failure", reason: "dest-revealed-source-unclaimed", revealTxRef: "polygon-amoy:0xreveal" });
  const re = reputationReweight({ jobId, weight: 1 }, corr);
  expect(re.effectiveWeight).toBe(0);
  expect(re.priorWeight).toBe(1);
  expect(re.adjudicated).toBe(true);
});

// ── ISC-31: reputation reweight (supersede-with-provenance) ───────────────────
test("ISC-31: a refund voids the disputed contribution and records provenance", () => {
  const record = makeRecord(buyer);
  const outcome = makeOutcome(record);
  const re = reputationReweight({ jobId, weight: 1 }, outcome);
  expect(re.effectiveWeight).toBe(0);
  expect(re.priorWeight).toBe(1); // prior preserved (non-destructive audit trail)
  expect(re.adjudicated).toBe(true);
  expect(re.adjudicatedBy).toBeTruthy();
});

test("ISC-31: a reputation-correction multiplies the weight; no-fault leaves it but marks adjudicated", () => {
  const record = makeRecord(buyer);
  const corrected = makeOutcome(record, arbitrator, { kind: "reputation-corrected", weightMultiplier: "0.5", favors: "initiator" });
  expect(reputationReweight({ jobId, weight: 1 }, corrected).effectiveWeight).toBeCloseTo(0.5);
  const noFault = makeOutcome(record, arbitrator, { kind: "no-fault" });
  const re = reputationReweight({ jobId, weight: 1 }, noFault);
  expect(re.effectiveWeight).toBe(1);
  expect(re.priorWeight).toBe(1);
  expect(re.adjudicated).toBe(true);
});

// ── ISC-20: the generic separator path agrees with the registered path ───────
test("ISC-20: verifyArtifactSignatureWithSeparator matches the registered-kind path", () => {
  // Sign a registered-kind doc and verify via the generic path with the same separator.
  const unsigned = { listingId: "abc", listingVersion: 1 };
  const sep = "dacs-listing:v1:";
  const sig = signArtifact(sep, unsigned, buyer.privateKey);
  const res = verifyArtifactSignatureWithSeparator({
    separator: sep,
    doc: { ...unsigned, signature: sig },
    publicKeyRaw: buyer.publicKeyRaw,
    signatureRaw: new Uint8Array(Buffer.from(sig, "base64url")),
    signatureFields: ["signature"],
  });
  expect(res.ok).toBe(true);
});
