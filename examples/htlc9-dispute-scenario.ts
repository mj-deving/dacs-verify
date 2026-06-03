import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { dacsXSeparator } from "../src/dacsx/separators.ts";
import { verifyDisputeFlow } from "../src/dacsx/flow.ts";
import { disputeRecordHash } from "../src/dacsx/dispute.ts";
import type {
  DisputeRecord,
  DisputeOutcome,
  ArbitrationRule,
  DisputedBundleRef,
  SessionReputationContribution,
} from "../src/dacsx/types.ts";
import type { IdentityBundle, BundleRequirement } from "../src/dacs1.ts";
import { keypairFromSeed, signArtifact } from "./issuer-kit.ts";
import {
  ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
  ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF,
  buildAttestationBundleHtlc9,
} from "./attestation-bundle-0004.ts";

// THE SETTLEMENT → DISPUTE SEAM (HTLC-9, §9.5.4 / §9.8).
//
// DACS settlement specifies the asymmetric cross-chain state
// `dest-revealed-source-unclaimed` — the payee was paid on the DESTINATION chain
// (the HTLC preimage was revealed there) but the SOURCE-chain claim failed — and
// it MUST surface as outcome:"failure" + an `htlc-reveal` txRef, closed by a
// §9.7.1 `correction` amendment. But §9.8/HTLC-9 DEFER that closure to "dispute
// or manual intervention" — i.e. DACS-X, which does not exist in v0.1.
//
// This scenario is that deferral, wired: a dispute over an asymmetric HTLC
// settlement → a credentialed arbitrator → a `correction-ordered` DisputeOutcome
// (NEVER a refund — that would double-pay the payee) → reputation voided. This is
// DACS-X's concrete first use-case and its coordination point with the HTLC lane.

const BASE_TIME = 1_780_000_000_000;

const payer = keypairFromSeed("a1".repeat(32)); // buyer / source-chain payer
const arbitrator = keypairFromSeed("55".repeat(32));

const payerClaim = ATTESTATION_BUNDLE_0004_BUYER_CLAIM;
const arbitratorClaim = `did:arbitrator:settlement-court`;

// The contested session: a cross-chain HTLC settlement that hit the HTLC-9
// asymmetric state. The bundle records outcome:"failure" with the structured
// reason and the destination-chain reveal txRef (§9.5.4 / §9.8).
const bundleHtlc9 = buildAttestationBundleHtlc9();
const jobId = bundleHtlc9.bundle.jobId;
const revealTxRef = ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF;
const bundleHash = bundleHtlc9.bundleHash;
const knownBundles: DisputedBundleRef[] = [{ jobId, bundleHash }];

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
  presentedAt: BASE_TIME,
  claims: [
    { ref: arbitratorClaim, verifiedBy: { anchor: { kind: "sr1-root", locator: "sr1://settlement-court" }, contentHash: sha256Hex("court"), recipeVersion: 1 }, issuedAt: BASE_TIME - 86_400_000 },
    { ref: "arbitrator-accreditation:settlement-panel", verifiedBy: { anchor: { kind: "sr1-root", locator: "sr1://accr" }, contentHash: sha256Hex("accr"), recipeVersion: 1 }, issuedAt: BASE_TIME - 86_400_000 },
  ],
  presentation: { kind: "per-claim" },
};

const recordUnsigned: Omit<DisputeRecord, "signature"> = {
  dacsXVersion: "1",
  disputeId: "dispute-htlc9-0001",
  initiator: payerClaim,
  disputed: [{ jobId, bundleHash }],
  contestedClaim: "asymmetric-settlement",
  requestedRemedy: "no-fault", // payer asks for the record to be corrected, not refunded
  arbitration: { ruleRef },
  openedAt: BASE_TIME,
};
const record: DisputeRecord = {
  ...recordUnsigned,
  signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), recordUnsigned as unknown as Record<string, unknown>, payer.privateKey),
};

// The arbitrator orders a `correction` amendment — NOT a refund.
const outcomeUnsigned: Omit<DisputeOutcome, "signature"> = {
  dacsXVersion: "1",
  disputeId: "dispute-htlc9-0001",
  disputeRecordHash: disputeRecordHash(record),
  arbitrator: arbitratorClaim,
  remedy: { kind: "correction-ordered", correctedOutcome: "failure", reason: "dest-revealed-source-unclaimed", revealTxRef },
  decidedAt: BASE_TIME + 3_600_000,
};
const outcome: DisputeOutcome = {
  ...outcomeUnsigned,
  signature: signArtifact(dacsXSeparator("dacs-x-dispute-outcome"), outcomeUnsigned as unknown as Record<string, unknown>, arbitrator.privateKey),
};

const priorReputation: SessionReputationContribution = { jobId, weight: 1 };

const result = verifyDisputeFlow({
  record,
  initiatorPublicKeyRaw: payer.publicKeyRaw,
  knownBundles,
  arbitratorBundle,
  agreedRule,
  now: BASE_TIME + 3_600_000,
  outcome,
  arbitratorPublicKeyRaw: arbitrator.publicKeyRaw,
  priorReputation,
});

console.log("DACS-X × HTLC-9 — the settlement→dispute seam (§9.5.4 / §9.8)\n");
console.log("  contested: asymmetric cross-chain settlement (dest-revealed-source-unclaimed)");
for (const s of result.steps) console.log(`  ${s.ok ? "PASS" : "FAIL"}  ${s.name}${s.reason ? ` — ${s.reason}` : ""}`);
console.log(`\n  decision: ${result.decision.toUpperCase()}`);
console.log(`  remedy: correction amendment (NOT a refund — would double-pay the payee paid on the dest chain)`);
console.log(`  reputation: weight ${result.reweighted?.priorWeight} → ${result.reweighted?.effectiveWeight} (HTLC-9 failure; reason rides the outcome hash)`);

const outDir = join(import.meta.dir, "..", "vectors", "dacs-x", "htlc9");
mkdirSync(outDir, { recursive: true });
const write = (name: string, obj: unknown) => writeFileSync(join(outDir, name), JSON.stringify(obj, null, 2) + "\n");
write("htlc9-bundle.json", bundleHtlc9.bundle);
write("dispute-record.json", record);
write("dispute-outcome.json", outcome);
write("flow-result.json", { decision: result.decision, steps: result.steps, reweighted: result.reweighted });
write("public-keys.json", { payer: payer.publicKeyB64u, arbitrator: arbitrator.publicKeyB64u, bundleParties: bundleHtlc9.publicKeys });

const ok = result.decision === "pass" && result.reweighted?.effectiveWeight === 0;
console.log(`\n  wrote 5 illustrative (non-normative) vectors → vectors/dacs-x/htlc9/`);
console.log(`\n${ok ? "PASS" : "FAIL"} — DACS-X closes the HTLC-9 asymmetric-settlement state via a correction amendment`);
process.exit(ok ? 0 : 1);
