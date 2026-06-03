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
  ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
  buildAttestationBundle0004,
  buildAttestationBundle0004Seller,
} from "./attestation-bundle-0004.ts";

// End-to-end DACS-X dispute scenario (§11.2.1) on the existing DACS substrate.
//
// Story (§10.4.3 divergent-bundle): a buyer and seller anchored two-sided bundles
// that DISAGREE. The buyer opens a dispute; an arbitrator whose accreditation was
// agreed at agreement time adjudicates and orders a refund; the disputed session's
// reputation contribution is reweighted to zero. Every artifact is signed under the
// SIG-4 `dacs-x-*` namespace and re-verified by the read-only verifier. Output is
// written to vectors/dacs-x/ as golden fixtures (the missing dispute §14 vectors).

const BASE_TIME = 1_780_000_000_000; // fixed for reproducible vectors

// ── Parties (deterministic demo seeds → byte-stable vectors; public keys only
//    are emitted). Seeds are fixed demo constants, never real keys. ───────────
const buyer = keypairFromSeed("a1".repeat(32));
const seller = keypairFromSeed("c3".repeat(32));
const arbitrator = keypairFromSeed("33".repeat(32));

const buyerClaim = ATTESTATION_BUNDLE_0004_BUYER_CLAIM;
const sellerClaim = ATTESTATION_BUNDLE_0004_SELLER_CLAIM;
const arbitratorClaim = `did:arbitrator:acme-court`;

// ── The contested session: same jobId, two divergent §10.4 bundles ───────────
const bundle0004 = buildAttestationBundle0004();
const bundle0004Seller = buildAttestationBundle0004Seller();
const jobId = bundle0004.bundle.jobId;
const bundleHash = bundle0004.bundleHash;
const sellerBundleHash = bundle0004Seller.bundleHash;
const disputedRefs: DisputedBundleRef[] = [{ jobId, bundleHash }, { jobId, bundleHash: sellerBundleHash }];
const knownBundles: DisputedBundleRef[] = disputedRefs;

// ── Arbitration rule, agreed at agreement time (§8.4.3) ──────────────────────
const requirement: BundleRequirement = {
  requirementVersion: "1",
  required: [{ scheme: "arbitrator-accreditation", verificationRequired: true }],
  primaryClaimSelector: "did",
};
const agreedRule: ArbitrationRule = {
  requirement,
  arbitrators: [arbitratorClaim],
  policyVersion: 1,
};
const ruleRef = sha256Hex(canonicalize(agreedRule));

// ── Arbitrator identity bundle (DACS-1) satisfying the agreed requirement ────
const arbitratorBundle: IdentityBundle = {
  bundleVersion: "1",
  presentedBy: arbitratorClaim,
  presentedAt: BASE_TIME,
  claims: [
    {
      ref: arbitratorClaim,
      verifiedBy: { anchor: { kind: "sr1-root", locator: "sr1://acme-court" }, contentHash: sha256Hex("acme-did"), recipeVersion: 1 },
      issuedAt: BASE_TIME - 86_400_000,
    },
    {
      ref: "arbitrator-accreditation:iso-17000:acme",
      verifiedBy: { anchor: { kind: "sr1-root", locator: "sr1://iso-17000" }, contentHash: sha256Hex("acme-accreditation"), recipeVersion: 1 },
      issuedAt: BASE_TIME - 86_400_000,
    },
  ],
  presentation: { kind: "per-claim" },
};

// ── dispute-open: buyer signs the DisputeRecord ──────────────────────────────
const recordUnsigned: Omit<DisputeRecord, "signature"> = {
  dacsXVersion: "1",
  disputeId: "dispute-0001",
  initiator: buyerClaim,
  disputed: disputedRefs,
  contestedClaim: "divergent-bundle",
  requestedRemedy: "refund",
  arbitration: { ruleRef },
  openedAt: BASE_TIME,
};
const record: DisputeRecord = {
  ...recordUnsigned,
  signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), recordUnsigned as unknown as Record<string, unknown>, buyer.privateKey),
};

// ── DisputeOutcome: arbitrator orders a refund and signs ─────────────────────
const outcomeUnsigned: Omit<DisputeOutcome, "signature"> = {
  dacsXVersion: "1",
  disputeId: "dispute-0001",
  disputeRecordHash: disputeRecordHash(record),
  arbitrator: arbitratorClaim,
  remedy: { kind: "refund-ordered", amount: "5", asset: "usdc" },
  decidedAt: BASE_TIME + 3_600_000,
};
const outcome: DisputeOutcome = {
  ...outcomeUnsigned,
  signature: signArtifact(dacsXSeparator("dacs-x-dispute-outcome"), outcomeUnsigned as unknown as Record<string, unknown>, arbitrator.privateKey),
};

const priorReputation: SessionReputationContribution = { jobId, weight: 1 };

// ── Run the read-only verifier over the whole flow ───────────────────────────
const result = verifyDisputeFlow({
  record,
  initiatorPublicKeyRaw: buyer.publicKeyRaw,
  knownBundles,
  arbitratorBundle,
  agreedRule,
  now: BASE_TIME + 3_600_000,
  outcome,
  arbitratorPublicKeyRaw: arbitrator.publicKeyRaw,
  priorReputation,
});

// ── Negative control: a swapped arbitration rule must FAIL ───────────────────
const swappedRule: ArbitrationRule = {
  requirement: { requirementVersion: "1", required: [{ scheme: "self-signed", verificationRequired: false }] },
  arbitrators: [arbitratorClaim],
  policyVersion: 1,
};
const swapped = verifyDisputeFlow({
  record,
  initiatorPublicKeyRaw: buyer.publicKeyRaw,
  knownBundles,
  arbitratorBundle,
  agreedRule: swappedRule, // attacker presents a different rule than the pinned ruleRef
  now: BASE_TIME + 3_600_000,
  outcome,
  arbitratorPublicKeyRaw: arbitrator.publicKeyRaw,
});

// ── Report ───────────────────────────────────────────────────────────────────
console.log("DACS-X dispute scenario (§11.2.1) — §10.4.3 divergent-bundle\n");
for (const s of result.steps) console.log(`  ${s.ok ? "PASS" : "FAIL"}  ${s.name}${s.reason ? ` — ${s.reason}` : ""}`);
console.log(`\n  decision: ${result.decision.toUpperCase()}`);
console.log(`  reputation reweight: weight ${result.reweighted?.priorWeight} → ${result.reweighted?.effectiveWeight} (prior preserved; adjudicated=${result.reweighted?.adjudicated}, by=${result.reweighted?.adjudicatedBy?.slice(0, 12)}…)`);
console.log(`\n  negative control (swapped arbitration rule): decision ${swapped.decision.toUpperCase()} — ${swapped.steps.find((s) => !s.ok)?.reason}`);

// ── Emit golden vectors ──────────────────────────────────────────────────────
const outDir = join(import.meta.dir, "..", "vectors", "dacs-x");
mkdirSync(outDir, { recursive: true });
const write = (name: string, obj: unknown) => writeFileSync(join(outDir, name), JSON.stringify(obj, null, 2) + "\n");
write("arbitration-rule.json", agreedRule);
write("arbitrator-bundle.json", arbitratorBundle);
write("dispute-record.json", record);
write("dispute-outcome.json", outcome);
write("public-keys.json", { buyer: buyer.publicKeyB64u, seller: seller.publicKeyB64u, arbitrator: arbitrator.publicKeyB64u });
write("disputed-bundle.json", bundle0004.bundle);
write("disputed-bundle-seller.json", bundle0004Seller.bundle);
write("flow-result.json", { decision: result.decision, steps: result.steps, reweighted: result.reweighted });
console.log(`\n  wrote ${8} illustrative (non-normative) vectors → vectors/dacs-x/`);

const ok = result.decision === "pass" && swapped.decision === "fail";
console.log(`\n${ok ? "PASS" : "FAIL"} — DACS-X dispute prototype end-to-end`);
process.exit(ok ? 0 : 1);
