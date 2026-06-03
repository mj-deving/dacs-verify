#!/usr/bin/env bun
/**
 * DACS v0.1 — conformance vector runner.  (proposed / non-normative · MIT)
 *
 * Executes the golden conformance vectors against this independent verifier
 * (github.com/mj-deving/dacs-verify) and prints a per-case PASS/FAIL report.
 *
 * Deterministic by construction: every key and signature is derived from a
 * fixed public seed via examples/issuer-kit.ts, and every timestamp is pinned —
 * so each run is byte-stable. No private key material is stored; seeds are
 * public test material.
 *
 *   bun conformance/run.ts          run all vectors
 *   bun conformance/run.ts --emit   (re)write MANIFEST.json + vectors/golden.json
 *
 * Golden surface: 24 primitive checks + one §10.4 bundle area (4 checks) + 18
 * dispute / disclosure checks, all byte-stable and accepted by this reference
 * verifier.
 *
 * An external implementer can read MANIFEST.json (the case index) and
 * vectors/golden.json (the pinned outputs), point their own DACS verifier at the
 * same inputs, and diff. See README.md for the spec §-map.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalize, withoutSignature } from "../src/canonicalize.ts";
import { sha256Hex, contentHash } from "../src/hash.ts";
import { canonicalDecimal, assertPositiveAmount } from "../src/decimal.ts";
import {
  DOMAIN_SEPARATOR_REGISTRY,
  verifyArtifactSignature,
  isRegisteredSeparator,
} from "../src/signing.ts";
import {
  matchRequirement,
  listingLogicalAddress,
  nativeAddressPerSpec,
  validateListingStructure,
  type IdentityBundle,
  type BundleRequirement,
  type ClaimReference,
} from "../src/dacs1.ts";
import {
  verifyDisputeFlow,
  verifyTranscriptDisclosure,
  transcriptContentHash,
  dacsXSeparator,
  disputeRecordHash,
  DACS_X_SEPARATORS,
  type DisputeRecord,
  type DisputeOutcome,
  type ArbitrationRule,
  type RemedyDecision,
  type DisputeFlowInput,
  type ChannelTranscript,
  type DisclosureGrant,
  type DisclosureAuthority,
  type DisclosureInput,
} from "../src/dacsx/index.ts";
import { verifyBundle } from "../src/dacs5/index.ts";
import {
  evidenceHash,
  verifySettlementEvidence,
  type PaymentPhaseInput,
  type PhaseHandlerResult,
  type SettlementEvidence,
} from "../src/dacs4/index.ts";
import { keypairFromSeed, signArtifact, type Keypair } from "../examples/issuer-kit.ts";
import {
  ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF,
  buildAttestationBundle0004,
  buildAttestationBundle0004Seller,
  buildAttestationBundleHtlc9,
} from "../examples/attestation-bundle-0004.ts";
import {
  SETTLEMENT_ORCHESTRATOR_CLAIM,
  buildSettlementDeliverySuccess,
  buildSettlementPaymentSuccess,
} from "../examples/settlement-evidence.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const EMIT = process.argv.includes("--emit");

const statusOf = (_area: string): "golden" => "golden";
const reasonOf = (area: string): string =>
  area === "bundle" || area === "dispute" || area === "disclosure"
    ? "reference-verifier-accepted (verifyBundle) + byte-stable"
    : "reference-verifier-accepted + byte-stable";

const bundle0004 = buildAttestationBundle0004();
const bundle0004Seller = buildAttestationBundle0004Seller();
const bundleHtlc9 = buildAttestationBundleHtlc9();
const settlementPayment = buildSettlementPaymentSuccess();
const settlementDelivery = buildSettlementDeliverySuccess();
const bundle0004Keys: Record<ClaimReference, Uint8Array> = Object.fromEntries(
  Object.entries(bundle0004.publicKeys).map(([claim, key]) => [claim, new Uint8Array(Buffer.from(key, "base64url"))]),
) as Record<ClaimReference, Uint8Array>;
const bundleHtlc9Keys: Record<ClaimReference, Uint8Array> = Object.fromEntries(
  Object.entries(bundleHtlc9.publicKeys).map(([claim, key]) => [claim, new Uint8Array(Buffer.from(key, "base64url"))]),
) as Record<ClaimReference, Uint8Array>;
const settlementKeys: Record<ClaimReference, Uint8Array> = Object.fromEntries(
  Object.entries(settlementPayment.publicKeys).map(([claim, key]) => [claim, new Uint8Array(Buffer.from(key, "base64url"))]),
) as Record<ClaimReference, Uint8Array>;

// ── tiny harness ─────────────────────────────────────────────────────────────
type Case = { id: string; area: string; spec: string; summary: string; got: unknown; want: unknown };
const cases: Case[] = [];
const golden: Record<string, unknown> = {};

function rec(id: string, area: string, spec: string, summary: string, got: unknown, want: unknown): void {
  cases.push({ id, area, spec, summary, got, want });
}
/** Returns "throws" if fn throws (optionally matching `re`), else "no-throw". */
function throwResult(fn: () => unknown, re?: RegExp): string {
  try { fn(); return "no-throw"; } catch (e) { return !re || re.test(String(e)) ? "throws" : "throws:wrong-message"; }
}
function stable(x: unknown): string {
  return JSON.stringify(x, (_k, v) =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1)))
      : v,
  );
}
const eq = (a: unknown, b: unknown): boolean => stable(a) === stable(b);

// ── §7.1 — JCS canonicalization ──────────────────────────────────────────────
rec("canon-key-order", "canonicalize", "§7.1", "object members ordered by UTF-16 code unit of key",
  canonicalize({ b: 1, a: 2, A: 3 }), '{"A":3,"a":2,"b":1}');
rec("canon-nested", "canonicalize", "§7.1", "nested objects sorted; array order preserved",
  canonicalize({ z: [3, 1, 2], a: { y: 1, x: 2 } }), '{"a":{"x":2,"y":1},"z":[3,1,2]}');
rec("canon-escaping", "canonicalize", "§7.1", "only JCS-required escapes are applied",
  canonicalize('a"b\\c\n\t'), '"a\\"b\\\\c\\n\\t"');
rec("canon-no-escape-slash", "canonicalize", "§7.1", "forward slash and non-ASCII are not escaped",
  canonicalize("a/bé"), '"a/bé"');
rec("canon-int", "canonicalize", "§7.1", "safe integers serialise as plain decimals",
  canonicalize(Number.MAX_SAFE_INTEGER), "9007199254740991");
rec("canon-noninteger-throws", "canonicalize", "§7.1", "non-integer numbers are rejected",
  throwResult(() => canonicalize(1.5), /§7\.1/), "throws");
rec("canon-without-signature", "canonicalize", "§7.2", "the signed scope excludes the signature field",
  canonicalize(withoutSignature({ a: 1, signature: "x" })), '{"a":1}');

// ── §14.4 / §9.3 — CD-1 canonical decimals ──────────────────────────────────
rec("cd1-trailing-zeros", "decimal", "§14.4", "1.50 / 01.5 / 1.500 all canonicalise to 1.5",
  [canonicalDecimal("1.50"), canonicalDecimal("01.5"), canonicalDecimal("1.500")], ["1.5", "1.5", "1.5"]);
rec("cd1-normal-forms", "decimal", "§14.4", "0.0 → 0 ; .5 → 0.5 ; 0.50 → 0.5",
  [canonicalDecimal("0.0"), canonicalDecimal(".5"), canonicalDecimal("0.50")], ["0", "0.5", "0.5"]);
rec("cd1-reject-exponent", "decimal", "§14.4", "exponent / sign-plus / non-numeric are rejected",
  [throwResult(() => canonicalDecimal("1e3")), throwResult(() => canonicalDecimal("+1")), throwResult(() => canonicalDecimal("abc"))],
  ["throws", "throws", "throws"]);
rec("cd1-economic-equality", "decimal", "§14.4", "economically-equal amounts share a content hash; raw strings do not",
  {
    canonicalEqual: contentHash({ amount: canonicalDecimal("1.50"), currency: "USDC" }) === contentHash({ amount: canonicalDecimal("1.500"), currency: "USDC" }),
    rawDiffers: contentHash({ amount: "1.50", currency: "USDC" }) !== contentHash({ amount: "1.500", currency: "USDC" }),
  },
  { canonicalEqual: true, rawDiffers: true });
rec("cd1-positivity", "decimal", "§9.3", "amount MUST be > 0",
  throwResult(() => assertPositiveAmount("0"), /> 0/), "throws");

// ── §7.7 — domain-separated Ed25519 signing ─────────────────────────────────
{
  const SEED = "11".repeat(32);
  const { publicKeyRaw, privateKey } = keypairFromSeed(SEED);
  const doc = { listingId: "conf-listing", listingVersion: 1 };
  const separator = DOMAIN_SEPARATOR_REGISTRY["dacs-1-listing"];
  const signature = signArtifact(separator, doc as unknown as Record<string, unknown>, privateKey);
  const signatureRaw = new Uint8Array(Buffer.from(signature, "base64url"));

  const roundtrip = verifyArtifactSignature({ kind: "dacs-1-listing", doc, publicKeyRaw, signatureRaw });
  rec("sig-roundtrip", "signing", "§7.7", "a dacs-1-listing signature verifies under its own separator",
    { ok: roundtrip.ok, separator: roundtrip.separator }, { ok: true, separator });

  const tampered = verifyArtifactSignature({ kind: "dacs-1-listing", doc: { ...doc, listingVersion: 2 }, publicKeyRaw, signatureRaw });
  rec("sig-tamper", "signing", "§7.7", "mutating the signed scope breaks verification",
    tampered.ok, false);

  const crossDomain = verifyArtifactSignature({ kind: "dacs-5-bundle", doc, publicKeyRaw, signatureRaw });
  rec("sig-sig2-cross-domain", "signing", "§7.7", "SIG-2: a listing signature does not verify as a bundle signature",
    crossDomain.ok, false);

  rec("sig-registry-closed-16", "signing", "§7.7", "the domain-separator registry is the closed set of 16",
    Object.keys(DOMAIN_SEPARATOR_REGISTRY).length, 16);

  rec("sig-sig4-dacsx-disjoint", "signing", "§7.7", "SIG-4: DACS-X separators are dacs-x-* and disjoint from the §7.7 registry",
    Object.values(DACS_X_SEPARATORS).every((s) => s.startsWith("dacs-x-") && !isRegisteredSeparator(s)), true);

  golden["signing"] = { seed: SEED, kind: "dacs-1-listing", separator, doc, signature, publicKeyHex: Buffer.from(publicKeyRaw).toString("hex") };
}

// ── §6.3 — DACS-1 identity-bundle validation ────────────────────────────────
{
  const NOW = 1_900_000_000_000;
  const mkBundle = (claims: { ref: string; verified?: boolean }[], presentedBy?: string): IdentityBundle => ({
    bundleVersion: "1",
    presentedBy: presentedBy ?? claims[0]!.ref,
    presentedAt: NOW,
    claims: claims.map((c) => ({
      ref: c.ref,
      ...(c.verified ? { verifiedBy: { anchor: { kind: "storage-program", locator: "stor-x" }, contentHash: "h", recipeVersion: 1 } } : {}),
    })),
    presentation: { kind: "siwd" },
  });

  const cciLeiBundle = mkBundle([{ ref: "cci-lei:984500ABCDEF12345678", verified: true }]);
  const reqLei: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }] };
  const reqCciLei: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "cci-lei", verificationRequired: true }] };
  rec("dacs1-cci-lei-defect", "dacs1", "§6.3.3", "OBSERVATION DACS-VERIFY-0001 (adjacent issue #42): a cci-lei: claim does NOT satisfy a bare lei requirement",
    matchRequirement(cciLeiBundle, reqLei, NOW).ok, false);
  rec("dacs1-cci-lei-named-matches", "dacs1", "§6.3.1", "0001 is naming-only: cci-lei: satisfies a cci-lei requirement",
    matchRequirement(cciLeiBundle, reqCciLei, NOW).ok, true);

  const launderBundle = mkBundle(
    [{ ref: "lei:984500ABCDEF12345678", verified: false }, { ref: "lei:529900T8BM49AABBCC11", verified: true }],
    "lei:984500ABCDEF12345678",
  );
  const reqPrimary: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }], primaryClaimSelector: "lei" };
  rec("dacs1-tier-laundering-guard", "dacs1", "§6.3.3", "step 3b: an unverified presentedBy claim is rejected even if another verified claim satisfies the requirement",
    matchRequirement(launderBundle, reqPrimary, NOW).ok, false);

  const intake = { dacsVersion: "1", listingId: "rfp-intake-1", listingVersion: 1, validity: { notBefore: NOW - 1000 }, pipeline: [{ kind: "negotiate-sealed-envelope" }, { kind: "commit-agreement" }] };
  rec("dacs1-listing-intake-ok", "dacs1", "§6.3.4", "an intake-only listing (no pay phase) may omit acceptedRails",
    validateListingStructure(intake, NOW).ok, true);

  const payNoRails = { dacsVersion: "1", listingId: "buy-1", listingVersion: 1, validity: { notBefore: NOW - 1000 }, pipeline: [{ kind: "pay-evm-erc20" }, { kind: "deliver-storage-program" }] };
  const payRes = validateListingStructure(payNoRails, NOW);
  rec("dacs1-listing-pay-no-rails-fail", "dacs1", "§6.3.4", "step 8: a pay-* phase without acceptedRails fails",
    { ok: payRes.ok, failedAt: payRes.ok ? null : payRes.failedAt }, { ok: false, failedAt: "accepted-rails-conditional" });

  const expired = { dacsVersion: "1", listingId: "old-1", listingVersion: 1, validity: { notBefore: NOW - 2000, notAfter: NOW - 1000 }, pipeline: [{ kind: "negotiate-fixed-price" }, { kind: "commit-agreement" }] };
  const expRes = validateListingStructure(expired, NOW);
  rec("dacs1-listing-expired-fail", "dacs1", "§6.3.4", "an expired validity window is rejected",
    { ok: expRes.ok, failedAt: expRes.ok ? null : expRes.failedAt }, { ok: false, failedAt: "validity-window" });

  const logical = listingLogicalAddress("lei:984500ABCDEF12345678", "fx-rfq-eur-usd", 1);
  const native = nativeAddressPerSpec(logical);
  rec("dacs1-native-address", "dacs1", "§6.3.4", "OBSERVATION DACS-VERIFY-0003: spec rule yields stor-<64hex> (Demos uses stor-<40hex>; verify on substrate before relying)",
    { shape64: /^stor-[0-9a-f]{64}$/.test(native), notLen40: native.length !== "stor-".length + 40 }, { shape64: true, notLen40: true });
  golden["addressing"] = { logical, native };
}

// ── §10.4 — DACS-5 AttestationBundle verification ───────────────────────────
{
  const resolve = (claim: ClaimReference): Uint8Array | undefined => bundle0004Keys[claim];
  const resolveHtlc9 = (claim: ClaimReference): Uint8Array | undefined => bundleHtlc9Keys[claim];
  const htlc9SettlementPhase = bundleHtlc9.bundle.phaseSummary.find((p) => p.kind === "pay-cross-chain-htlc");
  rec("bundle-0004-pass", "bundle", "§10.4", "DACS-VERIFY-0004 completed AttestationBundle verifies with buyer + seller signatures",
    verifyBundle(bundle0004.bundle, resolve), "pass");

  rec("bundle-htlc9-pass", "bundle", "§10.4", "HTLC-9 AttestationBundle verifies and carries settlement-atomicity failure + destination reveal txRef",
    {
      decision: verifyBundle(bundleHtlc9.bundle, resolveHtlc9),
      outcome: bundleHtlc9.bundle.outcome,
      phaseOutcome: htlc9SettlementPhase?.outcome,
      errorClass: htlc9SettlementPhase?.errorClass,
      revealRecorded: htlc9SettlementPhase?.txRefs?.some((tx) => tx.kind === "htlc-reveal" && tx.txHash === ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF) ?? false,
    },
    { decision: "pass", outcome: "failed-substrate", phaseOutcome: "fail", errorClass: "settlement-atomicity", revealRecorded: true });

  const missingSeller = { ...bundle0004.bundle, signatures: bundle0004.bundle.signatures.filter((s) => s.party !== "did:demos:seller") };
  rec("bundle-required-signer-fail", "bundle", "§10.4.1", "completed bundle missing a required seller signature → FAIL",
    verifyBundle(missingSeller, resolve), "fail");

  rec("bundle-malformed-key-error", "bundle", "§10.4.1", "wrong-length resolved public key → ERROR, not a false-negative FAIL",
    verifyBundle(bundle0004.bundle, (claim) => claim === "did:demos:buyer" ? new Uint8Array([1, 2, 3]) : resolve(claim)), "error");

  golden["bundle"] = {
    status: "golden — reference-verifier-accepted (verifyBundle) + byte-stable",
    fixture: "conformance/fixtures/attestation-bundle-0004.json",
    jobId: bundle0004.bundle.jobId,
    bundleHash: bundle0004.bundleHash,
    decisions: { pass: "pass", requiredSignerReject: "fail", malformedKey: "error" },
    seeds: bundle0004.seeds,
    publicKeys: bundle0004.publicKeys,
    divergentSellerFixture: "conformance/fixtures/attestation-bundle-0004-seller.json",
    divergentSeller: {
      jobId: bundle0004Seller.bundle.jobId,
      bundleHash: bundle0004Seller.bundleHash,
      decision: verifyBundle(bundle0004Seller.bundle, resolve),
      outcome: bundle0004Seller.bundle.outcome,
    },
    htlc9Fixture: "conformance/fixtures/attestation-bundle-htlc9.json",
    htlc9: {
      jobId: bundleHtlc9.bundle.jobId,
      bundleHash: bundleHtlc9.bundleHash,
      decision: verifyBundle(bundleHtlc9.bundle, resolveHtlc9),
      settlementPhase: {
        kind: htlc9SettlementPhase?.kind,
        outcome: htlc9SettlementPhase?.outcome,
        errorClass: htlc9SettlementPhase?.errorClass,
        revealTxRef: ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF,
      },
    },
  };
}

// ── §11.2.1 — DACS-X dispute flow (4-value decision) ────────────────────────
// Golden: every dispute record pins full §10.4 AttestationBundles by exact
// (jobId, bundleHash), and those bundles verify through verifyBundle above.
{
  const NOW = 1_780_000_000_000;
  const buyer = keypairFromSeed("a1".repeat(32));
  const arbitrator = keypairFromSeed("b2".repeat(32));
  const buyerClaim = "did:demos:buyer";
  const arbitratorClaim = "did:arbitrator:court";
  const jobId = bundle0004.bundle.jobId;
  const bundleHash = bundle0004.bundleHash;
  const sellerBundleHash = bundle0004Seller.bundleHash;
  const divergentBundleRefs = [{ jobId, bundleHash }, { jobId, bundleHash: sellerBundleHash }];
  const knownBundles = divergentBundleRefs;
  const htlc9JobId = bundleHtlc9.bundle.jobId;
  const htlc9BundleHash = bundleHtlc9.bundleHash;
  const htlc9KnownBundles = [{ jobId: htlc9JobId, bundleHash: htlc9BundleHash }];
  const requirement: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "arbitrator-accreditation", verificationRequired: true }], primaryClaimSelector: "did" };
  const agreedRule: ArbitrationRule = { requirement, arbitrators: [arbitratorClaim], policyVersion: 1 };
  const ruleRef = sha256Hex(canonicalize(agreedRule));
  const arbitratorBundle: IdentityBundle = {
    bundleVersion: "1", presentedBy: arbitratorClaim, presentedAt: NOW,
    claims: [
      { ref: arbitratorClaim, verifiedBy: { anchor: { kind: "sr1-root", locator: "x" }, contentHash: sha256Hex("a"), recipeVersion: 1 }, issuedAt: NOW - 1000 },
      { ref: "arbitrator-accreditation:iso", verifiedBy: { anchor: { kind: "sr1-root", locator: "y" }, contentHash: sha256Hex("b"), recipeVersion: 1 }, issuedAt: NOW - 1000 },
    ],
    presentation: {},
  };
  const makeRecord = (signer = buyer): DisputeRecord => {
    const unsigned: Omit<DisputeRecord, "signature"> = {
      dacsXVersion: "1", disputeId: "d1", initiator: buyerClaim, disputed: divergentBundleRefs,
      contestedClaim: "divergent-bundle", requestedRemedy: "refund", arbitration: { ruleRef }, openedAt: NOW,
    };
    return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
  };
  const makeHtlc9Record = (signer = buyer): DisputeRecord => {
    const unsigned: Omit<DisputeRecord, "signature"> = {
      dacsXVersion: "1", disputeId: "d1-htlc9", initiator: buyerClaim, disputed: [{ jobId: htlc9JobId, bundleHash: htlc9BundleHash }],
      contestedClaim: "asymmetric-settlement", requestedRemedy: "no-fault", arbitration: { ruleRef }, openedAt: NOW,
    };
    return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
  };
  const makeOutcome = (record: DisputeRecord, signer = arbitrator, remedy: RemedyDecision = { kind: "refund-ordered", amount: "5", asset: "usdc" }): DisputeOutcome => {
    const unsigned: Omit<DisputeOutcome, "signature"> = {
      dacsXVersion: "1", disputeId: record.disputeId, disputeRecordHash: disputeRecordHash(record), arbitrator: arbitratorClaim, remedy, decidedAt: NOW + 1000,
    };
    return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-outcome"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
  };
  const baseInput = (): DisputeFlowInput => {
    const record = makeRecord();
    return {
      record, initiatorPublicKeyRaw: buyer.publicKeyRaw, knownBundles, arbitratorBundle, agreedRule,
      now: NOW + 1000, outcome: makeOutcome(record), arbitratorPublicKeyRaw: arbitrator.publicKeyRaw, priorReputation: { jobId, weight: 1 },
    };
  };

  const happy = verifyDisputeFlow(baseInput());
  rec("dispute-happy-pass", "dispute", "§11.2.1", "consistent dispute → PASS, disputed contribution reweighted to 0 (prior preserved)",
    { decision: happy.decision, effectiveWeight: happy.reweighted?.effectiveWeight, priorWeight: happy.reweighted?.priorWeight },
    { decision: "pass", effectiveWeight: 0, priorWeight: 1 });

  const open = baseInput(); delete (open as Partial<DisputeFlowInput>).outcome; delete (open as Partial<DisputeFlowInput>).arbitratorPublicKeyRaw;
  rec("dispute-open-indeterminate", "dispute", "§11.2.1", "an open dispute with no outcome yet → INDETERMINATE",
    verifyDisputeFlow(open).decision, "indeterminate");

  const badKey = baseInput(); badKey.initiatorPublicKeyRaw = arbitrator.publicKeyRaw;
  rec("dispute-bad-record-key-fail", "dispute", "§11.2.1", "a dispute-record verified against the wrong key → FAIL",
    verifyDisputeFlow(badKey).decision, "fail");

  const malformed = baseInput(); malformed.initiatorPublicKeyRaw = new Uint8Array([1, 2, 3]);
  rec("dispute-malformed-key-error", "dispute", "§11.2.1", "an unparseable (non-32-byte) key → ERROR, not a false-negative FAIL",
    verifyDisputeFlow(malformed).decision, "error");

  const ruleSwap = baseInput();
  ruleSwap.agreedRule = { requirement: { requirementVersion: "1", required: [{ scheme: "self-signed", verificationRequired: false }] }, arbitrators: [arbitratorClaim], policyVersion: 1 };
  rec("dispute-rule-swap-fail", "dispute", "§11.2.1", "a post-hoc arbitration-rule swap (rule-ref mismatch) → FAIL",
    verifyDisputeFlow(ruleSwap).decision, "fail");

  const wrongOutcomeKey = baseInput(); wrongOutcomeKey.arbitratorPublicKeyRaw = buyer.publicKeyRaw;
  rec("dispute-wrong-outcome-key-fail", "dispute", "§11.2.1", "an outcome signed by the wrong key → FAIL",
    verifyDisputeFlow(wrongOutcomeKey).decision, "fail");

  const nonCanon = baseInput(); nonCanon.outcome = makeOutcome(nonCanon.record, arbitrator, { kind: "refund-ordered", amount: "5.00", asset: "usdc" });
  rec("dispute-noncanonical-amount-fail", "dispute", "§11.2.1", "an outcome with a non-CD-1 refund amount → FAIL",
    verifyDisputeFlow(nonCanon).decision, "fail");

  const unknownBundle = baseInput(); unknownBundle.knownBundles = [{ jobId: "other-job", bundleHash }];
  rec("dispute-unknown-bundle-fail", "dispute", "§11.2.1", "a dispute pinned to an unknown bundle → FAIL",
    verifyDisputeFlow(unknownBundle).decision, "fail");

  const htlc9Record = makeHtlc9Record();
  const htlc9: DisputeFlowInput = {
    record: htlc9Record,
    initiatorPublicKeyRaw: buyer.publicKeyRaw,
    knownBundles: htlc9KnownBundles,
    arbitratorBundle,
    agreedRule,
    now: NOW + 1000,
    outcome: makeOutcome(htlc9Record, arbitrator, {
      kind: "correction-ordered",
      correctedOutcome: "failure",
      reason: "dest-revealed-source-unclaimed",
      revealTxRef: ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF,
    }),
    arbitratorPublicKeyRaw: arbitrator.publicKeyRaw,
    priorReputation: { jobId: htlc9JobId, weight: 1 },
  };
  const htlc9Res = verifyDisputeFlow(htlc9);
  rec("dispute-htlc9-correction-pass", "dispute", "§11.2.1", "HTLC-9 asymmetric settlement closes via a correction amendment → PASS, contribution voided (never a refund)",
    { decision: htlc9Res.decision, effectiveWeight: htlc9Res.reweighted?.effectiveWeight }, { decision: "pass", effectiveWeight: 0 });

  golden["dispute"] = {
    status: "golden — reference-verifier-accepted (verifyBundle) + byte-stable",
    bundleRef: { jobId, bundleHash },
    divergentBundleRefs,
    htlc9BundleRef: { jobId: htlc9JobId, bundleHash: htlc9BundleHash },
    seeds: { buyer: "a1".repeat(32), arbitrator: "b2".repeat(32) },
    now: NOW,
    decisions: {
      happy: "pass", open: "indeterminate", badRecordKey: "fail", malformedKey: "error",
      ruleSwap: "fail", wrongOutcomeKey: "fail", nonCanonicalAmount: "fail", unknownBundle: "fail", htlc9Correction: "pass",
    },
    inputs: "constructed deterministically in conformance/run.ts from the seeds above; divergent-bundle refs point to conformance/fixtures/attestation-bundle-0004.json + attestation-bundle-0004-seller.json; HTLC-9 correction ref points to conformance/fixtures/attestation-bundle-htlc9.json",
  };
}

// ── §8.7 — DACS-X step 3: arbitrator transcript-disclosure (DP-1) ────────────
// Realises the §8.7 hook ("DACS-X dispute MAY require selective transcript
// disclosure under signed party agreement or arbitrator order") under steward
// sign-off DP-1: full transcript → named arbitrator only, no presentable artifact.
{
  const NOW = 1_780_000_000_000;
  const buyer = keypairFromSeed("a1".repeat(32));
  const seller = keypairFromSeed("c3".repeat(32));
  const arbitrator = keypairFromSeed("b2".repeat(32));
  const buyerClaim = "did:demos:buyer", sellerClaim = "did:demos:seller", arbitratorClaim = "did:arbitrator:court";
  const transcriptSep = DOMAIN_SEPARATOR_REGISTRY["dacs-3-transcript"];
  const grantSep = dacsXSeparator("dacs-x-disclosure-grant");
  const requirement: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "arbitrator-accreditation", verificationRequired: true }], primaryClaimSelector: "did" };
  const agreedRule: ArbitrationRule = { requirement, arbitrators: [arbitratorClaim], policyVersion: 1 };
  const ruleRef = sha256Hex(canonicalize(agreedRule));
  const recUnsigned: Omit<DisputeRecord, "signature"> = {
    dacsXVersion: "1", disputeId: "d1", initiator: buyerClaim, disputed: [
      { jobId: bundle0004.bundle.jobId, bundleHash: bundle0004.bundleHash },
      { jobId: bundle0004Seller.bundle.jobId, bundleHash: bundle0004Seller.bundleHash },
    ],
    contestedClaim: "divergent-bundle", requestedRemedy: "reputation-correction", arbitration: { ruleRef }, openedAt: NOW,
  };
  const record: DisputeRecord = { ...recUnsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), recUnsigned as unknown as Record<string, unknown>, buyer.privateKey) };

  const buildTranscript = (sellerSig?: string): ChannelTranscript => {
    const base: Omit<ChannelTranscript, "signatures"> = {
      transcriptVersion: "1", channelId: "subnet-7", members: [buyerClaim, sellerClaim],
      messages: [{ sequence: 1, author: buyerClaim, envelopeHash: sha256Hex("offer") }, { sequence: 2, author: sellerClaim, envelopeHash: sha256Hex("counter") }],
      generatedAt: NOW - 5000,
    };
    const sign = (kp: Keypair) => signArtifact(transcriptSep, { ...base } as Record<string, unknown>, kp.privateKey, ["signatures"]);
    return { ...base, signatures: [{ signer: buyerClaim, signature: sign(buyer) }, { signer: sellerClaim, signature: sellerSig ?? sign(seller) }] };
  };
  const transcript = buildTranscript();
  const buildGrant = (authority: DisclosureAuthority, signers: [ClaimReference, Keypair][], over: Partial<DisclosureGrant> = {}): DisclosureGrant => {
    const base: Omit<DisclosureGrant, "signatures"> = {
      dacsXVersion: "1", disputeId: "d1", disputeRecordHash: disputeRecordHash(record),
      transcriptHash: transcriptContentHash(transcript), recipient: arbitratorClaim, authority, grantedAt: NOW + 500, ...over,
    };
    const sign = (kp: Keypair) => signArtifact(grantSep, { ...base } as Record<string, unknown>, kp.privateKey, ["signatures"]);
    return { ...base, signatures: signers.map(([signer, kp]) => ({ signer, signature: sign(kp) })) };
  };
  const memberKeys: Record<ClaimReference, Uint8Array> = { [buyerClaim]: buyer.publicKeyRaw, [sellerClaim]: seller.publicKeyRaw };
  const di = (grant: DisclosureGrant, over: Partial<DisclosureInput> = {}): DisclosureInput => ({ grant, transcript, record, agreedRule, recipientPublicKeyRaw: arbitrator.publicKeyRaw, memberKeys, now: NOW + 500, ...over });
  const decide = (input: DisclosureInput): string => { try { return verifyTranscriptDisclosure(input).ok ? "pass" : "fail"; } catch { return "error"; } };

  rec("disclosure-party-agreement-pass", "disclosure", "§8.7", "all channel members co-sign → transcript disclosure to the named arbitrator authorized",
    decide(di(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]]))), "pass");
  rec("disclosure-arbitrator-order-pass", "disclosure", "§8.7", "the credentialed arbitrator orders disclosure → authorized",
    decide(di(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]]))), "pass");
  rec("disclosure-wrong-recipient-fail", "disclosure", "§8.7", "DP-1 named-arbitrator-only: a recipient not in the agreed arbitrator allow-set → FAIL",
    decide(di(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { recipient: "did:rando:x" }))), "fail");
  const rando = keypairFromSeed("d4".repeat(32));
  const swappedRule: ArbitrationRule = { requirement, arbitrators: ["did:rando:x"], policyVersion: 2 };
  rec("disclosure-rule-swap-fail", "disclosure", "§8.7", "DP-1 anti-swap: an agreed rule whose hash ≠ the record's pinned ruleRef → FAIL (can't swap in a rule naming an attacker's recipient)",
    decide(di(buildGrant("arbitrator-order", [["did:rando:x", rando]], { recipient: "did:rando:x" }), { agreedRule: swappedRule, recipientPublicKeyRaw: rando.publicKeyRaw })), "fail");
  rec("disclosure-transcript-substitution-fail", "disclosure", "§8.7", "a grant pinning a different transcript hash → FAIL (the disclosed transcript can't be swapped)",
    decide(di(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]], { transcriptHash: sha256Hex("other-transcript") }))), "fail");
  rec("disclosure-missing-consent-fail", "disclosure", "§8.7", "party-agreement missing a member's consent → FAIL (full consent required)",
    decide(di(buildGrant("party-agreement", [[buyerClaim, buyer]]))), "fail");
  rec("disclosure-wrong-dispute-fail", "disclosure", "§8.7", "a grant not bound to the DisputeRecord → FAIL",
    decide(di(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { disputeRecordHash: sha256Hex("nope") }))), "fail");
  rec("disclosure-malformed-key-error", "disclosure", "§8.7", "a non-32-byte member key → ERROR, not a false-negative FAIL",
    decide(di(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]]), { memberKeys: { [buyerClaim]: new Uint8Array([1, 2, 3]), [sellerClaim]: seller.publicKeyRaw } })), "error");
  const forged = buildTranscript(buildTranscript().signatures[0]!.signature);
  rec("disclosure-transcript-unsigned-fail", "disclosure", "§8.7", "a transcript with an unverifiable member signature → FAIL (authenticity)",
    decide(di(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { transcriptHash: transcriptContentHash(forged) }), { transcript: forged })), "fail");

  golden["disclosure"] = {
    status: "golden — reference-verifier-accepted (verifyBundle) + byte-stable",
    bundleRef: { jobId: bundle0004.bundle.jobId, bundleHash: bundle0004.bundleHash },
    divergentBundleRefs: [
      { jobId: bundle0004.bundle.jobId, bundleHash: bundle0004.bundleHash },
      { jobId: bundle0004Seller.bundle.jobId, bundleHash: bundle0004Seller.bundleHash },
    ],
    seeds: { buyer: "a1".repeat(32), seller: "c3".repeat(32), arbitrator: "b2".repeat(32), rando: "d4".repeat(32) },
    now: NOW,
    decisions: {
      partyAgreement: "pass", arbitratorOrder: "pass", wrongRecipient: "fail", ruleSwap: "fail", transcriptSubstitution: "fail",
      missingConsent: "fail", wrongDispute: "fail", malformedKey: "error", transcriptUnsigned: "fail",
    },
    inputs: "constructed deterministically in conformance/run.ts from the seeds above; dispute record points to conformance/fixtures/attestation-bundle-0004.json + attestation-bundle-0004-seller.json",
  };
}

// ── §14.4 — DACS-4 settlement evidence ──────────────────────────────────────
{
  const resolve = (claim: ClaimReference): Uint8Array | undefined => settlementKeys[claim];
  const signSettlement = (unsigned: Omit<SettlementEvidence, "signature">): SettlementEvidence => {
    const orchestrator = keypairFromSeed("e4".repeat(32));
    return {
      ...unsigned,
      signature: {
        algorithm: "ed25519",
        signer: SETTLEMENT_ORCHESTRATOR_CLAIM,
        value: signArtifact("dacs-evidence:v1:", unsigned as unknown as Record<string, unknown>, orchestrator.privateKey, ["signature"]),
      },
    };
  };
  const refreshRef = (result: PhaseHandlerResult, evidence: SettlementEvidence): PhaseHandlerResult => ({
    ...result,
    attestationRef: { ...result.attestationRef!, contentHash: evidenceHash(evidence) },
  });
  const paymentCase = (over: {
    result?: Partial<PhaseHandlerResult>;
    evidence?: Partial<Omit<SettlementEvidence, "signature">>;
    paymentInput?: (input: PaymentPhaseInput) => PaymentPhaseInput;
    refreshHash?: boolean;
  } = {}) => {
    const { signature: _signature, ...unsignedBase } = settlementPayment.evidence;
    const evidence = signSettlement({ ...unsignedBase, ...over.evidence });
    const paymentInput = over.paymentInput?.(settlementPayment.paymentInput) ?? settlementPayment.paymentInput;
    const resultBase = over.refreshHash === false ? settlementPayment.result : refreshRef(settlementPayment.result, evidence);
    const result = { ...resultBase, ...over.result };
    return { result, evidence, paymentInput };
  };
  const decide = (input: { result: PhaseHandlerResult; evidence: SettlementEvidence; expectedOrchestrator?: ClaimReference; paymentInput?: PaymentPhaseInput; resolveKey?: (claim: ClaimReference) => Uint8Array | null | undefined }): string =>
    verifySettlementEvidence({
      result: input.result,
      evidence: input.evidence,
      expectedOrchestrator: input.expectedOrchestrator ?? SETTLEMENT_ORCHESTRATOR_CLAIM,
      ...(input.paymentInput !== undefined ? { paymentInput: input.paymentInput } : {}),
      resolveKey: input.resolveKey ?? resolve,
    });

  rec("settlement-payment-pass", "settlement", "§14.4", "pay-evm-erc20 success evidence passes PC-1..PC-6 + dacs-4-evidence signature",
    decide(settlementPayment), "pass");
  rec("settlement-delivery-pass", "settlement", "§14.4", "deliver-storage-program success evidence passes with deliverable anchor and no settlementFinality",
    decide(settlementDelivery), "pass");

  const currencyMismatch = paymentCase({
    evidence: { paymentAmount: { amount: "5", currency: "DAI" } },
    paymentInput: (input) => ({ ...input, amount: { amount: "5", currency: "DAI" } }),
  });
  rec("settlement-currency-mismatch-not-rejected-fail", "settlement", "§9.5.1 PC-5", "amount.currency not resolved by rail.asset and handler settled → FAIL",
    decide(currencyMismatch), "fail");

  rec("settlement-success-payment-missing-finality-fail", "settlement", "§9.7 PC-6", "success payment evidence missing settlementFinality → FAIL",
    decide(paymentCase({ evidence: { settlementFinality: undefined } })), "fail");

  const { signature: _deliverySignature, ...deliveryUnsigned } = settlementDelivery.evidence;
  const deliveryWithFinality = signSettlement({
    ...deliveryUnsigned,
    settlementFinality: { model: "provider-receipt", finalityObservedAt: 1_780_014_500_000 },
  });
  rec("settlement-delivery-with-finality-fail", "settlement", "§9.7 PC-6", "delivery evidence carrying settlementFinality → FAIL",
    decide({ result: refreshRef(settlementDelivery.result, deliveryWithFinality), evidence: deliveryWithFinality }), "fail");

  rec("settlement-ok-true-errorclass-fail", "settlement", "§9.5.1 PC-4", "ok:true with errorClass present → FAIL",
    decide(paymentCase({ result: { errorClass: "permanent" } })), "fail");

  rec("settlement-ok-false-no-errorclass-fail", "settlement", "§9.5.1 PC-4", "ok:false without errorClass → FAIL",
    decide(paymentCase({
      result: { ok: false, errorClass: undefined },
      evidence: { outcome: "failure", reason: "rail-rejected", settlementFinality: undefined },
    })), "fail");

  rec("settlement-wrong-anchor-fail", "settlement", "§9.5.1 PC-2", "result.attestationRef id not at expected dacs4 payment anchor → FAIL",
    decide(paymentCase({ result: { attestationRef: { ...settlementPayment.result.attestationRef!, id: "dacs4:payment:wrong:rail" } } })), "fail");

  rec("settlement-attestationref-hash-mismatch-fail", "settlement", "§9.5.1 PC-3", "result.attestationRef contentHash not equal evidenceHash(evidence) → FAIL",
    decide(paymentCase({ refreshHash: false, evidence: { paymentAmount: { amount: "6", currency: "USDC" } } })), "fail");

  rec("settlement-failure-no-reason-fail", "settlement", "§9.7", "failure evidence without non-empty reason → FAIL",
    decide(paymentCase({
      result: { ok: false, errorClass: "permanent" },
      evidence: { outcome: "failure", reason: undefined, settlementFinality: undefined },
    })), "fail");

  const wrong = keypairFromSeed("f5".repeat(32));
  rec("settlement-wrong-signer-key-fail", "settlement", "§9.7", "resolved key is well-formed but not the signing key → FAIL",
    decide({ ...settlementPayment, resolveKey: () => wrong.publicKeyRaw }), "fail");

  rec("settlement-malformed-key-error", "settlement", "§9.7", "resolved signer key is not 32 bytes → ERROR",
    decide({ ...settlementPayment, resolveKey: () => new Uint8Array([1, 2, 3]) }), "error");

  rec("settlement-unresolvable-key-indeterminate", "settlement", "§9.7", "signer key cannot be resolved → INDETERMINATE",
    decide({ ...settlementPayment, resolveKey: () => undefined }), "indeterminate");

  rec("settlement-phase-rail-mismatch-fail", "settlement", "§9.4.1/§9.14", "evidence.phase (pay-solana-spl) ≠ pinned rail.phaseHandler (pay-evm-erc20) → FAIL",
    decide(paymentCase({ evidence: { phase: "pay-solana-spl" } })), "fail");

  rec("settlement-txrefs-mismatch-fail", "settlement", "§9.5.1 PC-1/PC-3", "handler-return txRefs ≠ signed evidence.paymentTxRefs → FAIL (signature covers paymentTxRefs only)",
    decide(paymentCase({ result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xUNSIGNED", kind: "payment" }] } })), "fail");

  rec("settlement-noncanonical-amount-fail", "settlement", "§14.4 CD-1", "non-canonical PriceTerm.amount (\"1.50\") → FAIL (CD-1 minimal-form)",
    decide(paymentCase({ evidence: { paymentAmount: { amount: "1.50", currency: "USDC" } }, paymentInput: (i) => ({ ...i, amount: { amount: "1.50", currency: "USDC" } }) })), "fail");

  rec("settlement-nonpositive-amount-fail", "settlement", "§9.3", "non-positive PriceTerm.amount (\"0\") → FAIL (amount MUST be > 0)",
    decide(paymentCase({ evidence: { paymentAmount: { amount: "0", currency: "USDC" } }, paymentInput: (i) => ({ ...i, amount: { amount: "0", currency: "USDC" } }) })), "fail");

  rec("settlement-wrong-attestation-kind-fail", "settlement", "§9.5.1 PC-3", "attestationRef.kind ≠ dacs-4-evidence (mislabelled as dacs-5-bundle) → FAIL",
    decide(paymentCase({ result: { attestationRef: { ...settlementPayment.result.attestationRef!, kind: "dacs-5-bundle" } } })), "fail");

  // signer ≠ authorized orchestrator: signed by an attacker DID whose key resolves, but not the expected orchestrator.
  const attacker = keypairFromSeed("99".repeat(32));
  const { signature: _attackerSig, ...attackerUnsigned } = settlementPayment.evidence;
  const attackerEvidence: SettlementEvidence = {
    ...attackerUnsigned,
    signature: { algorithm: "ed25519", signer: "did:attacker:x", value: signArtifact("dacs-evidence:v1:", attackerUnsigned as unknown as Record<string, unknown>, attacker.privateKey, ["signature"]) },
  };
  rec("settlement-non-orchestrator-signer-fail", "settlement", "§9.7", "evidence signed by a non-orchestrator claim (key resolves) ≠ expected orchestrator → FAIL",
    decide({ result: refreshRef(settlementPayment.result, attackerEvidence), evidence: attackerEvidence, paymentInput: settlementPayment.paymentInput, resolveKey: (c) => (c === "did:attacker:x" ? attacker.publicKeyRaw : resolve(c)) }), "fail");

  rec("settlement-success-missing-paymenttxrefs-fail", "settlement", "§9.5.2", "success payment evidence omitting paymentTxRefs → FAIL (audit value)",
    decide(paymentCase({ result: { txRefs: undefined }, evidence: { paymentTxRefs: undefined } })), "fail");

  rec("settlement-success-missing-paymentamount-fail", "settlement", "§9.7", "success payment evidence omitting paymentAmount → FAIL (actual settled amount required)",
    decide(paymentCase({ evidence: { paymentAmount: undefined } })), "fail");

  const { signature: _delMissingSig, ...delMissingUnsigned } = settlementDelivery.evidence;
  const deliveryMissingDeliverable = signSettlement({ ...delMissingUnsigned, deliverableContentHash: undefined, deliverableAnchor: undefined });
  rec("settlement-delivery-missing-deliverable-fail", "settlement", "§9.6", "deliver-storage-program success omitting deliverableContentHash/anchor → FAIL",
    decide({ result: refreshRef(settlementDelivery.result, deliveryMissingDeliverable), evidence: deliveryMissingDeliverable }), "fail");

  const deliveryBadHash = signSettlement({ ...delMissingUnsigned, deliverableContentHash: "not-a-hash" });
  rec("settlement-delivery-malformed-contenthash-fail", "settlement", "§9.6", "delivery deliverableContentHash not 64-hex (\"not-a-hash\") → FAIL (content-addressing)",
    decide({ result: refreshRef(settlementDelivery.result, deliveryBadHash), evidence: deliveryBadHash }), "fail");

  rec("settlement-storage-anchored-as-entitlement-fail", "settlement", "§9.6", "deliver-storage-program anchored at dacs4:entitlement namespace → FAIL (phase-specific anchor)",
    decide({ result: { ...settlementDelivery.result, attestationRef: { ...settlementDelivery.result.attestationRef!, id: `dacs4:entitlement:${settlementDelivery.evidence.jobId}:0` } }, evidence: settlementDelivery.evidence }), "fail");

  rec("settlement-negative-fee-fail", "settlement", "§9.7", "negative paymentFee (\"-1\") → FAIL (a fee may be 0, never negative)",
    decide(paymentCase({ evidence: { paymentFee: { amount: "-1", currency: "USDC" } } })), "fail");

  rec("settlement-underpayment-vs-agreement-fail", "settlement", "§9.5.1/PIPE-5", "paymentInput.amount (1 USDC) ≠ agreement.terms.price (5 USDC) → FAIL (underpayment)",
    decide(paymentCase({ evidence: { paymentAmount: { amount: "1", currency: "USDC" } }, paymentInput: (i) => ({ ...i, amount: { amount: "1", currency: "USDC" } }) })), "fail");

  rec("settlement-incoherent-rail-type-handler-fail", "settlement", "§9.4.3 RD-5", "rail railType evm-erc20 with phaseHandler pay-solana-spl → FAIL (incoherent rail)",
    decide(paymentCase({ evidence: { phase: "pay-solana-spl" }, paymentInput: (i) => ({ ...i, rail: { ...i.rail, phaseHandler: "pay-solana-spl" } }) })), "fail");

  rec("settlement-rail-network-mismatch-fail", "settlement", "§9.4.3 RD-5", "evm-erc20 rail with a solana network → FAIL (railType↔asset/network coherence)",
    decide(paymentCase({ paymentInput: (i) => ({ ...i, rail: { ...i.rail, network: { kind: "solana", cluster: "mainnet" } } }) })), "fail");

  // POSITIVE goldens locking the deliberate conformance-scope interpretation (RD-5 = kinds only; SIG-5 open-world) —
  // documented so it's auditable and not silently re-litigated by a later review round.
  rec("settlement-cross-chainid-matching-kind-pass", "settlement", "§9.4.3 RD-5", "rail with matching KINDS but asset.chainId≠network.chainId → PASS (RD-5 binds kinds, not chainId-equality)",
    decide(paymentCase({ paymentInput: (i) => ({ ...i, rail: { ...i.rail, asset: { kind: "erc20", chainId: 1, contract: "0x0000000000000000000000000000000000000001", symbol: "USDC", decimals: 6 }, network: { kind: "evm", chainId: 80002, rpcAttestation: "evm-rpc" } } }) })), "pass");

  const { signature: _delPaySig, ...delPayUnsigned } = settlementDelivery.evidence;
  const deliveryWithExtraPayment = signSettlement({ ...delPayUnsigned, paymentAmount: { amount: "5", currency: "USDC" } });
  rec("settlement-delivery-extra-payment-field-pass", "settlement", "§7.7 SIG-5", "delivery evidence carrying a non-settlementFinality payment field → PASS (SIG-5 preserve-unknown / open-world)",
    decide({ result: refreshRef(settlementDelivery.result, deliveryWithExtraPayment), evidence: deliveryWithExtraPayment }), "pass");

  golden["settlement"] = {
    status: "golden — reference-verifier-accepted + byte-stable",
    fixture: "conformance/fixtures/settlement-evidence-payment-success.json",
    deliveryFixture: "conformance/fixtures/settlement-evidence-delivery-success.json",
    jobId: settlementPayment.evidence.jobId,
    deliveryJobId: settlementDelivery.evidence.jobId,
    evidenceHash: settlementPayment.evidenceHash,
    deliveryEvidenceHash: settlementDelivery.evidenceHash,
    decisions: {
      paymentPass: "pass",
      deliveryPass: "pass",
      currencyMismatchNotRejected: "fail",
      successPaymentMissingFinality: "fail",
      deliveryWithFinality: "fail",
      okTrueWithErrorClass: "fail",
      okFalseNoErrorClass: "fail",
      wrongAnchor: "fail",
      attestationRefHashMismatch: "fail",
      failureNoReason: "fail",
      wrongSignerKey: "fail",
      malformedKey: "error",
      unresolvableKey: "indeterminate",
      phaseRailMismatch: "fail",
      txRefsMismatch: "fail",
      nonCanonicalAmount: "fail",
      nonPositiveAmount: "fail",
      wrongAttestationKind: "fail",
      nonOrchestratorSigner: "fail",
      successMissingPaymentTxRefs: "fail",
      successMissingPaymentAmount: "fail",
      deliveryMissingDeliverable: "fail",
      deliveryMalformedContentHash: "fail",
      storageAnchoredAsEntitlement: "fail",
      negativeFee: "fail",
      underpaymentVsAgreement: "fail",
      incoherentRailTypeHandler: "fail",
      railNetworkMismatch: "fail",
      crossChainIdMatchingKindPass: "pass",
      deliveryExtraPaymentFieldPass: "pass",
    },
    seeds: settlementPayment.seeds,
    publicKeys: settlementPayment.publicKeys,
  };
}

// ── report + emit ────────────────────────────────────────────────────────────
const RESET = "\x1b[0m", GREEN = "\x1b[32m", RED = "\x1b[31m", DIM = "\x1b[2m";
let passed = 0;
const byArea = new Map<string, Case[]>();
for (const c of cases) (byArea.get(c.area) ?? byArea.set(c.area, []).get(c.area)!).push(c);
const goldenN = cases.filter((c) => statusOf(c.area) === "golden").length;
const candidateN = cases.length - goldenN;

console.log(`\nDACS v0.1 conformance — ${goldenN} golden + ${candidateN} candidate (proposed / non-normative)\n`);
for (const [area, list] of byArea) {
  console.log(`  ${area}`);
  for (const c of list) {
    const ok = eq(c.got, c.want);
    if (ok) passed++;
    const mark = ok ? `${GREEN}✓${RESET}` : `${RED}✗${RESET}`;
    console.log(`    ${mark} ${c.id} ${DIM}${c.spec}${RESET}`);
    if (!ok) console.log(`        ${RED}got ${stable(c.got)} · want ${stable(c.want)}${RESET}`);
  }
}
const allPass = passed === cases.length;
console.log(`\n  ${allPass ? GREEN : RED}${passed}/${cases.length} passed${RESET} ${DIM}(${goldenN} golden · ${candidateN} candidate)${RESET}\n`);

if (EMIT) {
  const vectorsDir = join(HERE, "vectors");
  mkdirSync(vectorsDir, { recursive: true });
  const manifest = {
    dacsVersion: "0.1",
    generator: "github.com/mj-deving/dacs-verify",
    note: "Proposed / non-normative. Run: bun conformance/run.ts",
    surfaces: {
      golden: `${goldenN} vectors — 24 primitives + 1 bundle-area (4 checks) + 18 dispute/disclosure + settlement area; byte-stable and reference-verifier-accepted.`,
      candidate: `${candidateN} vectors.`,
    },
    cases: cases.map((c) => ({ id: c.id, area: c.area, spec: c.spec, summary: c.summary, status: statusOf(c.area), reason: reasonOf(c.area), want: c.want })),
  };
  const fixturesDir = join(HERE, "fixtures");
  mkdirSync(fixturesDir, { recursive: true });
  writeFileSync(join(fixturesDir, "attestation-bundle-0004.json"), JSON.stringify(bundle0004.bundle, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "attestation-bundle-0004-seller.json"), JSON.stringify(bundle0004Seller.bundle, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "attestation-bundle-htlc9.json"), JSON.stringify(bundleHtlc9.bundle, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "settlement-evidence-payment-success.json"), JSON.stringify({
    result: settlementPayment.result,
    evidence: settlementPayment.evidence,
    paymentInput: settlementPayment.paymentInput,
    evidenceHash: settlementPayment.evidenceHash,
    publicKeys: settlementPayment.publicKeys,
    seeds: settlementPayment.seeds,
  }, null, 2) + "\n");
  writeFileSync(join(fixturesDir, "settlement-evidence-delivery-success.json"), JSON.stringify({
    result: settlementDelivery.result,
    evidence: settlementDelivery.evidence,
    evidenceHash: settlementDelivery.evidenceHash,
    publicKeys: settlementDelivery.publicKeys,
    seeds: settlementDelivery.seeds,
  }, null, 2) + "\n");
  writeFileSync(join(HERE, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
  writeFileSync(join(vectorsDir, "golden.json"), JSON.stringify(golden, null, 2) + "\n");
  console.log(`  ${DIM}emitted MANIFEST.json + vectors/golden.json${RESET}\n`);
}

process.exit(allPass ? 0 : 1);
