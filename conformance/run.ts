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
 *   bun conformance/run.ts          verify the published primitive vectors (§7.1/§14.4/§7.7/§6.3)
 *   bun conformance/run.ts --emit   (re)write MANIFEST.json + the pinned goldens under vectors/
 *   bun conformance/run.ts --full   also run the §11.2.1 dispute vectors — held from the published
 *                                   golden set pending the #99 shared full-AttestationBundle fixture
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
} from "../src/dacs1.ts";
import {
  verifyDisputeFlow,
  dacsXSeparator,
  disputeRecordHash,
  DACS_X_SEPARATORS,
  type DisputeRecord,
  type DisputeOutcome,
  type ArbitrationRule,
  type RemedyDecision,
  type DisputeFlowInput,
} from "../src/dacsx/index.ts";
import { keypairFromSeed, signArtifact } from "../examples/issuer-kit.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const EMIT = process.argv.includes("--emit");
const FULL = process.argv.includes("--full"); // also run the §11.2.1 dispute area (held from the published golden set pending #99)

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

// ── §11.2.1 — DACS-X dispute flow (the 4-value decision) ────────────────────
// Held from the published golden set pending the #99 shared full-AttestationBundle
// fixture: PATH-OS's unmodified DACS-5 verify-bundle returns §7.5.1 indeterminate on
// these minimal dispute-layer fixtures, so they are single-impl, not cross-impl golden.
// Opt in with --full to run/emit them locally.
if (FULL) {
  const NOW = 1_780_000_000_000;
  const buyer = keypairFromSeed("a1".repeat(32));
  const arbitrator = keypairFromSeed("b2".repeat(32));
  const buyerClaim = "did:demos:buyer";
  const arbitratorClaim = "did:arbitrator:court";
  const jobId = "job-flow";
  const bundleHash = contentHash({ bundleVersion: "1", jobId, outcome: "divergent" });
  const knownBundles = [{ jobId, bundleHash }];
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
      dacsXVersion: "1", disputeId: "d1", initiator: buyerClaim, disputed: [{ jobId, bundleHash }],
      contestedClaim: "divergent-bundle", requestedRemedy: "refund", arbitration: { ruleRef }, openedAt: NOW,
    };
    return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), unsigned as unknown as Record<string, unknown>, signer.privateKey) };
  };
  const makeOutcome = (record: DisputeRecord, signer = arbitrator, remedy: RemedyDecision = { kind: "refund-ordered", amount: "5", asset: "usdc" }): DisputeOutcome => {
    const unsigned: Omit<DisputeOutcome, "signature"> = {
      dacsXVersion: "1", disputeId: "d1", disputeRecordHash: disputeRecordHash(record), arbitrator: arbitratorClaim, remedy, decidedAt: NOW + 1000,
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

  const htlc9 = baseInput();
  htlc9.outcome = makeOutcome(htlc9.record, arbitrator, { kind: "correction-ordered", correctedOutcome: "failure", reason: "dest-revealed-source-unclaimed", revealTxRef: "polygon-amoy:0xreveal" });
  const htlc9Res = verifyDisputeFlow(htlc9);
  rec("dispute-htlc9-correction-pass", "dispute", "§11.2.1", "HTLC-9 asymmetric settlement closes via a correction amendment → PASS, contribution voided (never a refund)",
    { decision: htlc9Res.decision, effectiveWeight: htlc9Res.reweighted?.effectiveWeight }, { decision: "pass", effectiveWeight: 0 });

  golden["dispute"] = {
    seeds: { buyer: "a1".repeat(32), arbitrator: "b2".repeat(32) },
    now: NOW,
    decisions: {
      happy: "pass", open: "indeterminate", badRecordKey: "fail", malformedKey: "error",
      ruleSwap: "fail", wrongOutcomeKey: "fail", nonCanonicalAmount: "fail", unknownBundle: "fail", htlc9Correction: "pass",
    },
    artifacts: "see vectors/dacs-x/ for the byte-stable dispute-record / outcome / bundle fixtures",
  };
}

// ── report + emit ────────────────────────────────────────────────────────────
const RESET = "\x1b[0m", GREEN = "\x1b[32m", RED = "\x1b[31m", DIM = "\x1b[2m";
let passed = 0;
const byArea = new Map<string, Case[]>();
for (const c of cases) (byArea.get(c.area) ?? byArea.set(c.area, []).get(c.area)!).push(c);

console.log(`\nDACS v0.1 conformance — ${cases.length} vectors (proposed / non-normative)\n`);
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
console.log(`\n  ${allPass ? GREEN : RED}${passed}/${cases.length} passed${RESET}\n`);

if (EMIT) {
  const vectorsDir = join(HERE, "vectors");
  mkdirSync(vectorsDir, { recursive: true });
  const manifest = {
    dacsVersion: "0.1",
    generator: "github.com/mj-deving/dacs-verify",
    note: FULL
      ? "DACS v0.1 conformance vectors incl. the §11.2.1 dispute area (held from the published set pending interface-issue #99). Proposed / non-normative."
      : "Golden conformance vectors for the deterministic DACS v0.1 primitive surface (§7.1 canonicalization, §14.4 decimals, §7.7 signing, §6.3 identity). Proposed / non-normative. Run: bun conformance/run.ts",
    cases: cases.map((c) => ({ id: c.id, area: c.area, spec: c.spec, summary: c.summary, want: c.want })),
  };
  writeFileSync(join(HERE, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
  writeFileSync(join(vectorsDir, "golden.json"), JSON.stringify(golden, null, 2) + "\n");
  console.log(`  ${DIM}emitted MANIFEST.json + vectors/golden.json${RESET}\n`);
}

process.exit(allPass ? 0 : 1);
