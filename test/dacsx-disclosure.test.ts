import { test, expect } from "bun:test";
import { keypairFromSeed, signArtifact, type Keypair } from "../examples/issuer-kit.ts";
import { DOMAIN_SEPARATOR_REGISTRY } from "../src/signing.ts";
import { sha256Hex } from "../src/hash.ts";
import { canonicalize } from "../src/canonicalize.ts";
import {
  verifyTranscriptDisclosure,
  transcriptContentHash,
  disputeRecordHash,
  dacsXSeparator,
  type ChannelTranscript,
  type DisclosureGrant,
  type DisclosureAuthority,
  type DisputeRecord,
  type ArbitrationRule,
  type DisclosureInput,
} from "../src/dacsx/index.ts";
import type { BundleRequirement, ClaimReference } from "../src/dacs1.ts";

// DACS-X step 3 — §8.7 arbitrator-disclosure (DP-1). Deterministic fixtures.

const NOW = 1_780_000_000_000;
const buyer = keypairFromSeed("a1".repeat(32));
const seller = keypairFromSeed("c3".repeat(32));
const arbitrator = keypairFromSeed("b2".repeat(32));
const buyerClaim = "did:demos:buyer";
const sellerClaim = "did:demos:seller";
const arbitratorClaim = "did:arbitrator:court";

const transcriptSep = DOMAIN_SEPARATOR_REGISTRY["dacs-3-transcript"];
const grantSep = dacsXSeparator("dacs-x-disclosure-grant");

const requirement: BundleRequirement = {
  requirementVersion: "1",
  required: [{ scheme: "arbitrator-accreditation", verificationRequired: true }],
  primaryClaimSelector: "did",
};
const agreedRule: ArbitrationRule = { requirement, arbitrators: [arbitratorClaim], policyVersion: 1 };
const ruleRef = sha256Hex(canonicalize(agreedRule));

const record: DisputeRecord = (() => {
  const unsigned: Omit<DisputeRecord, "signature"> = {
    dacsXVersion: "1", disputeId: "d1", initiator: buyerClaim,
    disputed: [{ jobId: "job-flow", bundleHash: sha256Hex("b") }],
    contestedClaim: "divergent-bundle", requestedRemedy: "reputation-correction",
    arbitration: { ruleRef }, openedAt: NOW,
  };
  return { ...unsigned, signature: signArtifact(dacsXSeparator("dacs-x-dispute-record"), unsigned as unknown as Record<string, unknown>, buyer.privateKey) };
})();

function buildTranscript(sellerSig?: string): ChannelTranscript {
  const base: Omit<ChannelTranscript, "signatures"> = {
    transcriptVersion: "1", channelId: "subnet-7", members: [buyerClaim, sellerClaim],
    messages: [
      { sequence: 1, author: buyerClaim, envelopeHash: sha256Hex("offer") },
      { sequence: 2, author: sellerClaim, envelopeHash: sha256Hex("counter") },
    ],
    generatedAt: NOW - 5000,
  };
  const sign = (kp: Keypair) => signArtifact(transcriptSep, { ...base } as Record<string, unknown>, kp.privateKey, ["signatures"]);
  return {
    ...base,
    signatures: [
      { signer: buyerClaim, signature: sign(buyer) },
      { signer: sellerClaim, signature: sellerSig ?? sign(seller) },
    ],
  };
}

const transcript = buildTranscript();

function buildGrant(
  authority: DisclosureAuthority,
  signers: [ClaimReference, Keypair][],
  overrides: Partial<DisclosureGrant> = {},
): DisclosureGrant {
  const base: Omit<DisclosureGrant, "signatures"> = {
    dacsXVersion: "1", disputeId: "d1", disputeRecordHash: disputeRecordHash(record),
    transcriptHash: transcriptContentHash(transcript), recipient: arbitratorClaim,
    authority, grantedAt: NOW + 500, ...overrides,
  };
  const sign = (kp: Keypair) => signArtifact(grantSep, { ...base } as Record<string, unknown>, kp.privateKey, ["signatures"]);
  return { ...base, signatures: signers.map(([signer, kp]) => ({ signer, signature: sign(kp) })) };
}

const memberKeys: Record<ClaimReference, Uint8Array> = {
  [buyerClaim]: buyer.publicKeyRaw,
  [sellerClaim]: seller.publicKeyRaw,
};

const baseInput = (grant: DisclosureGrant, over: Partial<DisclosureInput> = {}): DisclosureInput => ({
  grant, transcript, record, agreedRule,
  recipientPublicKeyRaw: arbitrator.publicKeyRaw, memberKeys, now: NOW + 500, ...over,
});

test("party-agreement: all members consent → ok, recipient is the arbitrator", () => {
  const r = verifyTranscriptDisclosure(baseInput(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]])));
  expect(r.ok).toBe(true);
  if (r.ok) expect(r.recipient).toBe(arbitratorClaim);
});

test("arbitrator-order: the credentialed arbitrator orders disclosure → ok", () => {
  const r = verifyTranscriptDisclosure(baseInput(buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]])));
  expect(r.ok).toBe(true);
});

test("DP-1 named-arbitrator-only: a non-credentialed recipient → fail", () => {
  const grant = buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { recipient: "did:rando:x" });
  const r = verifyTranscriptDisclosure(baseInput(grant));
  expect(r.ok).toBe(false);
});

test("anti-substitution: a grant pinning a different transcript hash → fail", () => {
  const grant = buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]], { transcriptHash: sha256Hex("other-transcript") });
  const r = verifyTranscriptDisclosure(baseInput(grant));
  expect(r.ok).toBe(false);
});

test("party-agreement requires FULL consent: a missing member signature → fail", () => {
  const r = verifyTranscriptDisclosure(baseInput(buildGrant("party-agreement", [[buyerClaim, buyer]])));
  expect(r.ok).toBe(false);
});

test("dispute binding: a grant not bound to the DisputeRecord → fail", () => {
  const grant = buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { disputeRecordHash: sha256Hex("nope") });
  const r = verifyTranscriptDisclosure(baseInput(grant));
  expect(r.ok).toBe(false);
});

test("malformed key → throws (caller surfaces as `error`, not a false-negative fail)", () => {
  const input = baseInput(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]]), {
    memberKeys: { [buyerClaim]: new Uint8Array([1, 2, 3]), [sellerClaim]: seller.publicKeyRaw },
  });
  expect(() => verifyTranscriptDisclosure(input)).toThrow(/malformed/);
});

test("transcript authenticity: an unverifiable member signature → fail", () => {
  // seller's slot carries the buyer's signature — wrong signer, won't verify.
  const buyerSig = buildTranscript().signatures[0]!.signature;
  const forged = buildTranscript(buyerSig);
  const grant = buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { transcriptHash: transcriptContentHash(forged) });
  const r = verifyTranscriptDisclosure(baseInput(grant, { transcript: forged }));
  expect(r.ok).toBe(false);
});

test("DP-1 no presentable artifact: the result is a bare check, nothing re-anchorable", () => {
  const r = verifyTranscriptDisclosure(baseInput(buildGrant("party-agreement", [[buyerClaim, buyer], [sellerClaim, seller]])));
  expect(r.ok).toBe(true);
  expect(r).not.toHaveProperty("signature");
  expect(r).not.toHaveProperty("signatures");
  expect(Object.keys(r).sort()).toEqual(["ok", "recipient", "transcriptHash"]);
});

test("CRITICAL anti-swap (cross-vendor catch): an agreed rule whose hash != the record's pinned ruleRef → fail", () => {
  // Without binding agreedRule to record.arbitration.ruleRef, an attacker swaps in a
  // rule whose allow-set names their own recipient and defeats named-arbitrator-only.
  const rando = keypairFromSeed("d4".repeat(32));
  const swappedRule: ArbitrationRule = { requirement, arbitrators: ["did:rando:x"], policyVersion: 2 };
  const grant = buildGrant("arbitrator-order", [["did:rando:x", rando]], { recipient: "did:rando:x" });
  const r = verifyTranscriptDisclosure(baseInput(grant, { agreedRule: swappedRule, recipientPublicKeyRaw: rando.publicKeyRaw }));
  expect(r.ok).toBe(false);
});

test("transcript integrity: a message author outside the declared member set → fail", () => {
  const t = buildTranscript();
  const tampered: ChannelTranscript = { ...t, messages: [...t.messages, { sequence: 3, author: "did:ghost:z", envelopeHash: sha256Hex("x") }] };
  const grant = buildGrant("arbitrator-order", [[arbitratorClaim, arbitrator]], { transcriptHash: transcriptContentHash(tampered) });
  const r = verifyTranscriptDisclosure(baseInput(grant, { transcript: tampered }));
  expect(r.ok).toBe(false);
});
