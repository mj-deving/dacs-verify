import { describe, expect, test } from "bun:test";
import {
  classifyVetOutcome,
  evaluateVetRequirement,
  mayRetry,
  validateMethodContract,
  vetAttestationAddress,
  vetCompositeAddress,
  vetControlledPresentedBy,
  vetMatch,
  type VerifyResult,
  type VerifyResultResolver,
} from "../src/dacs2/vet.ts";
import { matchRequirement, type BundleClaim, type BundleRequirement, type IdentityBundle } from "../src/dacs1.ts";
import {
  deliverableSpecHash,
  listingContentHash,
  negotiableBand,
  validateAgreement,
  type AgreementDocument,
  type ListingForValidation,
} from "../src/dacs3/agreement.ts";
import { keypairFromSeed, signArtifact } from "../examples/issuer-kit.ts";

// ── §14.2 Vet ────────────────────────────────────────────────────────────────

describe("DACS-2 Vet — method common contract (CM-1..5)", () => {
  test("CM-4 classifies the four §7.5.1 outcomes; unknown throws", () => {
    expect(["pass", "fail", "indeterminate", "error"].map(classifyVetOutcome)).toEqual(["pass", "fail", "indeterminate", "error"]);
    expect(() => classifyVetOutcome("maybe")).toThrow(/§7\.5\.1/);
  });
  test("CM-5 method must equal the producing kind", () => {
    expect(validateMethodContract({ decision: "pass", method: "vc-presentation" }, "vc-presentation").ok).toBe(true);
    expect(validateMethodContract({ decision: "pass", method: "oauth-oidc" }, "vc-presentation").ok).toBe(false);
  });
  test("CM-1/CM-3 input-shape rejects missing/invalid decision or method", () => {
    expect(validateMethodContract({ decision: "pass" }).ok).toBe(false);
    expect(validateMethodContract({ method: "vc-presentation" }).ok).toBe(false);
    expect(validateMethodContract({ decision: "maybe", method: "vc-presentation" } as unknown as Partial<VerifyResult>).ok).toBe(false);
    expect(validateMethodContract({ decision: "indeterminate", method: "vc-presentation" }).ok).toBe(true);
  });
  test("CM-2 anchors at dacs2:{jobId}:{scheme}:{identifier}:v{recipeVersion}, scheme lowercased", () => {
    expect(vetAttestationAddress("job-abc", "LEI", "984500ABCDEF12345678", 3)).toBe("dacs2:job-abc:lei:984500ABCDEF12345678:v3");
    expect(vetAttestationAddress("job-abc", "CCI-XM", "evm:mainnet:0x1234", 3)).toBe("dacs2:job-abc:cci-xm:evm%3Amainnet%3A0x1234:v3");
  });
  test("CF-4 encodes the dacs2 composite evaluatedParty segment", () => {
    expect(vetCompositeAddress("job-abc", "cci-xm:evm:mainnet:0x1234")).toBe("dacs2:composite:job-abc:cci-xm%3Aevm%3Amainnet%3A0x1234");
  });
});

describe("DACS-2 Vet — retry semantics (VP-R1..R4)", () => {
  test("VP-R1 transient retries while attempts < budget, stops at budget", () => {
    expect(mayRetry({ decision: "error", retryClass: "transient", attempts: 1, retryBudget: 3 })).toBe(true);
    expect(mayRetry({ decision: "error", retryClass: "transient", attempts: 3, retryBudget: 3 })).toBe(false);
  });
  test("VP-R3 permanent never retries", () => {
    expect(mayRetry({ decision: "error", retryClass: "permanent", attempts: 0, retryBudget: 3 })).toBe(false);
  });
  test("VP-R4 indeterminate retries only when retryOnIndeterminate is true", () => {
    expect(mayRetry({ decision: "indeterminate", attempts: 0, retryBudget: 3 })).toBe(false);
    expect(mayRetry({ decision: "indeterminate", retryOnIndeterminate: true, attempts: 0, retryBudget: 3 })).toBe(true);
  });
  test("terminal authority answers (pass/fail) are never retried", () => {
    expect(mayRetry({ decision: "pass", attempts: 0 })).toBe(false);
    expect(mayRetry({ decision: "fail", attempts: 0 })).toBe(false);
  });
});

describe("DACS-2 Vet — matching algorithm (MA-1..MA-3) with full resolution", () => {
  const NOW = 1_900_000_000_000;
  const vb = (locator: string): NonNullable<BundleClaim["verifiedBy"]> => ({ anchor: { kind: "storage-program", locator }, contentHash: "h", recipeVersion: 1 });
  const resolve: VerifyResultResolver = (v) =>
    v.anchor.locator === "stor-fail" ? { decision: "fail", method: "vc-presentation" }
      : v.anchor.locator === "stor-indet" ? { decision: "indeterminate", method: "vc-presentation" }
        : v.anchor.locator === "stor-error" ? { decision: "error", method: "vc-presentation", errorClass: "transient" }
          : v.anchor.locator === "stor-counterparty-malformed" ? { decision: "error", method: "vc-presentation", errorClass: "counterparty" }
            : v.anchor.locator === "stor-vlei-pass" ? { decision: "pass", method: "vlei-presentation", data: { holderBinding: true } }
              : v.anchor.locator === "stor-registry-fake-holderbinding" ? { decision: "pass", method: "gleif-registry", data: { holderBinding: true } }
                : v.anchor.locator === "stor-sr1-pass" ? { decision: "pass", method: "sr1-link", data: { sr1ControlLink: true } }
                : { decision: "pass", method: "gleif-registry" };
  const mk = (claims: BundleClaim[], presentedBy?: string, presentation: IdentityBundle["presentation"] = { kind: "siwd" }): IdentityBundle => ({
    bundleVersion: "1",
    presentedBy: presentedBy ?? claims[0]!.ref,
    presentedAt: NOW,
    claims: claims.map((c) => (c.issuedAt === undefined && c.expiresAt === undefined ? { ...c, issuedAt: NOW - 1_000 } : c)),
    presentation,
  });
  const reqLei: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }] };
  const reqPrimary: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }], primaryClaimSelector: "lei" };

  test("MA-1 missing required → reject", () => {
    expect(vetMatch(mk([{ ref: "did:demos:x", verifiedBy: vb("stor-pass") }]), reqLei, resolve, NOW).ok).toBe(false);
  });
  test("MA-2 presentedBy scheme != selector → reject", () => {
    const b = mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-pass") }, { ref: "did:demos:k", verifiedBy: vb("stor-pass") }], "did:demos:k");
    expect(vetMatch(b, reqPrimary, resolve, NOW).ok).toBe(false);
  });
  test("MA-3 present-but-failing verifiedBy: dacs1 presence-only accepts, vetMatch rejects (the extension)", () => {
    const laundering = mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") }, { ref: "lei:529900T8BM49AABBCC11", verifiedBy: vb("stor-pass") }], "lei:984500ABCDEF12345678");
    expect(matchRequirement(laundering, reqPrimary, NOW).ok).toBe(true); // presence-only false-accept
    expect(vetMatch(laundering, reqPrimary, resolve, NOW).ok).toBe(false); // resolved reject
  });
  test("MA-3 verified presentedBy → accept", () => {
    expect(vetMatch(mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-vlei-pass") }], "lei:984500ABCDEF12345678"), reqPrimary, resolve, NOW).ok).toBe(true);
  });
  test("#170 existence-only LEI pass remains supporting context but not controlled presentedBy", () => {
    const b = mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-registry-pass") }], "lei:984500ABCDEF12345678");
    expect(vetMatch(b, reqLei, resolve, NOW).ok).toBe(true);
    expect(vetMatch(b, reqPrimary, resolve, NOW)).toEqual({ ok: false, reason: "MA-3 controlled presentedBy proof is existence-only" });
    expect(vetControlledPresentedBy(b, resolve, NOW)).toEqual({ ok: false, reason: "controlled presentedBy proof is existence-only" });
  });
  test("#170 holder-bound vLEI pass qualifies as controlled presentedBy", () => {
    const b = mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-vlei-pass") }], "lei:984500ABCDEF12345678");
    expect(vetMatch(b, reqPrimary, resolve, NOW).ok).toBe(true);
    expect(vetControlledPresentedBy(b, resolve, NOW).ok).toBe(true);
  });
  test("#170 existence-only method cannot forge control through holderBinding data", () => {
    const b = mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-registry-fake-holderbinding") }], "lei:984500ABCDEF12345678");
    expect(vetMatch(b, reqPrimary, resolve, NOW)).toEqual({ ok: false, reason: "MA-3 controlled presentedBy proof is existence-only" });
    expect(vetControlledPresentedBy(b, resolve, NOW)).toEqual({ ok: false, reason: "controlled presentedBy proof is existence-only" });
  });
  test("#170 key presentedBy is controlled by its presentation signature", () => {
    const reqKey: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "key", verificationRequired: false }], primaryClaimSelector: "key" };
    const kp = keypairFromSeed("17".repeat(32));
    const keyClaim = `key:${kp.publicKeyB64u}`;
    const unsigned = mk([{ ref: keyClaim, issuedAt: NOW - 1_000 }], keyClaim, { kind: "per-claim", signatures: [] });
    const signature = signArtifact("dacs-bundle-presentation:v1:", unsigned as unknown as Record<string, unknown>, kp.privateKey, ["presentation"]);
    const b = { ...unsigned, presentation: { kind: "per-claim", signatures: [{ ref: keyClaim, signature }] } };
    expect(vetMatch(b, reqKey, resolve, NOW).ok).toBe(true);
    expect(vetControlledPresentedBy(b, resolve, NOW).ok).toBe(true);
  });
  test("#170 malformed key presentation scope rejects without throwing", () => {
    const reqKey: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "key", verificationRequired: false }], primaryClaimSelector: "key" };
    const kp = keypairFromSeed("1a".repeat(32));
    const keyClaim = `key:${kp.publicKeyB64u}`;
    const unsigned = mk([{ ref: keyClaim, issuedAt: NOW - 1_000 }], keyClaim, { kind: "per-claim", signatures: [] });
    const signature = signArtifact("dacs-bundle-presentation:v1:", unsigned as unknown as Record<string, unknown>, kp.privateKey, ["presentation"]);
    const malformed = { ...unsigned, presentedAt: Number.MAX_SAFE_INTEGER + 1, presentation: { kind: "per-claim", signatures: [{ ref: keyClaim, signature }] } } as unknown as IdentityBundle;
    expect(() => vetMatch(malformed, reqKey, resolve, NOW)).not.toThrow();
    expect(() => vetControlledPresentedBy(malformed, resolve, NOW)).not.toThrow();
    expect(vetMatch(malformed, reqKey, resolve, NOW)).toEqual({ ok: false, reason: "MA-3 controlled presentedBy key lacks presentation proof" });
    expect(vetControlledPresentedBy(malformed, resolve, NOW)).toEqual({ ok: false, reason: "controlled presentedBy key lacks presentation proof" });
  });
  test("#170 stale key presentedBy is rejected despite a valid presentation signature", () => {
    const reqKey: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "key", verificationRequired: false }], primaryClaimSelector: "key" };
    const kp = keypairFromSeed("18".repeat(32));
    const keyClaim = `key:${Buffer.from(kp.publicKeyRaw).toString("hex")}`;
    const unsigned = mk([
      { ref: keyClaim, issuedAt: NOW - 2_000, expiresAt: NOW - 1_000 },
      { ref: `key:${"ab".repeat(32)}`, issuedAt: NOW - 1_000 },
    ], keyClaim, { kind: "per-claim", signatures: [] });
    const signature = signArtifact("dacs-bundle-presentation:v1:", unsigned as unknown as Record<string, unknown>, kp.privateKey, ["presentation"]);
    const b = { ...unsigned, presentation: { kind: "per-claim", signatures: [{ ref: keyClaim, signature }] } };
    expect(vetMatch(b, reqKey, resolve, NOW)).toEqual({ ok: false, reason: "MA-3 controlled presentedBy claim stale (primary freshness guard)" });
    expect(vetControlledPresentedBy(b, resolve, NOW)).toEqual({ ok: false, reason: "controlled presentedBy claim stale (primary freshness guard)" });
  });
  test("#170 verified key primary rejects unverified presentedBy despite another verified key", () => {
    const reqKeyVerified: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "key", verificationRequired: true }], primaryClaimSelector: "key" };
    const kp = keypairFromSeed("19".repeat(32));
    const keyClaim = `key:${Buffer.from(kp.publicKeyRaw).toString("hex")}`;
    const unsigned = mk([
      { ref: keyClaim, issuedAt: NOW - 1_000 },
      { ref: `key:${"cd".repeat(32)}`, issuedAt: NOW - 1_000, verifiedBy: vb("stor-pass") },
    ], keyClaim, { kind: "per-claim", signatures: [] });
    const signature = signArtifact("dacs-bundle-presentation:v1:", unsigned as unknown as Record<string, unknown>, kp.privateKey, ["presentation"]);
    const b = { ...unsigned, presentation: { kind: "per-claim", signatures: [{ ref: keyClaim, signature }] } };
    expect(vetMatch(b, reqKeyVerified, resolve, NOW)).toEqual({ ok: false, reason: "MA-3 controlled presentedBy verifiedBy does not resolve to decision=pass" });
    expect(vetControlledPresentedBy(b, resolve, NOW, reqKeyVerified.required[0])).toEqual({ ok: false, reason: "controlled presentedBy verifiedBy does not resolve to decision=pass" });
  });
  test("find_claim: verificationRequired + resolved indeterminate → claim absent", () => {
    expect(vetMatch(mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-indet") }]), reqLei, resolve, NOW).ok).toBe(false);
  });
  test("vetFindClaim freshness fails closed before maxAge", () => {
    const maxAgeReq: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true, maxAge: 60 }] };
    const unknownAge: IdentityBundle = { bundleVersion: "1", presentedBy: "lei:984500ABCDEF12345678", presentedAt: NOW, claims: [{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-pass") }], presentation: { kind: "siwd" } };
    expect(vetMatch(unknownAge, reqLei, resolve, NOW).ok).toBe(false);

    const expired: IdentityBundle = { ...unknownAge, claims: [{ ref: "lei:984500ABCDEF12345678", issuedAt: NOW - 1_000, expiresAt: NOW - 1, verifiedBy: vb("stor-pass") }] };
    expect(vetMatch(expired, reqLei, resolve, NOW).ok).toBe(false);

    const noIssuedAt: IdentityBundle = { ...unknownAge, claims: [{ ref: "lei:984500ABCDEF12345678", expiresAt: NOW + 1_000, verifiedBy: vb("stor-pass") }] };
    expect(vetMatch(noIssuedAt, reqLei, resolve, NOW).ok).toBe(true);
    expect(vetMatch(noIssuedAt, maxAgeReq, resolve, NOW).ok).toBe(false);
  });
  test("MA-3 rejects stale presentedBy even when another same-scheme claim satisfies required", () => {
    const b: IdentityBundle = {
      bundleVersion: "1",
      presentedBy: "lei:STALE",
      presentedAt: NOW,
      claims: [
        { ref: "lei:STALE", issuedAt: NOW - 10_000, expiresAt: NOW - 1, verifiedBy: vb("stor-pass") },
        { ref: "lei:FRESH", issuedAt: NOW - 1_000, expiresAt: NOW + 60_000, verifiedBy: vb("stor-pass") },
      ],
      presentation: { kind: "siwd" },
    };
    const req: BundleRequirement = {
      requirementVersion: "1",
      required: [{ scheme: "lei", verificationRequired: true, maxAge: 60 }],
      primaryClaimSelector: "lei",
    };

    expect(vetMatch(b, req, resolve, NOW)).toEqual({ ok: false, reason: "MA-3 controlled presentedBy claim stale (primary freshness guard)" });
  });
  test("oneOf aggregation precedence is error > indeterminate > fail within the group", () => {
    const req: BundleRequirement = {
      requirementVersion: "1",
      required: [],
      oneOf: [[
        { scheme: "lei", verificationRequired: true },
        { scheme: "domain", verificationRequired: true },
      ]],
    };
    const b = mk([
      { ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") },
      { ref: "domain:example.com", verifiedBy: vb("stor-error") },
    ]);
    expect(evaluateVetRequirement(b, req, resolve, NOW)).toEqual({ decision: "error", errorClass: "transient" });

    const indeterminate = mk([
      { ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") },
      { ref: "domain:example.com", verifiedBy: vb("stor-indet") },
    ]);
    expect(evaluateVetRequirement(indeterminate, req, resolve, NOW)).toEqual({ decision: "indeterminate" });
  });
  test("cross-accumulator precedence is fail > error > indeterminate", () => {
    const req: BundleRequirement = {
      requirementVersion: "1",
      required: [{ scheme: "lei", verificationRequired: true }],
      oneOf: [[{ scheme: "domain", verificationRequired: true }]],
    };
    const b = mk([
      { ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") },
      { ref: "domain:example.com", verifiedBy: vb("stor-error") },
    ]);
    expect(evaluateVetRequirement(b, req, resolve, NOW)).toEqual({ decision: "fail", errorClass: "permanent" });
  });
  test("counterparty-malformed oneOf error keeps decision error but attributes counterparty", () => {
    const req: BundleRequirement = {
      requirementVersion: "1",
      required: [],
      oneOf: [[
        { scheme: "lei", verificationRequired: true },
        { scheme: "domain", verificationRequired: true },
      ]],
    };
    const b = mk([
      { ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-fail") },
      { ref: "domain:example.com", verifiedBy: vb("stor-counterparty-malformed") },
    ]);
    expect(evaluateVetRequirement(b, req, resolve, NOW)).toEqual({ decision: "error", errorClass: "counterparty" });
  });
});

// ── §14.3 Negotiate — §8.5.2 agreement validation ────────────────────────────

describe("DACS-3 Negotiate — §8.5.2 listing-conformance validation", () => {
  const COMMITTED_AT = 1_900_000_000_000;
  const deliverableSpec = { deliverableType: "attested-payload", verificationMethod: "http-attestation", schemaUrl: "https://schemas.example/x.json" };
  const dHash = deliverableSpecHash(deliverableSpec);
  const baseListing: ListingForValidation = {
    listingId: "L1",
    listingVersion: 1,
    pricing: { kind: "negotiable", bandCenter: { amount: "100", currency: "USDC" }, minPct: 10, maxPct: 20 },
    acceptedRails: ["erc20-usdc-base", "spl-usdc"],
    offering: { deliverable: deliverableSpec },
    pattern: "rfq",
    terms: { deadlineSecAfterCommit: 86400 },
    validity: { notBefore: COMMITTED_AT - 100_000, notAfter: COMMITTED_AT + 1_000_000 },
  };
  const ok: AgreementDocument = {
    derivedFromPattern: "rfq",
    terms: { price: { amount: "95", currency: "USDC" }, rail: "erc20-usdc-base", deliverable: { deliverableType: "attested-payload", hash: dHash, schemaUrl: "https://schemas.example/x.json" }, deadline: COMMITTED_AT + 1000 },
  };
  const at = (amount: string): AgreementDocument => ({ ...ok, terms: { ...ok.terms, price: { amount, currency: "USDC" } } });
  const bind = (a: AgreementDocument, l: ListingForValidation = baseListing): AgreementDocument => ({
    ...a,
    listingRef: {
      listingId: l.listingId!,
      version: (l.version ?? l.listingVersion)!,
      contentHash: listingContentHash(l),
    },
  });
  const V = (a: AgreementDocument, l: ListingForValidation = baseListing) => validateAgreement(bind(a, l), l, COMMITTED_AT);

  test("price-band inclusive, edges accept, just-outside reject", () => {
    expect(V(at("95")).ok).toBe(true);
    expect(V(at("90")).ok).toBe(true);
    expect(V(at("120")).ok).toBe(true);
    expect(V(at("89.999")).ok).toBe(false);
    expect(V(at("120.001")).ok).toBe(false);
  });
  test("negotiableBand bounds are [90, 120]", () => {
    expect(negotiableBand("100", 10, 20)).toEqual({ lower: "90", upper: "120" });
    expect(negotiableBand("100", "2.5", "2.5")).toEqual({ lower: "97.5", upper: "102.5" });
  });
  test("currency mismatch rejected before amount compare", () => {
    const r = V({ ...ok, terms: { ...ok.terms, price: { amount: "95", currency: "EURC" } } });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.failedAt).toBe("currency");
  });
  test("listingRef binding fails closed when metadata is missing or mismatched", () => {
    const listingWithRef: ListingForValidation = { ...baseListing, listingId: "L1", listingVersion: 1 };
    const ref = { listingId: "L1", version: 1, contentHash: listingContentHash(listingWithRef) };
    const agreementWithRef: AgreementDocument = { ...ok, listingRef: ref };
    expect(validateAgreement(agreementWithRef, listingWithRef, COMMITTED_AT).ok).toBe(true);
    expect(validateAgreement({ ...agreementWithRef, listingRef: { ...ref, contentHash: "def456" } }, listingWithRef, COMMITTED_AT).ok).toBe(false);
    expect(validateAgreement(ok, listingWithRef, COMMITTED_AT).ok).toBe(false);
    const { listingId: _listingId, listingVersion: _listingVersion, ...listingWithoutMetadata } = listingWithRef;
    const missing = validateAgreement(agreementWithRef, listingWithoutMetadata, COMMITTED_AT);
    expect(missing.ok).toBe(false);
    expect(missing.ok === false && missing.failedAt).toBe("listingRef");
    const nullRef = validateAgreement({ ...ok, listingRef: null } as unknown as AgreementDocument, listingWithRef, COMMITTED_AT);
    expect(nullRef.ok).toBe(false);
    expect(nullRef.ok === false && nullRef.failedAt).toBe("listingRef");
  });
  test("listingRef binding rejects self-declared contentHash over tampered listing body", () => {
    const listingWithRef: ListingForValidation = { ...baseListing, listingId: "L1", listingVersion: 1 };
    const ref = { listingId: "L1", version: 1, contentHash: listingContentHash(listingWithRef) };
    const tampered: ListingForValidation = { ...listingWithRef, pricing: { kind: "negotiable", bandCenter: { amount: "95", currency: "USDC" }, minPct: 10, maxPct: 20 }, contentHash: ref.contentHash };
    expect(validateAgreement({ ...ok, listingRef: ref }, tampered, COMMITTED_AT).ok).toBe(false);
    const dualVersionTampered: ListingForValidation = { ...listingWithRef, version: 2, contentHash: ref.contentHash };
    expect(validateAgreement({ ...ok, listingRef: { ...ref, version: 2 } }, dualVersionTampered, COMMITTED_AT).ok).toBe(false);
    const conflictingAliases: ListingForValidation = { ...listingWithRef, version: 2, listingVersion: 1 };
    expect(validateAgreement({ ...ok, listingRef: { ...ref, version: 2, contentHash: listingContentHash(conflictingAliases) } }, conflictingAliases, COMMITTED_AT).ok).toBe(false);
  });
  test("listingRef binding rejects fractional JSON-number percentages", () => {
    const listingWithFractionalPct: ListingForValidation = { ...baseListing, listingId: "L1", listingVersion: 1, pricing: { kind: "negotiable", bandCenter: { amount: "100", currency: "USDC" }, minPct: 2.5, maxPct: 2.5 } };
    expect(() => listingContentHash(listingWithFractionalPct)).toThrow(/non-integer JSON number/);
  });
  test("listingRef binding accepts hash-safe decimal-string percentages", () => {
    const listingWithStringPct: ListingForValidation = { ...baseListing, pricing: { kind: "negotiable", bandCenter: { amount: "100", currency: "USDC" }, minPct: "2.5", maxPct: "2.5" } };
    expect(V(at("101"), listingWithStringPct).ok).toBe(true);
    expect(V(at("103"), listingWithStringPct).ok).toBe(false);
  });
  test("negotiable bands whose lower edge is non-positive are malformed", () => {
    const malformedBand: ListingForValidation = { ...baseListing, pricing: { kind: "negotiable", bandCenter: { amount: "100", currency: "USDC" }, minPct: 100, maxPct: 20 } };
    const result = V(at("50"), malformedBand);
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.failedAt).toBe("price");
  });
  test("rail not accepted → reject", () => {
    expect(V({ ...ok, terms: { ...ok.terms, rail: "wire-transfer" } }).ok).toBe(false);
  });
  test("pay-phase listings require an accepted rail unless explicitly zero-pay", () => {
    const { rail: _rail, ...termsWithoutRail } = ok.terms;
    const missingRail = { ...ok, terms: termsWithoutRail };
    expect(V(missingRail, { ...baseListing, acceptedRails: [] }).ok).toBe(false);
    expect(V(missingRail, { ...baseListing, acceptedRails: [], hasPayPhase: false }).ok).toBe(true);
    const { acceptedRails: _acceptedRails, ...zeroPayWithoutRails } = { ...baseListing, hasPayPhase: false };
    expect(V(missingRail, zeroPayWithoutRails).ok).toBe(true);
    expect(V(ok, { ...baseListing, acceptedRails: [], hasPayPhase: false }).ok).toBe(false);
    expect(V(missingRail, { ...baseListing, hasPayPhase: false, pipeline: [{ kind: "pay-x402" }] }).ok).toBe(false);
  });
  test("deliverable type/hash/schema conformance", () => {
    expect(V(ok).ok).toBe(true);
    expect(V({ ...ok, terms: { ...ok.terms, deliverable: { deliverableType: "entitlement", hash: dHash } } }).ok).toBe(false);
    expect(V({ ...ok, terms: { ...ok.terms, deliverable: { deliverableType: "attested-payload", hash: "deadbeef", schemaUrl: "https://schemas.example/x.json" } } }).ok).toBe(false);
    expect(V({ ...ok, terms: { ...ok.terms, deliverable: { deliverableType: "attested-payload", hash: dHash, schemaUrl: "https://other.example/y.json" } } }).ok).toBe(false);
  });
  test("deliverable hash is recomputed from the listing payload, not trusted inline", () => {
    expect(V(ok, { ...baseListing, offering: { deliverable: { ...deliverableSpec, hash: dHash } } }).ok).toBe(true);
    const tamperedSpec = { ...deliverableSpec, source: "https://evil.example/data", hash: dHash };
    expect(V(ok, { ...baseListing, offering: { deliverable: tamperedSpec } }).ok).toBe(false);
  });
  test("deadline measured against anchored committedAt", () => {
    expect(V({ ...ok, terms: { ...ok.terms, deadline: COMMITTED_AT + 86400 * 1000 } }).ok).toBe(true);
    expect(V({ ...ok, terms: { ...ok.terms, deadline: COMMITTED_AT + 86400 * 1000 + 1 } }).ok).toBe(false);
  });
  test("notAfter < committedAt → reject", () => {
    expect(V(ok, { ...baseListing, validity: { notBefore: COMMITTED_AT - 100_000, notAfter: COMMITTED_AT - 1 } }).ok).toBe(false);
  });
  test("derivedFromPattern mismatch → reject", () => {
    expect(V({ ...ok, derivedFromPattern: "sealed-envelope" }).ok).toBe(false);
    expect(V({ ...at("100"), derivedFromPattern: "fixed-price" }).ok).toBe(false);
  });
  test("PS-3 fixed-price over negotiable must equal bandCenter exactly", () => {
    const fixedOverNeg: ListingForValidation = { ...baseListing, pattern: "fixed-price" };
    expect(V({ ...at("100"), derivedFromPattern: "fixed-price" }, fixedOverNeg).ok).toBe(true);
    expect(V({ ...at("95"), derivedFromPattern: "fixed-price" }, fixedOverNeg).ok).toBe(false);
  });
  test("terms.price.amount must be CD-1 canonical in signed AgreementDocuments", () => {
    const r = V(at("100.00"));
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.failedAt).toBe("price");
    expect(V(at("0100")).ok).toBe(false);
    expect(V(at("100")).ok).toBe(true); // canonical, in band
  });
  test("priceAnchor: absent ok; present CD-1 ok; non-canonical reject; JSON null treated as absent (no crash)", () => {
    expect(V(ok).ok).toBe(true);
    expect(V({ ...ok, terms: { ...ok.terms, priceAnchor: { price: "100", attestationRef: { contentHash: "abc123" } } } }).ok).toBe(true);
    expect(V({ ...ok, terms: { ...ok.terms, priceAnchor: { price: "100.00", attestationRef: { contentHash: "abc123" } } } }).ok).toBe(false);
    // a JSON `null` priceAnchor (external agreement input) is absent, not a TypeError
    expect(V({ ...ok, terms: { ...ok.terms, priceAnchor: null } as unknown as AgreementDocument["terms"] }).ok).toBe(true);
  });
});
