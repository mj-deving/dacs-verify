import { describe, expect, test } from "bun:test";
import {
  classifyVetOutcome,
  mayRetry,
  validateMethodContract,
  vetAttestationAddress,
  vetMatch,
  type VerifyResult,
  type VerifyResultResolver,
} from "../src/dacs2/vet.ts";
import { matchRequirement, type BundleClaim, type BundleRequirement, type IdentityBundle } from "../src/dacs1.ts";
import {
  deliverableSpecHash,
  negotiableBand,
  validateAgreement,
  type AgreementDocument,
  type ListingForValidation,
} from "../src/dacs3/agreement.ts";

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
        : { decision: "pass", method: "vc-presentation" };
  const mk = (claims: BundleClaim[], presentedBy?: string): IdentityBundle => ({ bundleVersion: "1", presentedBy: presentedBy ?? claims[0]!.ref, presentedAt: NOW, claims, presentation: { kind: "siwd" } });
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
    expect(vetMatch(mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-pass") }], "lei:984500ABCDEF12345678"), reqPrimary, resolve, NOW).ok).toBe(true);
  });
  test("find_claim: verificationRequired + resolved indeterminate → claim absent", () => {
    expect(vetMatch(mk([{ ref: "lei:984500ABCDEF12345678", verifiedBy: vb("stor-indet") }]), reqLei, resolve, NOW).ok).toBe(false);
  });
});

// ── §14.3 Negotiate — §8.5.2 agreement validation ────────────────────────────

describe("DACS-3 Negotiate — §8.5.2 listing-conformance validation", () => {
  const COMMITTED_AT = 1_900_000_000_000;
  const deliverableSpec = { deliverableType: "attested-payload", verificationMethod: "http-attestation", schemaUrl: "https://schemas.example/x.json" };
  const dHash = deliverableSpecHash(deliverableSpec);
  const baseListing: ListingForValidation = {
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
  const V = (a: AgreementDocument, l: ListingForValidation = baseListing) => validateAgreement(a, l, COMMITTED_AT);

  test("price-band inclusive, edges accept, just-outside reject", () => {
    expect(V(at("95")).ok).toBe(true);
    expect(V(at("90")).ok).toBe(true);
    expect(V(at("120")).ok).toBe(true);
    expect(V(at("89.999")).ok).toBe(false);
    expect(V(at("120.001")).ok).toBe(false);
  });
  test("negotiableBand bounds are [90, 120]", () => {
    expect(negotiableBand("100", 10, 20)).toEqual({ lower: "90", upper: "120" });
  });
  test("currency mismatch rejected before amount compare", () => {
    const r = V({ ...ok, terms: { ...ok.terms, price: { amount: "95", currency: "EURC" } } });
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.failedAt).toBe("currency");
  });
  test("rail not accepted → reject", () => {
    expect(V({ ...ok, terms: { ...ok.terms, rail: "wire-transfer" } }).ok).toBe(false);
  });
  test("deliverable type/hash/schema conformance", () => {
    expect(V(ok).ok).toBe(true);
    expect(V({ ...ok, terms: { ...ok.terms, deliverable: { deliverableType: "entitlement", hash: dHash } } }).ok).toBe(false);
    expect(V({ ...ok, terms: { ...ok.terms, deliverable: { deliverableType: "attested-payload", hash: "deadbeef", schemaUrl: "https://schemas.example/x.json" } } }).ok).toBe(false);
    expect(V({ ...ok, terms: { ...ok.terms, deliverable: { deliverableType: "attested-payload", hash: dHash, schemaUrl: "https://other.example/y.json" } } }).ok).toBe(false);
  });
  test("deadline measured against anchored committedAt", () => {
    expect(V({ ...ok, terms: { ...ok.terms, deadline: COMMITTED_AT + 86400 * 1000 } }).ok).toBe(true);
    expect(V({ ...ok, terms: { ...ok.terms, deadline: COMMITTED_AT + 86400 * 1000 + 1 } }).ok).toBe(false);
  });
  test("notAfter < committedAt → reject", () => {
    expect(validateAgreement(ok, { ...baseListing, validity: { notBefore: COMMITTED_AT - 100_000, notAfter: COMMITTED_AT - 1 } }, COMMITTED_AT).ok).toBe(false);
  });
  test("derivedFromPattern mismatch → reject", () => {
    expect(V({ ...ok, derivedFromPattern: "sealed-envelope" }).ok).toBe(false);
  });
  test("PS-3 fixed-price over negotiable must equal bandCenter exactly", () => {
    const fixedOverNeg: ListingForValidation = { ...baseListing, pattern: "fixed-price" };
    expect(validateAgreement({ ...at("100"), derivedFromPattern: "fixed-price" }, fixedOverNeg, COMMITTED_AT).ok).toBe(true);
    expect(validateAgreement({ ...at("95"), derivedFromPattern: "fixed-price" }, fixedOverNeg, COMMITTED_AT).ok).toBe(false);
  });
  test("terms.price.amount must be CD-1 canonical — non-canonical rejected (matches settlement lane)", () => {
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
