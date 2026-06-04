import { test, expect } from "bun:test";
import {
  schemeOf,
  deriveIdentityTier,
  findClaim,
  isVerifyResultRef,
  matchRequirement,
  nativeAddressPerSpec,
  listingLogicalAddress,
  validateListingStructure,
  type IdentityBundle,
  type BundleRequirement,
} from "../src/dacs1.ts";
import { sha256Hex } from "../src/hash.ts";
import { cf4Decode, cf4Encode } from "../src/logical-address.ts";

const NOW = 1_900_000_000_000;

function bundle(claims: { ref: string; verified?: boolean }[], presentedBy?: string): IdentityBundle {
  return {
    bundleVersion: "1",
    presentedBy: presentedBy ?? claims[0]!.ref,
    presentedAt: NOW,
    claims: claims.map((c) => ({ ref: c.ref, issuedAt: NOW - 1_000, ...(c.verified ? { verifiedBy: { anchor: { kind: "storage-program", locator: "stor-x" }, contentHash: "h", recipeVersion: 1 } } : {}) })),
    presentation: { kind: "siwd" },
  };
}

function verifiedByFor(ref: string, locator = `stor-verify-${ref.replaceAll(":", "-")}`) {
  return {
    anchor: { kind: "storage-program", locator },
    contentHash: sha256Hex(`verify-result:${ref}:${locator}:pass`),
    recipeVersion: 1,
  };
}

const resolvedPass = (claim: { ref: string; verifiedBy?: unknown }): boolean => {
  if (!isVerifyResultRef(claim.verifiedBy)) return false;
  return claim.verifiedBy.contentHash === sha256Hex(`verify-result:${claim.ref}:${claim.verifiedBy.anchor.locator}:pass`);
};

test("FINDING DACS-VERIFY-0001 (B1-1): a `cci-lei:` claim does NOT satisfy a `lei` requirement", () => {
  // §6.3.1 registers the CCI-native scheme as `cci-lei`; §6.3.3/§7.4.2/§6.3.4/
  // §6.3.5/§10.5.2 all use the bare `lei`. find_claim does exact scheme
  // equality (§6.3.3: `c.ref.scheme != cr.scheme`), so the two never match.
  const b = bundle([{ ref: "cci-lei:984500ABCDEF12345678", verified: true }]);
  const reqLei: BundleRequirement = {
    requirementVersion: "1",
    required: [{ scheme: "lei", verificationRequired: true }],
  };
  expect(matchRequirement(b, reqLei, NOW).ok).toBe(false); // the defect

  // With the scheme spelled as registered in §6.3.1, it matches — proving the
  // failure is a pure naming inconsistency, not a logic gap.
  const reqCciLei: BundleRequirement = {
    requirementVersion: "1",
    required: [{ scheme: "cci-lei", verificationRequired: true }],
  };
  expect(matchRequirement(b, reqCciLei, NOW).ok).toBe(true);
});

test("schemeOf parses the scheme component and lowercases it", () => {
  expect(schemeOf("lei:984500ABCDEF12345678")).toBe("lei");
  expect(schemeOf("cci-xm:evm:mainnet:0xabc")).toBe("cci-xm");
  expect(schemeOf("ERC8004:1:0xabc:42")).toBe("erc8004");
});

test("FINDING DACS-VERIFY-0003 (B4-1): spec native-address rule yields stor-<64hex>, not Demos's stor-<40hex>", () => {
  const logical = listingLogicalAddress("lei:984500ABCDEF12345678", "fx-rfq-eur-usd", 1);
  expect(logical).toBe("dacs1:lei%3A984500ABCDEF12345678:fx-rfq-eur-usd:v1");
  const native = nativeAddressPerSpec(logical);
  // Spec §6.3.4: "stor-" + sha256(logical) → 64 hex chars.
  expect(native).toMatch(/^stor-[0-9a-f]{64}$/);
  // Demos actually addresses stor-{SHA256(deployer:programName:salt)[:40]} —
  // 40 hex, keyed differently. A listing anchored per the spec rule would not
  // resolve on Demos. (Documented as finding; verify on substrate before filing.)
  expect(native.length).not.toBe("stor-".length + 40);
});

test("CF-4 encodes only reserved logical-address delimiters and round-trips", () => {
  const raw = "cci-xm:evm:mainnet:0x1234?x=1&y=100%";
  const encoded = cf4Encode(raw);
  expect(encoded).toBe("cci-xm%3Aevm%3Amainnet%3A0x1234%3Fx%3D1%26y%3D100%25");
  expect(cf4Decode(encoded)).toBe(raw);
});

test("listingLogicalAddress CF-4-encodes claim and listingId variable segments", () => {
  const logical = listingLogicalAddress("cci-xm:evm:mainnet:0x1234", "rfq:lot?x=1", 3);
  expect(logical).toBe("dacs1:cci-xm%3Aevm%3Amainnet%3A0x1234:rfq%3Alot%3Fx%3D1:v3");
  const [, seller, listingId, version] = logical.split(":");
  expect(cf4Decode(seller!)).toBe("cci-xm:evm:mainnet:0x1234");
  expect(cf4Decode(listingId!)).toBe("rfq:lot?x=1");
  expect(version).toBe("v3");
});

test("§6.3.3 step 3b tier-laundering guard: unverified presentedBy claim is rejected", () => {
  const b = bundle(
    [
      { ref: "lei:984500ABCDEF12345678", verified: false }, // presentedBy, NOT verified
      { ref: "lei:529900T8BM49AABBCC11", verified: true }, // a different verified lei
    ],
    "lei:984500ABCDEF12345678",
  );
  const req: BundleRequirement = {
    requirementVersion: "1",
    required: [{ scheme: "lei", verificationRequired: true }],
    primaryClaimSelector: "lei",
  };
  // required is satisfied by the *other* verified lei, but presentedBy itself is
  // unverified → must REJECT (no reputation laundering).
  expect(matchRequirement(b, req, NOW).ok).toBe(false);
});

test("findClaim freshness fails closed before maxAge", () => {
  const req: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true }] };
  const reqMaxAge: BundleRequirement = { requirementVersion: "1", required: [{ scheme: "lei", verificationRequired: true, maxAge: 60 }] };
  const verifiedBy = { anchor: { kind: "storage-program", locator: "stor-lei" }, contentHash: "h", recipeVersion: 1 };

  const unknownAge: IdentityBundle = { bundleVersion: "1", presentedBy: "lei:529900T8BM49AURSDO55", presentedAt: NOW, claims: [{ ref: "lei:529900T8BM49AURSDO55", verifiedBy }], presentation: { kind: "siwd" } };
  expect(matchRequirement(unknownAge, req, NOW).ok).toBe(false);

  const expired: IdentityBundle = { ...unknownAge, claims: [{ ref: "lei:529900T8BM49AURSDO55", issuedAt: NOW - 1_000, expiresAt: NOW - 1, verifiedBy }] };
  expect(matchRequirement(expired, req, NOW).ok).toBe(false);

  const noIssuedAt: IdentityBundle = { ...unknownAge, claims: [{ ref: "lei:529900T8BM49AURSDO55", expiresAt: NOW + 1_000, verifiedBy }] };
  expect(matchRequirement(noIssuedAt, req, NOW).ok).toBe(true);
  expect(matchRequirement(noIssuedAt, reqMaxAge, NOW).ok).toBe(false);
});

test("primaryClaimSelector rejects stale presentedBy even when another same-scheme claim is fresh", () => {
  const verifiedBy = { anchor: { kind: "storage-program", locator: "stor-lei" }, contentHash: "h", recipeVersion: 1 };
  const b: IdentityBundle = {
    bundleVersion: "1",
    presentedBy: "lei:STALE",
    presentedAt: NOW,
    claims: [
      { ref: "lei:STALE", issuedAt: NOW - 10_000, expiresAt: NOW - 1, verifiedBy },
      { ref: "lei:FRESH", issuedAt: NOW - 1_000, expiresAt: NOW + 60_000, verifiedBy },
    ],
    presentation: { kind: "siwd" },
  };
  const req: BundleRequirement = {
    requirementVersion: "1",
    required: [{ scheme: "lei", verificationRequired: true, maxAge: 60 }],
    primaryClaimSelector: "lei",
  };

  expect(matchRequirement(b, req, NOW)).toEqual({ ok: false, reason: "presentedBy claim stale (primary freshness guard)" });
});

test("identity tier derivation uses verified-and-fresh institutional claims", () => {
  const b = bundle([{ ref: "key:aaaaaaaa" }], "lei:529900T8BM49AURSDO55");
  b.claims.push({
    ref: "lei:529900T8BM49AURSDO55",
    issuedAt: NOW - 1_000,
    verifiedBy: verifiedByFor("lei:529900T8BM49AURSDO55"),
  });
  expect(deriveIdentityTier(b, NOW, resolvedPass)).toBe("institutional");
});

test("identity tier derivation returns verified for non-authority verified claims", () => {
  const b = bundle([{ ref: "key:bbbbbbbb" }], "domain:example.com");
  b.claims.push({
    ref: "domain:example.com",
    issuedAt: NOW - 1_000,
    verifiedBy: verifiedByFor("domain:example.com"),
  });
  expect(deriveIdentityTier(b, NOW, resolvedPass)).toBe("verified");
});

test("identity tier derivation ignores self-asserted tier values and stale verified claims", () => {
  const b = {
    ...bundle([{ ref: "key:cccccccc" }]),
    identityTier: "institutional",
  } as IdentityBundle & { identityTier: string };
  expect(deriveIdentityTier(b, NOW, resolvedPass)).toBe("self-declared");

  const stale = bundle([{ ref: "lei:529900T8BM49AURSDO55" }], "lei:529900T8BM49AURSDO55");
  stale.claims[0] = {
    ref: "lei:529900T8BM49AURSDO55",
    issuedAt: NOW - 10_000,
    expiresAt: NOW - 1,
    verifiedBy: verifiedByFor("lei:529900T8BM49AURSDO55"),
  };
  expect(deriveIdentityTier(stale, NOW, resolvedPass)).toBe("self-declared");
});

test("identity tier derivation fails closed without a resolved passing verifiedBy", () => {
  const b = bundle([{ ref: "lei:529900T8BM49AURSDO55" }], "lei:529900T8BM49AURSDO55");
  b.claims[0] = {
    ref: "lei:529900T8BM49AURSDO55",
    issuedAt: NOW - 1_000,
    verifiedBy: { kind: "storage-program", locator: "stor-forged", contentHash: sha256Hex("forged") } as never,
  };

  expect(deriveIdentityTier(b, NOW)).toBe("self-declared");
  expect(deriveIdentityTier(b, NOW, resolvedPass)).toBe("self-declared");
});

test("listing validation: intake-only listing (no pay phase) may omit acceptedRails", () => {
  const intake = {
    dacsVersion: "1",
    listingId: "rfp-intake-1",
    listingVersion: 1,
    validity: { notBefore: NOW - 1000 },
    pipeline: [{ kind: "negotiate-sealed-envelope" }, { kind: "commit-agreement" }],
  };
  expect(validateListingStructure(intake, NOW).ok).toBe(true);
});

test("listing validation: pay-* phase without acceptedRails fails (§6.3.4 step 8)", () => {
  const bad = {
    dacsVersion: "1",
    listingId: "buy-1",
    listingVersion: 1,
    validity: { notBefore: NOW - 1000 },
    pipeline: [{ kind: "pay-evm-erc20" }, { kind: "deliver-storage-program" }],
  };
  const res = validateListingStructure(bad, NOW);
  expect(res.ok).toBe(false);
  if (!res.ok) expect(res.failedAt).toBe("accepted-rails-conditional");
});

test("listing validation: rejects expired validity window", () => {
  const expired = {
    dacsVersion: "1",
    listingId: "old-1",
    listingVersion: 1,
    validity: { notBefore: NOW - 2000, notAfter: NOW - 1000 },
    pipeline: [{ kind: "negotiate-fixed-price" }, { kind: "commit-agreement" }],
  };
  const res = validateListingStructure(expired, NOW);
  expect(res.ok).toBe(false);
  if (!res.ok) expect(res.failedAt).toBe("validity-window");
});
