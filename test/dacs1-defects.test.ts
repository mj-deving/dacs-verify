import { test, expect } from "bun:test";
import {
  schemeOf,
  findClaim,
  matchRequirement,
  nativeAddressPerSpec,
  listingLogicalAddress,
  validateListingStructure,
  type IdentityBundle,
  type BundleRequirement,
} from "../src/dacs1.ts";

const NOW = 1_900_000_000_000;

function bundle(claims: { ref: string; verified?: boolean }[], presentedBy?: string): IdentityBundle {
  return {
    bundleVersion: "1",
    presentedBy: presentedBy ?? claims[0]!.ref,
    presentedAt: NOW,
    claims: claims.map((c) => ({ ref: c.ref, ...(c.verified ? { verifiedBy: { anchor: { kind: "storage-program", locator: "stor-x" }, contentHash: "h", recipeVersion: 1 } } : {}) })),
    presentation: { kind: "siwd" },
  };
}

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
  expect(logical).toBe("dacs1:lei:984500ABCDEF12345678:fx-rfq-eur-usd:v1");
  const native = nativeAddressPerSpec(logical);
  // Spec §6.3.4: "stor-" + sha256(logical) → 64 hex chars.
  expect(native).toMatch(/^stor-[0-9a-f]{64}$/);
  // Demos actually addresses stor-{SHA256(deployer:programName:salt)[:40]} —
  // 40 hex, keyed differently. A listing anchored per the spec rule would not
  // resolve on Demos. (Documented as finding; verify on substrate before filing.)
  expect(native.length).not.toBe("stor-".length + 40);
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
