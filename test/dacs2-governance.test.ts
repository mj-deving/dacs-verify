import { describe, expect, test } from "bun:test";
import {
  ANCHORING_PHASES,
  classifyAnchoringPhase,
  evaluatePinnedRecipe,
  isCanonicallyAnchored,
  validateStewardDisclosure,
} from "../src/dacs2/governance.ts";

// §14.7 GOV-1..GOV-3 over the §7.4.4 progressive-anchoring scheme.

describe("GOV-2 — anchoring-phase classification (§7.4.4)", () => {
  test("the three §7.4.1 phases classify to themselves", () => {
    expect(ANCHORING_PHASES.map(classifyAnchoringPhase)).toEqual(["in-code", "single-signer", "multisig"]);
  });
  test("an unknown phase throws", () => {
    expect(() => classifyAnchoringPhase("constituted")).toThrow(/GOV-2/);
    expect(() => classifyAnchoringPhase("")).toThrow();
  });
  test("in-code is NOT canonically anchored; single-signer/multisig are", () => {
    expect(isCanonicallyAnchored("in-code")).toBe(false);
    expect(isCanonicallyAnchored("single-signer")).toBe(true);
    expect(isCanonicallyAnchored("multisig")).toBe(true);
  });
});

describe("GOV-1 — steward disclosure (§12 / §14.7)", () => {
  test("surfaces key + presents PA-2 as single-steward → ok", () => {
    expect(validateStewardDisclosure({ authoritativeSigningKey: "ed25519:k", represents: "single-steward", actualPhase: "single-signer" }).ok).toBe(true);
  });
  test("missing authoritative key → reject", () => {
    expect(validateStewardDisclosure({ represents: "single-steward", actualPhase: "single-signer" }).ok).toBe(false);
    expect(validateStewardDisclosure({ authoritativeSigningKey: "", actualPhase: "single-signer" }).ok).toBe(false);
  });
  test("presenting a single-signer steward as a constituted body → reject", () => {
    const r = validateStewardDisclosure({ authoritativeSigningKey: "ed25519:k", represents: "constituted-body", actualPhase: "single-signer" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/constituted/);
  });
  test("presenting a constituted body is honest only at multisig (PA-3)", () => {
    expect(validateStewardDisclosure({ authoritativeSigningKey: "multisig:wg", represents: "constituted-body", actualPhase: "multisig" }).ok).toBe(true);
  });
  test("in-code (PA-1) bootstrap presented as constituted body → reject", () => {
    expect(validateStewardDisclosure({ authoritativeSigningKey: "in-code:k", represents: "constituted-body", actualPhase: "in-code" }).ok).toBe(false);
  });
});

describe("GOV-3 — pin-time anchoring-phase verification (§7.4.4 append-only)", () => {
  test("pin-time phase governs, NOT current registry phase", () => {
    const d = evaluatePinnedRecipe({ recipeVersion: 3, pinTimePhase: "single-signer", currentPhase: "multisig" });
    expect(d.evaluatedPhase).toBe("single-signer"); // a later PA-3 re-anchor MUST NOT retro-upgrade the pin
    expect(d.canonicallyAnchored).toBe(true);
    expect(d.ok).toBe(true);
  });
  test("a pinned in-code recipeVersion is not canonically anchored", () => {
    const d = evaluatePinnedRecipe({ recipeVersion: 1, pinTimePhase: "in-code" });
    expect(d.canonicallyAnchored).toBe(false);
    expect(d.ok).toBe(true); // not-anchored is a property, not a hard failure absent a trust floor
  });
  test("a single-signer pin below a multisig trust floor → reject", () => {
    const d = evaluatePinnedRecipe({ recipeVersion: 3, pinTimePhase: "single-signer", requiredMinPhase: "multisig" });
    expect(d.ok).toBe(false);
    expect(d.reason).toMatch(/trust floor/);
  });
  test("a multisig pin meeting a multisig trust floor → accept", () => {
    expect(evaluatePinnedRecipe({ recipeVersion: 7, pinTimePhase: "multisig", requiredMinPhase: "multisig" }).ok).toBe(true);
  });
  test("an in-code pin under a single-signer trust floor → reject", () => {
    expect(evaluatePinnedRecipe({ recipeVersion: 1, pinTimePhase: "in-code", requiredMinPhase: "single-signer" }).ok).toBe(false);
  });
});

describe("GOV trust boundary — malformed phase fail-closed (§7.4.4)", () => {
  test("evaluatePinnedRecipe throws on an unrecognised pin-time phase", () => {
    expect(() => evaluatePinnedRecipe({ recipeVersion: 9, pinTimePhase: "constituted" as unknown as "in-code" })).toThrow(/GOV-2/);
  });
  test("evaluatePinnedRecipe throws on an unrecognised requiredMinPhase", () => {
    expect(() => evaluatePinnedRecipe({ recipeVersion: 9, pinTimePhase: "single-signer", requiredMinPhase: "bogus" as unknown as "multisig" })).toThrow(/GOV-2/);
  });
  test("validateStewardDisclosure throws on an unrecognised actualPhase", () => {
    expect(() => validateStewardDisclosure({ authoritativeSigningKey: "k", actualPhase: "bogus" as unknown as "in-code" })).toThrow(/GOV-2/);
  });
  test("absent (null/undefined/empty) phase fails closed too, not just unknown strings", () => {
    // "absent field" and "unknown enum value" are different code paths — both MUST throw.
    expect(() => evaluatePinnedRecipe({ recipeVersion: 9, pinTimePhase: null as unknown as "in-code" })).toThrow();
    expect(() => evaluatePinnedRecipe({ recipeVersion: 9, pinTimePhase: undefined as unknown as "in-code" })).toThrow();
    expect(() => evaluatePinnedRecipe({ recipeVersion: 9, pinTimePhase: "" as unknown as "in-code" })).toThrow();
    expect(() => validateStewardDisclosure({ authoritativeSigningKey: "k", actualPhase: null as unknown as "in-code" })).toThrow();
  });
});
