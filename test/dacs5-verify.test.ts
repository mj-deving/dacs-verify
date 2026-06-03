import { test, expect } from "bun:test";

import {
  TERMINAL_STATES,
  bundleAddress,
  bundleHash,
  consumeBundles,
  deriveReputation,
  isLegalTransition,
  stateToOutcome,
  twoSidedLookup,
} from "../src/dacs5/index.ts";
import {
  VERIFY_BUYER_CLAIM,
  VERIFY_SELLER_CLAIM,
  VERIFY_DIVERGENT_JOB_ID,
  VERIFY_ONE_SIDED_JOB_ID,
  VERIFY_MISANCHORED_JOB_ID,
  VERIFY_REPUTATION_COMPUTED_AT,
  VERIFY_REPUTATION_WINDOW_END,
  VERIFY_REPUTATION_WINDOW_START,
  buildSessionBundleFixtures,
  makeBundleFetch,
} from "../examples/session-bundles.ts";

const fixtures = buildSessionBundleFixtures();
// §10.5.1: the reputation fixtures are the buyer's own anchored session bundles.
const anchoredBuyer = fixtures.reputationBundles.map((bundle) => ({ bundle, anchoredBy: VERIFY_BUYER_CLAIM }));
// §10.4.2: the consumer's externally-known expected parties for the session under audit.
const VERIFY_EXPECTED = { buyer: VERIFY_BUYER_CLAIM, seller: VERIFY_SELLER_CLAIM };

test("bundleAddress is deterministic and role-specific", () => {
  expect(bundleAddress("job-1", "buyer")).toBe("stor-c7bc689288bad9d6f448ca14c9aa949a4c9574a317f4a591c7f9486f4f7a6b8f");
  expect(bundleAddress("job-1", "seller")).toBe("stor-4bc62bd044c59f54946ca1baaf9bf943464c352f1d7aea1bdc74c9abbde784d9");
  expect(bundleAddress("job-1", "buyer")).toBe(bundleAddress("job-1", "buyer"));
  expect(bundleAddress("job-1", "buyer")).not.toBe(bundleAddress("job-1", "seller"));
});

test("twoSidedLookup returns both, one, or no expected-side bundles", () => {
  expect(Object.keys(twoSidedLookup(VERIFY_DIVERGENT_JOB_ID, fixtures.fetchDivergent)).sort()).toEqual(["buyer", "seller"]);
  expect(twoSidedLookup(VERIFY_ONE_SIDED_JOB_ID, fixtures.fetchOneSided)).toEqual({ buyer: fixtures.oneSidedBuyer });
  expect(twoSidedLookup("DACS-VERIFY-L3-ABSENT", fixtures.fetchAbsent)).toEqual({});
});

test("consumeBundles classifies canonically equal bundles as unified", () => {
  const result = consumeBundles(VERIFY_DIVERGENT_JOB_ID, fixtures.fetchUnified, fixtures.resolveKey, VERIFY_EXPECTED);
  expect(result.verdict).toBe("unified");
  expect(result.buyer?.decision).toBe("pass");
  expect(result.seller?.decision).toBe("pass");
  expect(bundleHash(result.buyer!.bundle)).toBe(bundleHash(result.seller!.bundle));
});

test("consumeBundles classifies one-sided bundles by §10.11 roles", () => {
  const result = consumeBundles(VERIFY_ONE_SIDED_JOB_ID, fixtures.fetchOneSided, fixtures.resolveKey, VERIFY_EXPECTED);
  expect(result.verdict).toBe("one-sided");
  expect(result.buyer?.decision).toBe("pass");
  expect(result.seller).toBeUndefined();
  expect(result.abortedBySelfRole).toBe("seller");
  expect(result.abortedByOtherRole).toBe("buyer");
});

test("consumeBundles keeps divergent bundles for per-party policy", () => {
  const result = consumeBundles(VERIFY_DIVERGENT_JOB_ID, fixtures.fetchDivergent, fixtures.resolveKey, VERIFY_EXPECTED);
  expect(result.verdict).toBe("divergent");
  expect(result.verdict).not.toBe("disputed");
  expect(result.buyer?.decision).toBe("pass");
  expect(result.seller?.decision).toBe("pass");
  expect(bundleHash(result.buyer!.bundle)).not.toBe(bundleHash(result.seller!.bundle));
});

test("consumeBundles returns absent when neither expected side is present", () => {
  expect(consumeBundles("DACS-VERIFY-L3-ABSENT", fixtures.fetchAbsent, fixtures.resolveKey, VERIFY_EXPECTED)).toEqual({ verdict: "absent" });
});

test("isLegalTransition accepts table entries and ST-7 substrate resume", () => {
  expect(isLegalTransition("draft", "vet-pending")).toBe(true);
  expect(isLegalTransition("settle-completed", "finalised")).toBe(true);
  expect(isLegalTransition("substrate-failure-paused", "commit-pending")).toBe(true);
  expect(isLegalTransition("substrate-failure-paused", "failed-substrate")).toBe(true);
});

test("isLegalTransition rejects non-table and backward transitions", () => {
  expect(isLegalTransition("commit-completed", "negotiate-pending")).toBe(false);
  expect(isLegalTransition("finalised", "rate-pending")).toBe(false);
  expect(isLegalTransition("substrate-failure-paused", "finalised")).toBe(false);
  expect(isLegalTransition("rate-completed", "settle-pending")).toBe(false);
});

test("TERMINAL_STATES is exactly ST-6", () => {
  expect([...TERMINAL_STATES].sort()).toEqual([
    "aborted-by-other",
    "aborted-by-self",
    "commit-failed",
    "failed-substrate",
    "finalised",
    "negotiate-failed",
    "settle-failed",
    "vet-failed",
  ]);
});

test("stateToOutcome maps terminal states and errorClass partitions", () => {
  expect(stateToOutcome("finalised")).toBe("completed");
  expect(stateToOutcome("failed-substrate")).toBe("failed-substrate");
  expect(stateToOutcome("aborted-by-self")).toBe("aborted-by-self");
  expect(stateToOutcome("aborted-by-other")).toBe("aborted-by-other");
  expect(stateToOutcome("vet-failed", "permanent")).toBe("failed-perm");
  expect(stateToOutcome("negotiate-failed", "transient")).toBe("failed-perm");
  expect(stateToOutcome("commit-failed", "counterparty")).toBe("failed-counterparty");
  expect(stateToOutcome("settle-failed", "settlement-atomicity")).toBe("failed-counterparty");
  expect(stateToOutcome("settle-failed", "substrate")).toBeNull();
  expect(stateToOutcome("settle-pending")).toBeNull();
});

test("deriveReputation excludes failed-substrate from party fault denominator", () => {
  const derivation = deriveReputation(
    VERIFY_BUYER_CLAIM,
    anchoredBuyer,
    VERIFY_REPUTATION_WINDOW_START,
    VERIFY_REPUTATION_WINDOW_END,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(derivation.bundleCount).toBe(5);
  expect(derivation.metrics.completionRate).toBe(0.25);
  expect(derivation.metrics.counterpartyDisputeRate).toBe(0.5);
  expect(derivation.metrics.averageBuyerRating).toBeNull();
  expect(derivation.metrics.averageSellerRating).toBeNull();
  expect(derivation.metrics.observedTransactionalVolume).toEqual([]);
  expect(derivation.bundleRefs).toHaveLength(5);
});

test("deriveReputation returns null metrics, not zero, when denominator is zero", () => {
  const onlySubstrate = anchoredBuyer.filter((a) => a.bundle.outcome === "failed-substrate");
  const derivation = deriveReputation(
    VERIFY_BUYER_CLAIM,
    onlySubstrate,
    VERIFY_REPUTATION_WINDOW_START,
    VERIFY_REPUTATION_WINDOW_END,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(derivation.bundleCount).toBe(1);
  expect(derivation.metrics.completionRate).toBeNull();
  expect(derivation.metrics.counterpartyDisputeRate).toBeNull();
  expect(derivation.metrics.completionRate).not.toBe(0);
  expect(derivation.metrics.counterpartyDisputeRate).not.toBe(0);
});

test("deriveReputation filters by window and scoped party", () => {
  const outside = deriveReputation(
    VERIFY_BUYER_CLAIM,
    anchoredBuyer,
    VERIFY_REPUTATION_WINDOW_END + 1,
    VERIFY_REPUTATION_WINDOW_END + 2_000,
    VERIFY_REPUTATION_COMPUTED_AT,
  );
  expect(outside.bundleCount).toBe(1);
  expect(outside.metrics.completionRate).toBe(1);

  const empty = deriveReputation("did:demos:not-present", anchoredBuyer, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(empty.bundleCount).toBe(0);
  expect(empty.metrics.completionRate).toBeNull();
  expect(empty.metrics.counterpartyDisputeRate).toBeNull();
});

test("consumeBundles rejects a bundle whose role-party did not sign it (role-signature binding)", () => {
  // §10.4.2/§10.11: a seller-signed bundle placed at the buyer address is not the buyer's bundle → absent, not a
  // flipped one-sided provenance.
  expect(consumeBundles(VERIFY_MISANCHORED_JOB_ID, fixtures.fetchMisanchored, fixtures.resolveKey, VERIFY_EXPECTED).verdict).toBe("absent");
});

test("consumeBundles rejects a present side whose role signature does not verify", () => {
  // §10.4.2/§10.11: a one-sided buyer bundle whose buyer claim resolves to the wrong key does not verify → not present.
  const sellerKey = new Uint8Array(Buffer.from(fixtures.publicKeys[VERIFY_SELLER_CLAIM]!, "base64url"));
  const wrongKeyResolve = (claim: string): Uint8Array | null | undefined => (claim === VERIFY_BUYER_CLAIM ? sellerKey : fixtures.resolveKey(claim));
  expect(consumeBundles(VERIFY_ONE_SIDED_JOB_ID, fixtures.fetchOneSided, wrongKeyResolve, VERIFY_EXPECTED).verdict).toBe("absent");
});

test("twoSidedLookup ignores a fetched bundle whose embedded jobId differs (cross-session)", () => {
  // §10.4.3(a): the address is jobId-derived; a bundle for another session returned here is ignored.
  const fetch = makeBundleFetch("DACS-VERIFY-L3-OTHER", fixtures.divergentBuyer); // divergentBuyer.jobId = DACS-VERIFY-0004
  expect(twoSidedLookup("DACS-VERIFY-L3-OTHER", fetch)).toEqual({});
  expect(consumeBundles("DACS-VERIFY-L3-OTHER", fetch, fixtures.resolveKey, VERIFY_EXPECTED).verdict).toBe("absent");
});

test("deriveReputation counts a unified session once across both anchored copies; abort outcome is anchorer-relative", () => {
  const completedBundle = fixtures.reputationBundles.find((b) => b.outcome === "completed" && b.finalisedAt <= VERIFY_REPUTATION_WINDOW_END)!;
  const both = deriveReputation(VERIFY_BUYER_CLAIM, [{ bundle: completedBundle, anchoredBy: VERIFY_BUYER_CLAIM }, { bundle: completedBundle, anchoredBy: VERIFY_SELLER_CLAIM }], VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(both.bundleCount).toBe(1);
  // buyer-anchored bundles scored for the seller must not fault the seller
  const seller = deriveReputation(VERIFY_SELLER_CLAIM, anchoredBuyer, VERIFY_REPUTATION_WINDOW_START, VERIFY_REPUTATION_WINDOW_END, VERIFY_REPUTATION_COMPUTED_AT);
  expect(seller.bundleCount).toBe(0);
  expect(seller.metrics.counterpartyDisputeRate).toBeNull();
});
