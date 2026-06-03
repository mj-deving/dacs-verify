import { sha256Hex } from "../hash.ts";
import { type ClaimReference } from "../dacs1.ts";
import type { PriceTerm } from "../dacs4/settlement.ts";
import {
  bundleHash,
  verifyBundle,
  type AttestationBundle,
  type AttestationRef,
  type BundleDecision,
  type BundleKeyResolver,
  type BundleOutcome,
} from "./bundle.ts";

export type BundleFetch = (storAddress: string) => AttestationBundle | null | undefined;

export type ConsumptionVerdict = "unified" | "one-sided" | "divergent" | "absent";

export interface ConsumptionResult {
  verdict: ConsumptionVerdict;
  buyer?: { bundle: AttestationBundle; decision: BundleDecision };
  seller?: { bundle: AttestationBundle; decision: BundleDecision };
  abortedBySelfRole?: "buyer" | "seller";
  abortedByOtherRole?: "buyer" | "seller";
}

export type SessionState =
  | "draft"
  | "vet-pending"
  | "vet-completed"
  | "vet-failed"
  | "negotiate-pending"
  | "negotiate-completed"
  | "negotiate-failed"
  | "commit-pending"
  | "commit-completed"
  | "commit-failed"
  | "settle-pending"
  | "settle-completed"
  | "settle-failed"
  | "rate-pending"
  | "rate-completed"
  | "substrate-failure-paused"
  | "failed-substrate"
  | "aborted-by-self"
  | "aborted-by-other"
  | "finalised";

export type TerminalState =
  | "finalised"
  | "vet-failed"
  | "negotiate-failed"
  | "commit-failed"
  | "settle-failed"
  | "failed-substrate"
  | "aborted-by-self"
  | "aborted-by-other";

export type ErrorClass =
  | "permanent"
  | "transient"
  | "counterparty"
  | "substrate"
  | "settlement-atomicity";

// §10.4.2/§10.5.1: a bundle paired with the party that ANCHORED it (its two-sided role-address). Reputation for a
// party is derived over the bundles that party anchored — the bundle's outcome is recorded from the anchorer's view.
export interface AnchoredBundle {
  bundle: AttestationBundle;
  anchoredBy: ClaimReference;
}

export interface ReputationDerivation {
  derivationVersion: "1";
  partyPrimaryClaim: ClaimReference;
  windowStart: number;
  windowEnd: number;
  bundleCount: number;
  metrics: {
    completionRate: number | null;
    counterpartyDisputeRate: number | null;
    averageBuyerRating: number | null;
    averageSellerRating: number | null;
    observedTransactionalVolume: PriceTerm[];
  };
  computedAt: number;
  bundleRefs: AttestationRef[];
}

const transitionSet = (states: SessionState[]): ReadonlySet<SessionState> => new Set(states);

const LEGAL_TRANSITIONS: ReadonlyMap<SessionState, ReadonlySet<SessionState>> = new Map([
  ["draft", transitionSet(["vet-pending"])],
  ["vet-pending", transitionSet(["vet-completed", "vet-failed", "substrate-failure-paused", "aborted-by-self", "aborted-by-other"])],
  ["vet-completed", transitionSet(["negotiate-pending"])],
  ["negotiate-pending", transitionSet(["negotiate-completed", "negotiate-failed", "substrate-failure-paused", "aborted-by-self", "aborted-by-other"])],
  ["negotiate-completed", transitionSet(["commit-pending"])],
  ["commit-pending", transitionSet(["commit-completed", "commit-failed", "substrate-failure-paused", "aborted-by-self", "aborted-by-other"])],
  ["commit-completed", transitionSet(["settle-pending"])],
  ["settle-pending", transitionSet(["settle-completed", "settle-failed", "substrate-failure-paused", "aborted-by-self", "aborted-by-other"])],
  ["settle-completed", transitionSet(["rate-pending", "finalised"])],
  ["rate-pending", transitionSet(["rate-completed", "finalised"])],
  ["rate-completed", transitionSet(["finalised"])],
  ["substrate-failure-paused", transitionSet(["vet-pending", "negotiate-pending", "commit-pending", "settle-pending", "failed-substrate"])],
]);

export const TERMINAL_STATES: ReadonlySet<SessionState> = new Set([
  "finalised",
  "vet-failed",
  "negotiate-failed",
  "commit-failed",
  "settle-failed",
  "failed-substrate",
  "aborted-by-self",
  "aborted-by-other",
]);

export function bundleAddress(jobId: string, role: "buyer" | "seller" | "orchestrator"): string {
  // §10.4.2: each role anchors at stor-{sha256(jobId + "-bundle-" + role)}.
  return `stor-${sha256Hex(`${jobId}-bundle-${role}`)}`;
}

export function twoSidedLookup(jobId: string, fetch: BundleFetch): { buyer?: AttestationBundle; seller?: AttestationBundle } {
  const buyer = fetch(bundleAddress(jobId, "buyer"));
  const seller = fetch(bundleAddress(jobId, "seller"));
  const result: { buyer?: AttestationBundle; seller?: AttestationBundle } = {};
  // §10.4.3(a): consumers MUST fetch both party-specific bundle addresses. The fetched bundle's embedded jobId MUST
  // match the looked-up jobId — the address is jobId-derived (§10.4.2), so a bundle for another session returned at
  // this address (replay / misreturn) is ignored, not consumed.
  if (buyer !== null && buyer !== undefined && buyer.jobId === jobId) result.buyer = buyer;
  if (seller !== null && seller !== undefined && seller.jobId === jobId) result.seller = seller;
  return result;
}

// §10.4.2/§10.11: a bundle at a role's address is that role's bundle ONLY if the EXTERNALLY-KNOWN party for that role
// (from the session/agreement the consumer is auditing) is a signer. The bundle's own `parties` role labels are
// untrusted — a signer can relabel its own claim into the "buyer" slot — so anchoring binds to the expected claim, NOT
// to the self-declared role. The §10.11 abort outcome is recorded from the signer's perspective, so a misattributed
// anchor would flip abort provenance and corrupt reputation.
function signedBy(bundle: AttestationBundle, expectedClaim: ClaimReference): boolean {
  return bundle.signatures.some((s) => s.party === expectedClaim);
}

export function consumeBundles(
  jobId: string,
  fetch: BundleFetch,
  resolveKey: BundleKeyResolver,
  expected: { buyer: ClaimReference; seller: ClaimReference },
): ConsumptionResult {
  const fetched = twoSidedLookup(jobId, fetch);
  // A side counts as present (for the verdict and abort provenance) ONLY if the expected party for that role is a signer
  // AND the bundle cryptographically verifies (decision "pass"). Storage is untrusted: a relabelled, merely-claimed, or
  // forged/unverifiable bundle MUST NOT drive abort provenance or reputation.
  const buyerDecision = fetched.buyer !== undefined && signedBy(fetched.buyer, expected.buyer) ? verifyBundle(fetched.buyer, resolveKey) : undefined;
  const sellerDecision = fetched.seller !== undefined && signedBy(fetched.seller, expected.seller) ? verifyBundle(fetched.seller, resolveKey) : undefined;
  const found: { buyer?: AttestationBundle; seller?: AttestationBundle } = {};
  // buyerDecision is only "pass" when fetched.buyer was defined and verified (see above), so the assertion is sound.
  if (buyerDecision === "pass") found.buyer = fetched.buyer!;
  if (sellerDecision === "pass") found.seller = fetched.seller!;

  if (found.buyer === undefined && found.seller === undefined) {
    // §10.4.3(a): neither expected address yielded a bundle for this session.
    return { verdict: "absent" };
  }

  if (found.buyer !== undefined && found.seller === undefined) {
    // §10.4.3(b)/§10.11: missing side is aborted-by-self; present signer is aborted-by-other.
    return {
      verdict: "one-sided",
      buyer: { bundle: found.buyer, decision: buyerDecision! },
      abortedBySelfRole: "seller",
      abortedByOtherRole: "buyer",
    };
  }

  if (found.buyer === undefined && found.seller !== undefined) {
    // §10.4.3(b)/§10.11: missing side is aborted-by-self; present signer is aborted-by-other.
    return {
      verdict: "one-sided",
      seller: { bundle: found.seller, decision: sellerDecision! },
      abortedBySelfRole: "buyer",
      abortedByOtherRole: "seller",
    };
  }

  const buyer = found.buyer!;
  const seller = found.seller!;
  const buyerEntry = { bundle: buyer, decision: buyerDecision! };
  const sellerEntry = { bundle: seller, decision: sellerDecision! };

  if (bundleHash(buyer) === bundleHash(seller)) {
    // §10.4.3(c): canonically equal bundles are the unified session bundle.
    return { verdict: "unified", buyer: buyerEntry, seller: sellerEntry };
  }

  // §10.4.3(d): canonically divergent bundles are a consumer-side disputed verdict;
  // both bundles stand on their own signatures for per-party policy.
  return { verdict: "divergent", buyer: buyerEntry, seller: sellerEntry };
}

export function isLegalTransition(from: SessionState, to: SessionState): boolean {
  // ST-1/ST-6/ST-7 (§10.3.1): only table-listed forward transitions are legal,
  // except substrate-failure-paused resume to the paused pending phase or failed-substrate.
  return LEGAL_TRANSITIONS.get(from)?.has(to) ?? false;
}

export function stateToOutcome(state: TerminalState, errorClass?: ErrorClass): BundleOutcome | null;
export function stateToOutcome(state: SessionState, errorClass?: ErrorClass): BundleOutcome | null;
export function stateToOutcome(state: SessionState, errorClass?: ErrorClass): BundleOutcome | null {
  switch (state) {
    case "finalised":
      // §10.3.1: finalised maps to completed.
      return "completed";
    case "failed-substrate":
      // §10.3.1: failed-substrate maps to failed-substrate.
      return "failed-substrate";
    case "aborted-by-self":
      // §10.3.1: aborted-by-self maps to aborted-by-self.
      return "aborted-by-self";
    case "aborted-by-other":
      // §10.3.1: aborted-by-other maps to aborted-by-other.
      return "aborted-by-other";
    case "vet-failed":
    case "negotiate-failed":
    case "commit-failed":
    case "settle-failed":
      if (errorClass === "permanent" || errorClass === "transient") {
        // §10.3.1: permanent failures and exhausted transient failures map to failed-perm.
        return "failed-perm";
      }
      if (errorClass === "counterparty" || errorClass === "settlement-atomicity") {
        // §10.3.1: counterparty and settlement-atomicity failures map to failed-counterparty.
        return "failed-counterparty";
      }
      // §10.3.1: terminal phase-failed states need a specified mapped error class.
      return null;
    default:
      // ST-6 (§10.3.1): non-terminal states do not derive bundle outcomes.
      return null;
  }
}

export function deriveReputation(
  party: ClaimReference,
  anchored: AnchoredBundle[],
  windowStart: number,
  windowEnd: number,
  computedAt: number,
): ReputationDerivation {
  // CONTRACT: `anchored` are the scored party's VERIFIED, consume-produced session bundles. Verification is the
  // §10.4.3 consumption boundary (consumeBundles gates on verifyBundle "pass"); §10.5.1 derive() operates on already-
  // verified bundles and is the METRIC boundary — it does not re-verify (that would diverge from the spec algorithm
  // and duplicate the consume gate). WINDOW: §10.5.1 (L3217) filters on `b.finalisedAt` — the spec-mandated field; an
  // anchor-time / anti-backdating window is a steward-facing spec question, not a verifier deviation (see ISA Decisions).
  // §10.5.1 (L3298): `scoped` restricts to bundles ANCHORED BY the scored party — the outcome (incl. aborted-by-self
  // vs aborted-by-other) is recorded from the anchoring party's perspective (§10.4.3/§10.11), NOT every bundle the
  // party merely appears in. Inclusive finalisedAt window. Dedupe by jobId so one session counts once even if both
  // two-sided copies are passed (the §10.4.3(c) unified case would otherwise double-count).
  const seen = new Set<string>();
  const scoped: AttestationBundle[] = [];
  for (const a of anchored) {
    if (a.anchoredBy !== party) continue;
    const b = a.bundle;
    if (b.finalisedAt < windowStart || b.finalisedAt > windowEnd) continue;
    if (seen.has(b.jobId)) continue;
    seen.add(b.jobId);
    scoped.push(b);
  }

  const completed = countOutcome(scoped, "completed");
  const failedCounterparty = countOutcome(scoped, "failed-counterparty");
  const failedSubstrate = countOutcome(scoped, "failed-substrate");
  const abortedByOther = countOutcome(scoped, "aborted-by-other");
  const partyFaultDenom = scoped.length - failedSubstrate;
  const counterpartyFaultCount = abortedByOther + failedCounterparty;

  // §10.5.1: RatingRecord and AgreementDocument resolution is out of L3 scope;
  // ratings stay null and observedTransactionalVolume stays empty until supplied by a future resolver.
  return {
    derivationVersion: "1",
    partyPrimaryClaim: party,
    windowStart,
    windowEnd,
    bundleCount: scoped.length,
    metrics: {
      completionRate: partyFaultDenom > 0 ? completed / partyFaultDenom : null,
      counterpartyDisputeRate: partyFaultDenom > 0 ? counterpartyFaultCount / partyFaultDenom : null,
      averageBuyerRating: null,
      averageSellerRating: null,
      observedTransactionalVolume: [],
    },
    computedAt,
    bundleRefs: scoped.map((b) => ({
      kind: "dacs-5-bundle",
      id: b.jobId,
      contentHash: bundleHash(b),
    })),
  };
}

function countOutcome(bundles: AttestationBundle[], outcome: BundleOutcome): number {
  return bundles.filter((b) => b.outcome === outcome).length;
}
