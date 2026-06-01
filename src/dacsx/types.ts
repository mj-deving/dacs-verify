import type { ClaimReference, BundleRequirement } from "../dacs1.ts";

// DACS-X (dispute / execution-verification) — PROPOSED extension types (§11.2.1).
//
// Field names follow DACS conventions: camelCase, claim references as strings
// (§6.3.1), content hashes as lowercase-hex sha256 of the JCS canonical form
// (§7.2). Every signed artifact carries its Ed25519 signature as base64url of
// the raw 64-byte value and is domain-separated under the SIG-4 `dacs-x-*`
// namespace. Per §7.1, fractional quantities (a reputation multiplier, a refund
// amount) are carried as CD-1 decimal STRINGS, never bare JSON numbers.

/** A reference to a contested AttestationBundle (DACS-5 §10). */
export interface DisputedBundleRef {
  jobId: string;
  /** sha256 hex of the bundle's signed scope (§7.2 content hash). */
  bundleHash: string;
}

export type ContestedClaimKind =
  | "non-delivery"
  | "mis-delivery"
  | "mis-classified-error"
  | "contested-amendment"
  | "divergent-bundle"; // the §10.4.3 two-sided-bundle disagreement

export type RequestedRemedyKind = "refund" | "reputation-correction" | "no-fault";

/**
 * The arbitration rule the parties agreed to at agreement time (§8.4.3).
 * Its content hash is the `rule-ref` a DisputeRecord pins to — binding the
 * arbitrator requirement BEFORE any dispute exists is what prevents either
 * party from swapping arbitrators after the outcome is known.
 */
export interface ArbitrationRule {
  /** Requirement an arbitrator's DACS-1 identity bundle must satisfy (DACS-1/2). */
  requirement: BundleRequirement;
  /** Optional explicit arbitrator allow-set, by primary claim reference. */
  arbitrators?: ClaimReference[];
  policyVersion: number;
}

/** dispute-open — signed by the initiating party's primary claim. */
export interface DisputeRecord {
  dacsXVersion: "1";
  disputeId: string;
  /** The initiating party's primary claim reference (§6.3). */
  initiator: ClaimReference;
  /** One or more bundles under dispute. */
  disputed: DisputedBundleRef[];
  contestedClaim: ContestedClaimKind;
  requestedRemedy: RequestedRemedyKind;
  /** Pins the agreed ArbitrationRule by content hash (§8.4.3 rule-ref). */
  arbitration: { ruleRef: string };
  openedAt: number;
  /** Ed25519 sig (base64url, raw) over the signed scope, dacs-x-dispute-record. */
  signature: string;
}

export interface RefundOrder {
  kind: "refund-ordered";
  /** CD-1 canonical decimal, strictly > 0 (§9.3). */
  amount: string;
  /** Asset / rail identifier; opaque to the verifier. */
  asset: string;
}

export interface ReputationCorrection {
  kind: "reputation-corrected";
  /** CD-1 canonical decimal in [0,1]; multiplier on the disputed contribution. */
  weightMultiplier: string;
  favors: "initiator" | "respondent";
}

export interface NoFault {
  kind: "no-fault";
}

export type RemedyDecision = RefundOrder | ReputationCorrection | NoFault;

/** Arbitrator-signed outcome — supersedes/annotates the disputed bundle (§10.10). */
export interface DisputeOutcome {
  dacsXVersion: "1";
  disputeId: string;
  /** sha256 hex of the DisputeRecord's signed scope — binds outcome to open. */
  disputeRecordHash: string;
  /** The arbitrator's primary claim reference. */
  arbitrator: ClaimReference;
  remedy: RemedyDecision;
  decidedAt: number;
  /** Ed25519 sig (base64url, raw) over the signed scope, dacs-x-dispute-outcome. */
  signature: string;
}

/**
 * A DACS-5 §10.5 session reputation contribution BEFORE adjudication — the
 * reweight input. In-memory derivation state, never signed or hashed.
 */
export interface SessionReputationContribution {
  jobId: string;
  /** Raw contribution weight from the (possibly disputed) session. */
  weight: number;
}

/**
 * Result of reweighting a contribution against an arbitrated outcome.
 *
 * NON-DESTRUCTIVE by design: the prior weight is PRESERVED (audit trail) and an
 * effective weight is derived from the remedy. A dispute record must be able to
 * show *why* a weight changed, so overwriting the original in place would defeat
 * the purpose. Whether the ratified standard ultimately wants a destructive
 * supersede or an append-only event log is an OPEN QUESTION for the group — this
 * prototype takes the non-destructive default and flags it.
 */
export interface ReputationReweight {
  jobId: string;
  /** Pre-dispute weight, retained for the audit trail. */
  priorWeight: number;
  /** Weight after adjudication, derived from the remedy. */
  effectiveWeight: number;
  adjudicated: true;
  /** Content hash of the DisputeOutcome that produced this reweight (provenance). */
  adjudicatedBy: string;
}
