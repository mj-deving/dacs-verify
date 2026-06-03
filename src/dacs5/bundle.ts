import { canonicalize, withoutSignature } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { verifyArtifactSignature } from "../signing.ts";
import { schemeOf, type ClaimReference } from "../dacs1.ts";

export type BundleDecision = "pass" | "fail" | "indeterminate" | "error";

export type BundleOutcome =
  | "completed"
  | "failed-perm"
  | "failed-counterparty"
  | "failed-substrate"
  | "aborted-by-self"
  | "aborted-by-other";

export type PhaseType = string;

export interface AttestationRef {
  kind: string;
  id: string;
  contentHash: string;
}

export interface ChainTxRef {
  rail: string;
  txHash: string;
  kind?: string;
}

export interface AttestationBundle {
  bundleVersion: "1";
  jobId: string;
  outcome: BundleOutcome;
  listingRef: { listingId: string; version: number; contentHash: string };
  agreementRef?: AttestationRef;
  parties: BundleParty[];
  phaseSummary: BundlePhaseEntry[];
  vetRecords: AttestationRef[];
  settlementEvidence: AttestationRef[];
  amendments?: AttestationRef[];
  ratingRefs?: AttestationRef[];
  recipeRegistryVersion: number;
  railRegistryVersion: number;
  finalisedAt: number;
  signatures: BundleSignature[];
}

export interface BundleParty {
  role: "buyer" | "seller" | "orchestrator";
  bundleHash: string;
  primaryClaim: ClaimReference;
}

export interface BundlePhaseEntry {
  index: number;
  kind: PhaseType;
  outcome: "ok" | "fail";
  errorClass?: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity";
  txRefs?: ChainTxRef[];
  attestationRef?: AttestationRef;
}

export interface BundleSignature {
  party: ClaimReference;
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate";
  value: string;
}

export type BundleKeyResolver = (party: ClaimReference) => Uint8Array | null | undefined;

const TERMINAL_REQUIRED_OUTCOMES: ReadonlySet<BundleOutcome> = new Set([
  "completed",
  "failed-perm",
  "failed-counterparty",
  "failed-substrate",
]);

const ALLOWED_OUTCOMES: ReadonlySet<string> = new Set([
  "completed",
  "failed-perm",
  "failed-counterparty",
  "failed-substrate",
  "aborted-by-self",
  "aborted-by-other",
]);

const HASH_RE = /^[0-9a-f]{64}$/;
const PARTY_ROLES: ReadonlySet<string> = new Set(["buyer", "seller", "orchestrator"]);
const PHASE_OUTCOMES: ReadonlySet<string> = new Set(["ok", "fail"]);
const ERROR_CLASSES: ReadonlySet<string> = new Set(["permanent", "transient", "counterparty", "substrate", "settlement-atomicity"]);
const SIGNATURE_ALGORITHMS: ReadonlySet<string> = new Set(["ed25519", "ecdsa-secp256k1", "sr1-aggregate"]);

export function bundleHash(bundle: AttestationBundle): string {
  return sha256Hex(canonicalize(withoutSignature(bundle as unknown as Record<string, unknown>, "signatures")));
}

export function verifyBundle(bundle: AttestationBundle, resolveKey: BundleKeyResolver): BundleDecision {
  try {
    if (!isStructurallySupported(bundle)) return "fail";
    if (bundle.signatures.length === 0) return "fail";

    const computedHash = bundleHash(bundle);
    if (!HASH_RE.test(computedHash)) return "error";

    const partyClaims = new Set(bundle.parties.map((p) => p.primaryClaim));
    for (const p of bundle.parties) {
      try {
        schemeOf(p.primaryClaim);
      } catch {
        return "fail";
      }
    }

    if (TERMINAL_REQUIRED_OUTCOMES.has(bundle.outcome)) {
      const required = requiredSignerClaims(bundle.parties);
      if (required === null) return "fail";
      const present = new Set(bundle.signatures.map((s) => s.party));
      for (const claim of required) {
        if (!present.has(claim)) return "fail";
      }
    }

    for (const sig of bundle.signatures) {
      if (sig.algorithm !== "ed25519") return "indeterminate";
      if (!partyClaims.has(sig.party)) return "fail";
      const publicKeyRaw = resolveKey(sig.party);
      if (publicKeyRaw === null || publicKeyRaw === undefined) return "indeterminate";
      if (publicKeyRaw.length !== 32) return "error";

      const signatureRaw = new Uint8Array(Buffer.from(sig.value, "base64url"));
      const result = verifyArtifactSignature({
        kind: "dacs-5-bundle",
        doc: bundle as unknown as Record<string, unknown>,
        publicKeyRaw,
        signatureRaw,
        signatureFields: ["signatures"],
      });
      if (result.artifactHash !== computedHash) return "error";
      if (!result.ok) return "fail";
    }

    return "pass";
  } catch {
    return "error";
  }
}

function requiredSignerClaims(parties: BundleParty[]): Set<ClaimReference> | null {
  const buyers = parties.filter((p) => p.role === "buyer").map((p) => p.primaryClaim);
  const sellers = parties.filter((p) => p.role === "seller").map((p) => p.primaryClaim);
  if (buyers.length === 0 || sellers.length === 0) return null;

  const required = new Set<ClaimReference>([...buyers, ...sellers]);
  // §10.4.1: "If the orchestrator is a distinct party (not buyer or seller), the
  // orchestrator signature is also REQUIRED." The !required.has() guard is that
  // "distinct" test — an orchestrator whose primaryClaim is already a buyer/seller
  // claim adds no new required signer; a distinct orchestrator's signature IS required.
  for (const p of parties) {
    if (p.role === "orchestrator" && !required.has(p.primaryClaim)) required.add(p.primaryClaim);
  }
  return required;
}

function isStructurallySupported(bundle: AttestationBundle): boolean {
  if (bundle.bundleVersion !== "1") return false;
  if (!ALLOWED_OUTCOMES.has(bundle.outcome)) return false;
  if (typeof bundle.jobId !== "string" || bundle.jobId.length === 0) return false;
  if (!bundle.listingRef || typeof bundle.listingRef.listingId !== "string") return false;
  if (!Number.isSafeInteger(bundle.listingRef.version)) return false;
  if (!HASH_RE.test(bundle.listingRef.contentHash)) return false;
  if (!Array.isArray(bundle.parties) || !Array.isArray(bundle.phaseSummary)) return false;
  if (!Array.isArray(bundle.vetRecords) || !Array.isArray(bundle.settlementEvidence)) return false;
  if (!Array.isArray(bundle.signatures)) return false;
  if (bundle.agreementRef !== undefined && !isAttestationRef(bundle.agreementRef)) return false;
  for (const party of bundle.parties) {
    if (!PARTY_ROLES.has(party.role)) return false;
    if (!HASH_RE.test(party.bundleHash)) return false;
    if (typeof party.primaryClaim !== "string" || party.primaryClaim.length === 0) return false;
  }
  for (const phase of bundle.phaseSummary) {
    if (!Number.isSafeInteger(phase.index)) return false;
    if (typeof phase.kind !== "string" || phase.kind.length === 0) return false;
    if (!PHASE_OUTCOMES.has(phase.outcome)) return false;
    if (phase.errorClass !== undefined && !ERROR_CLASSES.has(phase.errorClass)) return false;
    if (phase.attestationRef !== undefined && !isAttestationRef(phase.attestationRef)) return false;
    if (phase.txRefs !== undefined && (!Array.isArray(phase.txRefs) || phase.txRefs.some((tx) => typeof tx.rail !== "string" || typeof tx.txHash !== "string"))) return false;
  }
  if (bundle.vetRecords.some((r) => !isAttestationRef(r))) return false;
  if (bundle.settlementEvidence.some((r) => !isAttestationRef(r))) return false;
  if (bundle.amendments !== undefined && (!Array.isArray(bundle.amendments) || bundle.amendments.some((r) => !isAttestationRef(r)))) return false;
  if (bundle.ratingRefs !== undefined && (!Array.isArray(bundle.ratingRefs) || bundle.ratingRefs.some((r) => !isAttestationRef(r)))) return false;
  for (const sig of bundle.signatures) {
    if (typeof sig.party !== "string" || sig.party.length === 0) return false;
    if (!SIGNATURE_ALGORITHMS.has(sig.algorithm)) return false;
    if (typeof sig.value !== "string" || sig.value.length === 0) return false;
  }
  if (!Number.isSafeInteger(bundle.recipeRegistryVersion)) return false;
  if (!Number.isSafeInteger(bundle.railRegistryVersion)) return false;
  if (!Number.isSafeInteger(bundle.finalisedAt)) return false;
  return true;
}

function isAttestationRef(ref: AttestationRef): boolean {
  return typeof ref.kind === "string" && ref.kind.length > 0
    && typeof ref.id === "string" && ref.id.length > 0
    && HASH_RE.test(ref.contentHash);
}
