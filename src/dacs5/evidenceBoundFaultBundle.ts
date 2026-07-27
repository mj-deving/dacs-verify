import { createPublicKey, verify as verifySignature } from "node:crypto";

import { canonicalize, withoutSignature } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { buildSignedBytes } from "../signing.ts";

const DOMAIN = "dacs-evidence-bound-fault-bundle:v1:";
const EVIDENCE_DOMAIN = "dacs-evidence:v1:";
const HASH = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

export type EvidenceBoundFaultBundleDecision = "accepted" | "rejected" | "indeterminate";

export interface ResolvedEvidenceAuthority {
  readonly artifactCanonicalJson: string;
  readonly phaseKey?: string | null;
  readonly supersedingEvidenceRef?: string | null;
}

interface AuthenticatedEvidenceAuthority {
  readonly jobId: string;
  readonly phaseIndex: number | null;
  readonly phaseKind: string;
  readonly recordClass: "ordinary-terminal" | "st8-resolved-success" | "st8-expired-interim-failure";
  readonly supersedesRef?: string;
  readonly supersededByRef?: string | null;
}

export interface EvidenceBoundFaultBundleInput {
  readonly artifactCanonicalJson: string;
  readonly expectedAnchoredByRole: string;
  readonly expectedJobId: string;
  readonly expectedPhaseKeys: readonly string[];
  readonly publicKeys: Readonly<Record<string, string>>;
  readonly resolvedEvidenceByRef: Readonly<Record<string, ResolvedEvidenceAuthority>>;
  readonly unrelatedAuthorityDisposition: "verified" | "indeterminate";
}

export interface EvidenceBoundFaultBundleResult {
  readonly decision: EvidenceBoundFaultBundleDecision;
  readonly code: string;
  readonly bundleHash?: string;
}

export interface EvidenceBoundSettlementVectorInput {
  readonly expectedPhaseKeys: readonly string[];
  readonly topLevelRefs: readonly string[];
  readonly resolvedReferencePhaseKeys: Readonly<Record<string, string>>;
  readonly pointerMap: Readonly<Record<string, string>>;
  readonly recordClassByRef?: Readonly<Record<string,
    "ordinary-terminal" | "st8-resolved-success" | "st8-expired-interim-failure">>;
  readonly supersedesEdges: Readonly<Record<string, string>>;
  readonly unrelatedAuthorityDisposition: "verified" | "indeterminate";
}

export function evaluateEvidenceBoundSettlementVector(
  input: EvidenceBoundSettlementVectorInput,
): Readonly<{ decision: EvidenceBoundFaultBundleDecision; code: string }> {
  const resolved = Object.fromEntries(Object.entries(input.resolvedReferencePhaseKeys).map(
    ([ref, phaseKey]) => {
      const separator = phaseKey.indexOf(":");
      return [ref, {
        jobId: "candidate-vector-job",
        phaseIndex: Number(phaseKey.slice(0, separator)),
        phaseKind: phaseKey.slice(separator + 1),
        recordClass: input.recordClassByRef?.[ref] ?? "ordinary-terminal",
        ...(input.supersedesEdges[ref] === undefined
          ? {} : { supersedesRef: input.supersedesEdges[ref] }),
      }];
    },
  ));
  const code = decideSettlementSet({
    expectedPhaseKeys: input.expectedPhaseKeys,
    expectedJobId: "candidate-vector-job",
    pointerMap: input.pointerMap,
    refs: input.topLevelRefs,
    resolved,
  });
  if (code !== "ok") return Object.freeze({ decision: "rejected", code });
  return input.unrelatedAuthorityDisposition === "indeterminate"
    ? Object.freeze({ decision: "indeterminate", code: "unrelated-authority-indeterminate" })
    : Object.freeze({ decision: "accepted", code: "ok" });
}

export function verifyEvidenceBoundFaultBundle(
  input: EvidenceBoundFaultBundleInput,
): EvidenceBoundFaultBundleResult {
  let bundle: Record<string, unknown>;
  try {
    const parsed = JSON.parse(input.artifactCanonicalJson) as unknown;
    if (!isRecord(parsed)) return reject("invalid-shape");
    bundle = parsed;
    if (canonicalize(bundle) !== input.artifactCanonicalJson) return reject("non-canonical-json");
  } catch {
    return reject("invalid-json");
  }
  if (!isRecord(input.publicKeys) || !isRecord(input.resolvedEvidenceByRef)) {
    return reject("invalid-authority-input");
  }
  if (!Array.isArray(input.expectedPhaseKeys)
    || input.expectedPhaseKeys.some((phaseKey) => typeof phaseKey !== "string"
      || !/^\d+:.+$/.test(phaseKey))
    || (input.unrelatedAuthorityDisposition !== "verified"
      && input.unrelatedAuthorityDisposition !== "indeterminate")) {
    return reject("invalid-authority-input");
  }

  const versionFields = ["bundleVersion", "faultBundleVersion", "evidenceBoundFaultBundleVersion"]
    .filter((field) => Object.hasOwn(bundle, field));
  if (versionFields.length !== 1 || versionFields[0] !== "evidenceBoundFaultBundleVersion"
    || bundle["evidenceBoundFaultBundleVersion"] !== "1") {
    return reject("unsupported-discriminator");
  }
  if (bundle["jobId"] !== input.expectedJobId) return reject("wrong-job");
  if (!Array.isArray(bundle["parties"]) || !Array.isArray(bundle["phaseSummary"])
    || !Array.isArray(bundle["settlementEvidence"]) || !Array.isArray(bundle["signatures"])) {
    return reject("invalid-shape");
  }

  const parties = bundle["parties"] as Record<string, unknown>[];
  const roles = new Map<string, string>();
  for (const party of parties) {
    if (!isRecord(party) || typeof party["role"] !== "string"
      || typeof party["primaryClaim"] !== "string" || roles.has(party["role"] as string)) {
      return reject("invalid-parties");
    }
    roles.set(party["role"] as string, party["primaryClaim"] as string);
  }
  if (!roles.has("buyer") || !roles.has("seller")) return reject("invalid-parties");
  const anchoredByRole = bundle["anchoredByRole"];
  if (typeof anchoredByRole !== "string" || !roles.has(anchoredByRole)
    || anchoredByRole !== input.expectedAnchoredByRole) {
    return reject("invalid-anchor-role");
  }
  const outcome = bundle["outcome"];
  const faultedParty = bundle["faultedParty"];
  if (typeof outcome !== "string" || typeof faultedParty !== "string"
    || !faultAttributionPermitted(outcome, faultedParty, anchoredByRole, new Set(roles.keys()))) {
    return reject("invalid-fault-attribution");
  }

  const phases = bundle["phaseSummary"] as Record<string, unknown>[];
  const seenPhaseKeys = new Set<string>();
  const pointers: Record<string, string> = {};
  for (const phase of phases) {
    if (!isRecord(phase) || !Number.isSafeInteger(phase["index"])
      || typeof phase["kind"] !== "string") return reject("invalid-phase-summary");
    const phaseKey = `${phase["index"]}:${phase["kind"]}`;
    if (seenPhaseKeys.has(phaseKey)) return reject("invalid-phase-summary");
    seenPhaseKeys.add(phaseKey);
    if (phase["attestationRef"] !== undefined && input.expectedPhaseKeys.includes(phaseKey)) {
      try { pointers[phaseKey] = canonicalize(phase["attestationRef"]); }
      catch { return reject("invalid-phase-pointer"); }
    }
  }
  if (seenPhaseKeys.size !== new Set(input.expectedPhaseKeys).size
    || input.expectedPhaseKeys.some((phaseKey) => !seenPhaseKeys.has(phaseKey))) {
    return reject("phase-authority-mismatch");
  }

  const refs: string[] = [];
  try {
    for (const ref of bundle["settlementEvidence"] as unknown[]) refs.push(canonicalize(ref));
  } catch {
    return reject("invalid-settlement-reference");
  }
  const evidenceAuthorities = authenticateEvidenceAuthorities(
    input.resolvedEvidenceByRef,
    input.publicKeys,
    refs,
    input.expectedPhaseKeys,
  );
  if (evidenceAuthorities.decision === "rejected") return reject(evidenceAuthorities.code);
  const seb = decideSettlementSet({
    expectedPhaseKeys: input.expectedPhaseKeys,
    expectedJobId: input.expectedJobId,
    pointerMap: pointers,
    refs,
    resolved: evidenceAuthorities.resolved,
  });
  if (seb !== "ok") return reject(seb);

  const signedScope = withoutSignature(bundle, "signatures", "anchoredByRole");
  const bundleHash = sha256Hex(canonicalize(signedScope));
  const signatures = bundle["signatures"] as Record<string, unknown>[];
  const signedClaims = new Set<string>();
  const unavailableClaims = new Set<string>(evidenceAuthorities.unavailableClaims);
  for (const signature of signatures) {
    if (!isRecord(signature) || signature["algorithm"] !== "ed25519"
      || typeof signature["party"] !== "string" || typeof signature["value"] !== "string"
      || signedClaims.has(signature["party"] as string)
      || ![...roles.values()].includes(signature["party"] as string)) {
      return reject("invalid-signature-envelope");
    }
    const party = signature["party"] as string;
    const value = decodeCanonicalSignature(signature["value"] as string);
    if (value === null) return reject("invalid-signature-encoding");
    const key = resolveBoundPublicKey(input.publicKeys, party);
    if (key.status === "unavailable") {
      unavailableClaims.add(party);
      signedClaims.add(party);
      continue;
    }
    if (key.status === "invalid") return reject("invalid-signer-key");
    try {
      const publicKey = createPublicKey({
        key: { kty: "OKP", crv: "Ed25519", x: key.raw.toString("base64url") },
        format: "jwk",
      });
      if (!verifySignature(null, buildSignedBytes(DOMAIN, bundleHash), publicKey, value)) {
        return reject("signature-domain-or-value-mismatch");
      }
    } catch {
      return reject("invalid-signer-key");
    }
    signedClaims.add(party);
  }
  for (const required of [roles.get("buyer")!, roles.get("seller")!, roles.get("orchestrator")]) {
    if (required !== undefined && !signedClaims.has(required)) return reject("missing-required-signature");
  }
  if (evidenceAuthorities.successorAuthorityUnavailable) {
    return indeterminate("st8-successor-authority-unavailable", bundleHash);
  }
  if (evidenceAuthorities.relationshipAuthorityUnavailable) {
    return indeterminate("st8-relationship-authority-unavailable", bundleHash);
  }
  if (evidenceAuthorities.mappingAuthorityUnavailable) {
    return indeterminate("phase-mapping-authority-unavailable", bundleHash);
  }
  if (unavailableClaims.size > 0) return indeterminate("signer-key-unavailable", bundleHash);

  return input.unrelatedAuthorityDisposition === "indeterminate"
    ? indeterminate("unrelated-authority-indeterminate", bundleHash)
    : Object.freeze({ decision: "accepted", code: "ok", bundleHash });
}

function authenticateEvidenceAuthorities(
  supplied: Readonly<Record<string, ResolvedEvidenceAuthority>>,
  publicKeys: Readonly<Record<string, string>>,
  topLevelRefs: readonly string[],
  expectedPhaseKeys: readonly string[],
): Readonly<{
  decision: "accepted" | "rejected";
  code: string;
  resolved: Readonly<Record<string, AuthenticatedEvidenceAuthority>>;
  unavailableClaims: readonly string[];
  successorAuthorityUnavailable: boolean;
  relationshipAuthorityUnavailable: boolean;
  mappingAuthorityUnavailable: boolean;
}> {
  const resolved: Record<string, AuthenticatedEvidenceAuthority> = {};
  const unavailableClaims = new Set<string>();
  let successorAuthorityUnavailable = false;
  let relationshipAuthorityUnavailable = false;
  let mappingAuthorityUnavailable = false;
  try {
    for (const [referenceKey, rawAuthority] of Object.entries(supplied)) {
      if (!isRecord(rawAuthority) || typeof rawAuthority["artifactCanonicalJson"] !== "string") {
        return rejectedEvidenceAuthorities("invalid-resolved-evidence-authority");
      }
      const reference = JSON.parse(referenceKey) as unknown;
      if (!isRecord(reference) || canonicalize(reference) !== referenceKey
        || !HASH.test(reference["contentHash"] as string)) {
        return rejectedEvidenceAuthorities("invalid-resolved-evidence-reference");
      }
      const evidence = JSON.parse(rawAuthority["artifactCanonicalJson"] as string) as unknown;
      if (!isRecord(evidence)
        || canonicalize(evidence) !== rawAuthority["artifactCanonicalJson"]
        || evidence["evidenceVersion"] !== "1"
        || typeof evidence["jobId"] !== "string"
        || typeof evidence["phase"] !== "string"
        || !isRecord(evidence["signature"])) {
        return rejectedEvidenceAuthorities("invalid-resolved-evidence-artifact");
      }
      const evidenceHash = sha256Hex(canonicalize(withoutSignature(evidence, "signature")));
      if (reference["contentHash"] !== evidenceHash) {
        return rejectedEvidenceAuthorities("resolved-evidence-content-hash-mismatch");
      }
      const signature = evidence["signature"];
      if (signature["algorithm"] !== "ed25519" || typeof signature["signer"] !== "string"
        || typeof signature["value"] !== "string"
        || reference["signer"] !== signature["signer"]) {
        return rejectedEvidenceAuthorities("invalid-resolved-evidence-signature");
      }
      const signatureValue = decodeCanonicalSignature(signature["value"]);
      if (signatureValue === null) {
        return rejectedEvidenceAuthorities("invalid-resolved-evidence-signature");
      }
      const key = resolveBoundPublicKey(publicKeys, signature["signer"]);
      if (key.status === "unavailable") {
        unavailableClaims.add(signature["signer"]);
      } else if (key.status === "invalid") {
        return rejectedEvidenceAuthorities("invalid-resolved-evidence-signer-key");
      } else {
        try {
          const publicKey = createPublicKey({
            key: { kty: "OKP", crv: "Ed25519", x: key.raw.toString("base64url") },
            format: "jwk",
          });
          if (!verifySignature(null, buildSignedBytes(EVIDENCE_DOMAIN, evidenceHash), publicKey, signatureValue)) {
            return rejectedEvidenceAuthorities("invalid-resolved-evidence-signature");
          }
        } catch {
          return rejectedEvidenceAuthorities("invalid-resolved-evidence-signer-key");
        }
      }

      const matchingPhaseKeys = expectedPhaseKeys.filter((key) => key.endsWith(`:${evidence["phase"]}`));
      if (topLevelRefs.includes(referenceKey) && matchingPhaseKeys.length === 0) {
        return rejectedEvidenceAuthorities("exact-phase-mapping");
      }
      const phaseKey = rawAuthority["phaseKey"];
      let phaseIndex: number | null = null;
      if (phaseKey === undefined || phaseKey === null) {
        if (topLevelRefs.includes(referenceKey)) mappingAuthorityUnavailable = true;
      } else if (typeof phaseKey !== "string" || !/^\d+:.+$/.test(phaseKey)) {
        return rejectedEvidenceAuthorities("invalid-phase-authority");
      } else {
        const separator = phaseKey.indexOf(":");
        phaseIndex = Number(phaseKey.slice(0, separator));
        if (!Number.isSafeInteger(phaseIndex)
          || phaseKey.slice(separator + 1) !== evidence["phase"]
          || !expectedPhaseKeys.includes(phaseKey)) {
          return rejectedEvidenceAuthorities("exact-phase-mapping");
        }
      }

      if (evidence["outcome"] !== "success" && evidence["outcome"] !== "failure") {
        return rejectedEvidenceAuthorities("invalid-resolved-evidence-outcome");
      }

      let recordClass: AuthenticatedEvidenceAuthority["recordClass"] = "ordinary-terminal";
      let supersedesRef: string | undefined;
      let supersededByRef: string | null | undefined;
      if (Object.hasOwn(evidence, "supersedesEvidenceRef")) {
        if (!isRecord(evidence["supersedesEvidenceRef"])) {
          return rejectedEvidenceAuthorities("invalid-st8-supersedes-reference");
        }
        if ((evidence["phase"] !== "pay-cross-chain-htlc"
          && evidence["phase"] !== "pay-cross-chain-liquidity-tank")
          || evidence["outcome"] !== "success") {
          return rejectedEvidenceAuthorities("contradictory-st8-record-class");
        }
        recordClass = "st8-resolved-success";
        supersedesRef = canonicalize(evidence["supersedesEvidenceRef"]);
      } else if (evidence["outcome"] === "failure"
        && (evidence["reason"] === "dest-revealed-source-unclaimed"
          || evidence["reason"] === "tank-locked-unreleased")) {
        if (evidence["phase"] !== "pay-cross-chain-htlc"
          && evidence["phase"] !== "pay-cross-chain-liquidity-tank") {
          return rejectedEvidenceAuthorities("contradictory-st8-record-class");
        }
        recordClass = "st8-expired-interim-failure";
        if (!Object.hasOwn(rawAuthority, "supersedingEvidenceRef")) {
          successorAuthorityUnavailable = true;
        } else if (rawAuthority["supersedingEvidenceRef"] === null) {
          successorAuthorityUnavailable = true;
        } else if (typeof rawAuthority["supersedingEvidenceRef"] === "string") {
          const successor = JSON.parse(rawAuthority["supersedingEvidenceRef"] as string) as unknown;
          if (!isRecord(successor) || canonicalize(successor) !== rawAuthority["supersedingEvidenceRef"]) {
            return rejectedEvidenceAuthorities("invalid-st8-successor-reference");
          }
          supersededByRef = rawAuthority["supersedingEvidenceRef"] as string;
        } else {
          return rejectedEvidenceAuthorities("invalid-st8-successor-reference");
        }
      } else if (Object.hasOwn(rawAuthority, "supersedingEvidenceRef")) {
        return rejectedEvidenceAuthorities("contradictory-st8-authority");
      }
      resolved[referenceKey] = Object.freeze({
        jobId: evidence["jobId"] as string,
        phaseIndex,
        phaseKind: evidence["phase"] as string,
        recordClass,
        ...(supersedesRef === undefined ? {} : { supersedesRef }),
        ...(supersededByRef === undefined ? {} : { supersededByRef }),
      });
    }
    for (const [referenceKey, authority] of Object.entries(resolved)) {
      if (authority.recordClass === "st8-resolved-success") {
        const predecessor = authority.supersedesRef === undefined
          ? undefined : resolved[authority.supersedesRef];
        if (predecessor === undefined) {
          relationshipAuthorityUnavailable = true;
        } else if (predecessor.recordClass !== "st8-expired-interim-failure"
          || predecessor.jobId !== authority.jobId
          || predecessor.phaseKind !== authority.phaseKind
          || predecessor.supersededByRef !== referenceKey) {
          return rejectedEvidenceAuthorities("invalid-st8-predecessor-authority");
        } else if (predecessor.phaseIndex === null || authority.phaseIndex === null) {
          mappingAuthorityUnavailable = true;
        } else if (predecessor.phaseIndex !== authority.phaseIndex) {
          return rejectedEvidenceAuthorities("invalid-st8-predecessor-authority");
        }
      } else if (typeof authority.supersededByRef === "string") {
        const successor = resolved[authority.supersededByRef];
        if (successor === undefined) {
          relationshipAuthorityUnavailable = true;
        } else if (successor.recordClass !== "st8-resolved-success"
          || successor.supersedesRef !== referenceKey
          || successor.jobId !== authority.jobId
          || successor.phaseKind !== authority.phaseKind) {
          return rejectedEvidenceAuthorities("invalid-st8-successor-authority");
        } else if (successor.phaseIndex === null || authority.phaseIndex === null) {
          mappingAuthorityUnavailable = true;
        } else if (successor.phaseIndex !== authority.phaseIndex) {
          return rejectedEvidenceAuthorities("invalid-st8-successor-authority");
        }
      }
    }
  } catch {
    return rejectedEvidenceAuthorities("invalid-resolved-evidence-authority");
  }
  return Object.freeze({
    decision: "accepted" as const,
    code: "ok",
    resolved: Object.freeze(resolved),
    unavailableClaims: Object.freeze([...unavailableClaims]),
    successorAuthorityUnavailable,
    relationshipAuthorityUnavailable,
    mappingAuthorityUnavailable,
  });
}

function rejectedEvidenceAuthorities(code: string) {
  return Object.freeze({
    decision: "rejected" as const,
    code,
    resolved: Object.freeze({}) as Readonly<Record<string, AuthenticatedEvidenceAuthority>>,
    unavailableClaims: Object.freeze([]) as readonly string[],
    successorAuthorityUnavailable: false,
    relationshipAuthorityUnavailable: false,
    mappingAuthorityUnavailable: false,
  });
}

function decideSettlementSet(input: Readonly<{
  expectedPhaseKeys: readonly string[];
  expectedJobId: string;
  pointerMap: Readonly<Record<string, string>>;
  refs: readonly string[];
  resolved: Readonly<Record<string, AuthenticatedEvidenceAuthority>>;
}>): string {
  if (new Set(input.refs).size !== input.refs.length) return "raw-multiplicity";
  if (new Set(input.expectedPhaseKeys).size !== input.expectedPhaseKeys.length) {
    return "exact-phase-mapping";
  }
  const supersedes = new Map<string, string>();
  for (const [ref, authority] of Object.entries(input.resolved)) {
    if (authority.supersedesRef !== undefined) supersedes.set(ref, authority.supersedesRef);
    if (typeof authority.supersededByRef === "string") {
      supersedes.set(authority.supersededByRef, ref);
    }
  }
  for (const [successor, interim] of supersedes) {
    if (!input.refs.includes(successor) || input.refs.includes(interim)) return "st8-raw-admissibility";
  }
  for (const ref of input.refs) {
    const authority = input.resolved[ref];
    if (authority?.recordClass === "st8-resolved-success" && !supersedes.has(ref)) {
      return "st8-raw-admissibility";
    }
    if (authority === undefined || authority.jobId !== input.expectedJobId
      || typeof authority.phaseKind !== "string") return "exact-phase-mapping";
    if (authority.phaseIndex !== null
      && (!Number.isSafeInteger(authority.phaseIndex)
        || !input.expectedPhaseKeys.includes(`${authority.phaseIndex}:${authority.phaseKind}`))) {
      return "exact-phase-mapping";
    }
  }
  if (input.refs.length !== input.expectedPhaseKeys.length) return "exact-cardinality";
  const expectedKinds = new Map<string, number>();
  for (const phaseKey of input.expectedPhaseKeys) {
    const kind = phaseKey.slice(phaseKey.indexOf(":") + 1);
    expectedKinds.set(kind, (expectedKinds.get(kind) ?? 0) + 1);
  }
  const resolvedKinds = new Map<string, number>();
  for (const ref of input.refs) {
    const kind = input.resolved[ref]!.phaseKind;
    resolvedKinds.set(kind, (resolvedKinds.get(kind) ?? 0) + 1);
  }
  if (expectedKinds.size !== resolvedKinds.size
    || [...expectedKinds].some(([kind, count]) => resolvedKinds.get(kind) !== count)) {
    return "exact-bijection";
  }
  const mapped = input.refs.flatMap((ref) => {
    const authority = input.resolved[ref]!;
    return authority.phaseIndex === null ? [] : [`${authority.phaseIndex}:${authority.phaseKind}`];
  });
  if (new Set(mapped).size !== mapped.length) return "exact-bijection";
  if (
    mapped.length === input.refs.length
    && (
      new Set(mapped).size !== new Set(input.expectedPhaseKeys).size
      || input.expectedPhaseKeys.some((key) => !mapped.includes(key))
    )
  ) return "exact-bijection";
  const pointerRefs = Object.values(input.pointerMap);
  if (new Set(pointerRefs).size !== pointerRefs.length) return "pointer-agreement";
  const knownPhaseOwners = new Map<string, string>();
  for (const ref of input.refs) {
    const authority = input.resolved[ref]!;
    if (authority.phaseIndex !== null) {
      knownPhaseOwners.set(`${authority.phaseIndex}:${authority.phaseKind}`, ref);
    }
  }
  for (const [phaseKey, ref] of Object.entries(input.pointerMap)) {
    const authority = input.resolved[ref];
    const pointerKind = phaseKey.slice(phaseKey.indexOf(":") + 1);
    if (!input.refs.includes(ref) || authority === undefined
      || authority.phaseKind !== pointerKind
      || (authority.phaseIndex !== null
        && `${authority.phaseIndex}:${authority.phaseKind}` !== phaseKey)
      || (authority.phaseIndex === null
        && knownPhaseOwners.has(phaseKey)
        && knownPhaseOwners.get(phaseKey) !== ref)) return "pointer-agreement";
  }
  return "ok";
}

function faultAttributionPermitted(
  outcome: string,
  faultedParty: string,
  anchoredByRole: string,
  roles: ReadonlySet<string>,
): boolean {
  if (outcome === "completed" || outcome === "failed-substrate") return faultedParty === "none";
  if (outcome === "failed-perm" || outcome === "aborted-by-self") return faultedParty === anchoredByRole;
  if (outcome === "failed-counterparty" || outcome === "aborted-by-other") {
    return roles.has(faultedParty) && faultedParty !== anchoredByRole;
  }
  return false;
}

function decodeCanonicalSignature(value: string): Buffer | null {
  if (!BASE64URL.test(value) || value.length % 4 === 1) return null;
  const decoded = Buffer.from(value, "base64url");
  return decoded.byteLength === 64 && decoded.toString("base64url") === value ? decoded : null;
}

function resolveBoundPublicKey(
  publicKeys: Readonly<Record<string, string>>,
  claim: string,
): Readonly<{ status: "unavailable" }>
  | Readonly<{ status: "invalid" }>
  | Readonly<{ status: "verified"; raw: Buffer }> {
  if (!Object.hasOwn(publicKeys, claim)) return Object.freeze({ status: "unavailable" as const });
  const encoded = publicKeys[claim];
  if (typeof encoded !== "string" || !BASE64URL.test(encoded)) {
    return Object.freeze({ status: "invalid" as const });
  }
  try {
    const raw = Buffer.from(encoded, "base64url");
    const claimMatch = /^key:([0-9a-f]{64})$/.exec(claim);
    if (raw.byteLength !== 32 || raw.toString("base64url") !== encoded
      || claimMatch === null || raw.toString("hex") !== claimMatch[1]) {
      return Object.freeze({ status: "invalid" as const });
    }
    return Object.freeze({ status: "verified" as const, raw });
  } catch {
    return Object.freeze({ status: "invalid" as const });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code: string): EvidenceBoundFaultBundleResult {
  return Object.freeze({ decision: "rejected", code });
}

function indeterminate(code: string, bundleHash: string): EvidenceBoundFaultBundleResult {
  return Object.freeze({ decision: "indeterminate", code, bundleHash });
}
