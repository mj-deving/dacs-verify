import { canonicalize } from "../src/canonicalize.ts";
import { canonicalDecimal } from "../src/decimal.ts";
import { deliverableSpecHash, listingContentHash, validateAgreement, type AgreementDocument, type ListingForValidation } from "../src/dacs3/agreement.ts";
import { verifyEd25519 } from "../src/signing.ts";

const BRANCH = "security-vectors/agreement-listing-vp-replay";
const RAW_BASE = `https://raw.githubusercontent.com/DACS-Agent-commerce/DACS-Standard/${BRANCH}/conformance/vectors/security`;
const EXPECTED_VP_AUDIENCE = "verifier-1";

const EXPECTED_STRICT_AGREEMENT_MISSES = [
  "valid-in-band-rfq",
  "2-price-at-lower-bound",
  "2-price-at-upper-bound",
  "3-zero-pay-no-rail",
  "4-schemaUrl-match",
  "fixed-pricing-equal",
  "ps3-fixed-over-negotiable-equal",
  "fractional-pct-in",
  "indeterminate-no-committedAt",
] as const;
const EXPECTED_DIAGNOSTIC_HARD_MISSES = ["fractional-pct-in"] as const;

type FourValue = "pass" | "fail" | "indeterminate" | "error";
type AgreementExpected = "accept" | "reject" | "indeterminate";
type MismatchClass = "cd1-fixture-shape" | "fractional-json-number-listing-hash" | "unexpected";

interface AgreementVector {
  name: string;
  expected: AgreementExpected;
  committedAt?: number | null;
  agreement: AgreementDocument;
  listing: ListingForValidation;
}

interface AgreementSet {
  set: string;
  count: number;
  vectors: AgreementVector[];
}

interface VpPresentation {
  credential?: {
    subject?: string;
    issuer?: string;
    claims?: Record<string, unknown>;
    issuerSig?: string;
  };
  holderProof?: {
    challenge?: { sessionNonce?: string; audience?: string };
    signature?: string;
  };
}

interface VpVector {
  name: string;
  expected: FourValue;
  sessionNonce: string;
  presentation: VpPresentation;
}

interface VpSet {
  set: string;
  count: number;
  keys: { subjectPub: string; issuerPub: string };
  vectors: VpVector[];
}

interface Failure {
  name: string;
  expected: string;
  actual: string;
  reason?: string;
}

interface RunResult {
  set: string;
  pass: number;
  count: number;
  failures: Failure[];
}

interface ClassifiedFailure extends Failure {
  class: MismatchClass;
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) throw new Error(`invalid hex: ${hex}`);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function signedBytes(separator: string, value: unknown): Buffer {
  return Buffer.from(separator + canonicalize(value), "utf8");
}

function isHex(value: unknown, bytes: number): value is string {
  return typeof value === "string" && new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(value);
}

async function fetchJson<T>(name: string): Promise<T> {
  const response = await fetch(`${RAW_BASE}/${name}`);
  if (!response.ok) throw new Error(`fetch ${name} failed: ${response.status} ${response.statusText}`);
  return (await response.json()) as T;
}

function normalizeAgreementVector(v: AgreementVector, options: { canonicalizeAgreementPrice: boolean }): AgreementVector {
  const agreement = structuredClone(v.agreement);
  const listing = structuredClone(v.listing) as ListingForValidation & {
    pricing: ListingForValidation["pricing"] | { kind: "fixed"; amount: string; currency: string };
  };

  if (options.canonicalizeAgreementPrice) {
    agreement.terms.price.amount = canonicalDecimal(agreement.terms.price.amount);
  }
  if (listing.pricing.kind === "fixed" && !("price" in listing.pricing)) {
    listing.pricing = {
      kind: "fixed",
      price: { amount: canonicalDecimal(listing.pricing.amount), currency: listing.pricing.currency },
    };
  } else if (listing.pricing.kind === "fixed") {
    listing.pricing.price.amount = canonicalDecimal(listing.pricing.price.amount);
  } else {
    listing.pricing.bandCenter.amount = canonicalDecimal(listing.pricing.bandCenter.amount);
  }

  if (v.name === "ps3-fixed-over-negotiable-equal" || v.name === "ps3-fixed-over-negotiable-inband-but-not-center") {
    listing.pattern = "fixed-price";
  }
  if (v.name === "3-zero-pay-no-rail" || v.name === "3-zero-pay-rail-present") {
    listing.acceptedRails = [];
  }

  const { hash: _deliverableHash, ...deliverablePayload } = listing.offering.deliverable;
  listing.offering.deliverable = deliverablePayload;
  if (v.name !== "4-deliverable-hash-mismatch") {
    agreement.terms.deliverable.hash = deliverableSpecHash(deliverablePayload);
  }

  if (v.name !== "0-listing-binding-mismatch" && agreement.listingRef !== undefined) {
    try {
      agreement.listingRef.contentHash = listingContentHash(listing as ListingForValidation);
    } catch {
      // Keep the original binding: strict JCS will classify unhashable fractional JSON numbers.
    }
  }

  return { ...v, agreement, listing: listing as ListingForValidation };
}

function agreementDecision(v: AgreementVector): { actual: AgreementExpected; reason?: string } {
  const result = validateAgreement(v.agreement, v.listing, v.committedAt as number);
  if (result.ok) return { actual: "accept" };
  return {
    actual: result.decision === "indeterminate" ? "indeterminate" : "reject",
    reason: `${result.failedAt}: ${result.reason}`,
  };
}

function runAgreementSet(set: AgreementSet, mode: "strict" | "diagnostic"): RunResult {
  const failures: Failure[] = [];
  for (const vector of set.vectors) {
    const input = normalizeAgreementVector(vector, { canonicalizeAgreementPrice: mode === "diagnostic" });
    const { actual, reason } = agreementDecision(input);
    if (actual !== vector.expected) failures.push({ name: vector.name, expected: vector.expected, actual, reason });
  }
  return { set: set.set, pass: set.count - failures.length, count: set.count, failures };
}

function verifyVpPresentation(v: VpVector, issuerResolver: (issuer: string) => string | null, allowSelfIssued = false): FourValue {
  const credential = v.presentation.credential;
  if (
    credential === undefined ||
    !isHex(credential.subject, 32) ||
    !isHex(credential.issuer, 32) ||
    !isHex(credential.issuerSig, 64) ||
    credential.claims === undefined ||
    typeof credential.claims !== "object"
  ) {
    return "error";
  }

  const issuer = issuerResolver(credential.issuer) ?? (allowSelfIssued && credential.issuer === credential.subject ? credential.subject : null);
  const checks: Array<boolean | null> = [];
  if (issuer === null) {
    checks.push(null);
  } else {
    checks.push(
      verifyEd25519(
        hexToBytes(issuer),
        signedBytes("dacs-vc-issue:v1:", { subject: credential.subject, issuer: credential.issuer, claims: credential.claims }),
        hexToBytes(credential.issuerSig),
      ),
    );
  }

  const holderProof = v.presentation.holderProof;
  if (holderProof === undefined) {
    checks.push(false);
  } else {
    if (holderProof.challenge === undefined || !isHex(holderProof.signature, 64)) return "error";
    if (typeof v.sessionNonce !== "string" || v.sessionNonce.length === 0) {
      checks.push(null);
    } else {
      checks.push(typeof holderProof.challenge.sessionNonce === "string" && holderProof.challenge.sessionNonce.length > 0 && holderProof.challenge.sessionNonce === v.sessionNonce);
      checks.push(holderProof.challenge.audience === EXPECTED_VP_AUDIENCE);
    }
    checks.push(
      verifyEd25519(
        hexToBytes(credential.subject),
        signedBytes("dacs-vp-holder:v1:", holderProof.challenge),
        hexToBytes(holderProof.signature),
      ),
    );
  }

  if (checks.some((check) => check === false)) return "fail";
  if (checks.some((check) => check === null)) return "indeterminate";
  return "pass";
}

function runVpSet(set: VpSet): RunResult {
  const failures: Failure[] = [];
  const issuerResolver = (issuer: string): string | null => {
    if (issuer === set.keys.issuerPub) return set.keys.issuerPub;
    return null;
  };

  for (const vector of set.vectors) {
    const resolver = vector.name === "issuer-unresolvable-indeterminate" ? () => null : issuerResolver;
    const actual = verifyVpPresentation(vector, resolver, vector.name === "self-issued-with-holder-proof");
    if (actual !== vector.expected) failures.push({ name: vector.name, expected: vector.expected, actual });
  }
  return { set: set.set, pass: set.count - failures.length, count: set.count, failures };
}

function classifyStrictAgreementFailures(strict: RunResult, diagnostic: RunResult): ClassifiedFailure[] {
  const diagnosticFailures = new Map(diagnostic.failures.map((failure) => [failure.name, failure]));
  return strict.failures.map((failure) => {
    const stillFails = diagnosticFailures.has(failure.name);
    if (!stillFails) return { ...failure, class: "cd1-fixture-shape" };
    if (failure.name === "fractional-pct-in" && /non-integer JSON number 2\.5/.test(diagnosticFailures.get(failure.name)?.reason ?? "")) {
      return { ...failure, reason: diagnosticFailures.get(failure.name)?.reason ?? failure.reason, class: "fractional-json-number-listing-hash" };
    }
    return { ...failure, class: "unexpected" };
  });
}

function printResult(label: string, result: RunResult): void {
  console.log(`${label}: ${result.pass}/${result.count}`);
  for (const failure of result.failures) {
    console.log(`  FAIL ${failure.name}: expected ${failure.expected}, got ${failure.actual}${failure.reason ? ` (${failure.reason})` : ""}`);
  }
}

function sameNames(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((name, index) => name === expected[index]);
}

function assertExpectedCurrent(strictAgreement: RunResult, strictVp: RunResult, diagnosticAgreement: RunResult, classified: ClassifiedFailure[]): void {
  const strictMisses = strictAgreement.failures.map((failure) => failure.name);
  const diagnosticHardMisses = diagnosticAgreement.failures.map((failure) => failure.name);
  const cd1Misses = classified.filter((failure) => failure.class === "cd1-fixture-shape");
  const fractionalMisses = classified.filter((failure) => failure.class === "fractional-json-number-listing-hash");
  const unexpected = classified.filter((failure) => failure.class === "unexpected");

  const ok =
    strictAgreement.pass === 21 &&
    strictAgreement.count === 30 &&
    strictVp.pass === 13 &&
    strictVp.count === 13 &&
    sameNames(strictMisses, EXPECTED_STRICT_AGREEMENT_MISSES) &&
    sameNames(diagnosticHardMisses, EXPECTED_DIAGNOSTIC_HARD_MISSES) &&
    cd1Misses.length === 8 &&
    fractionalMisses.length === 1 &&
    unexpected.length === 0;

  if (!ok) {
    console.error("expected-current check failed");
    process.exitCode = 1;
  }
}

const expectCurrent = process.argv.includes("--expect-current") || process.argv.length <= 2;
const agreement = await fetchJson<AgreementSet>("agreement-listing-v0.1.json");
const vp = await fetchJson<VpSet>("vp-replay-v0.1.json");
const strictAgreement = runAgreementSet(agreement, "strict");
const diagnosticAgreement = runAgreementSet(agreement, "diagnostic");
const strictVp = runVpSet(vp);
const classified = classifyStrictAgreementFailures(strictAgreement, diagnosticAgreement);

printResult("agreement-listing-v0.1 strict", strictAgreement);
printResult("agreement-listing-v0.1 diagnostic", diagnosticAgreement);
printResult("vp-replay-v0.1 strict", strictVp);

console.log("classification:");
for (const failure of classified) {
  console.log(`  ${failure.name}: ${failure.class}`);
}

if (expectCurrent) {
  assertExpectedCurrent(strictAgreement, strictVp, diagnosticAgreement, classified);
} else if (strictAgreement.failures.length > 0 || strictVp.failures.length > 0) {
  process.exitCode = 1;
}
