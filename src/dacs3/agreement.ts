import { canonicalize } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { canonicalDecimal, isCanonicalDecimal } from "../decimal.ts";

// DACS-3 (Negotiate) — §8.5.2 listing-conformance validation of an
// AgreementDocument against its referenced listing. The value-independent checks
// (currency, price-band/equality, rail, deliverable, pattern) gate here; the two
// committedAt-relative checks (deadline, validity.notAfter) are re-evaluated
// against the ANCHORED committedAt (the SR-2 timestamp, §8.6), never the
// self-reported generatedAt. Signature presence/validity is CA-1..4, a separate
// category — this module is pure value-conformance.

export type PriceTerm = { amount: string; currency: string };

/** Listing pricing model (§8.8): fixed price or a negotiable band around a centre. */
export type ListingPricing =
  | { kind: "fixed"; price: PriceTerm }
  | { kind: "negotiable"; bandCenter: PriceTerm; minPct: number; maxPct: number };

/** The agreement's deliverable reference (§8.5): type + canonical hash + optional schema. */
export type DeliverableRef = { deliverableType: string; hash: string; schemaUrl?: string };

/** §8.5: optional reference-price snapshot both parties sign; informational, never agreement-validity-bearing. */
export type PriceAnchor = {
  price: string;
  attestationRef: { contentHash: string } & Record<string, unknown>;
} & Record<string, unknown>;

export type AgreementTerms = {
  price: PriceTerm;
  rail: string;
  deliverable: DeliverableRef;
  deadline: number; // unix ms
  priceAnchor?: PriceAnchor;
};

export type AgreementDocument = {
  derivedFromPattern: "fixed-price" | "rfq" | "sealed-envelope";
  terms: AgreementTerms;
} & Record<string, unknown>;

export type ListingForValidation = {
  pricing: ListingPricing;
  acceptedRails: string[];
  offering: { deliverable: { deliverableType: string; schemaUrl?: string } & Record<string, unknown> };
  pattern: "fixed-price" | "rfq" | "sealed-envelope";
  terms: { deadlineSecAfterCommit: number };
  validity?: { notBefore?: number; notAfter?: number };
};

export type AgreementValidation = { ok: true } | { ok: false; failedAt: string; reason: string };

/** DeliverableRef.hash = sha256(canonical_JCS(DeliverableSpec)), hex (§9.3 / §8.5.2). Hashed over the listing's offering.deliverable as anchored. */
export function deliverableSpecHash(spec: Record<string, unknown>): string {
  return sha256Hex(canonicalize(spec));
}

// ── exact signed-decimal arithmetic over CD-1 strings (BigInt fixed-point) ───
// The §8.5.2 band check is "full-precision decimal" and must not use float. We
// cross-multiply (price×100 vs bandCenter×(100±pct)) so division never appears.

type Dec = { neg: boolean; digits: bigint; scale: number };

function parseDec(raw: string): Dec {
  const c = canonicalDecimal(raw);
  const neg = c.startsWith("-");
  const body = neg ? c.slice(1) : c;
  const [int = "0", frac = ""] = body.split(".");
  return { neg: neg && !(int === "0" && frac === ""), digits: BigInt((int || "0") + frac), scale: frac.length };
}

function fmtDec(neg: boolean, digits: bigint, scale: number): string {
  let s = digits.toString();
  if (scale > 0) {
    s = s.padStart(scale + 1, "0");
    s = s.slice(0, s.length - scale) + "." + s.slice(s.length - scale);
  }
  return canonicalDecimal((neg && digits !== 0n ? "-" : "") + s);
}

function cmpDec(a: string, b: string): number {
  const pa = parseDec(a);
  const pb = parseDec(b);
  const scale = Math.max(pa.scale, pb.scale);
  const sa = (pa.neg ? -1n : 1n) * pa.digits * 10n ** BigInt(scale - pa.scale);
  const sb = (pb.neg ? -1n : 1n) * pb.digits * 10n ** BigInt(scale - pb.scale);
  return sa < sb ? -1 : sa > sb ? 1 : 0;
}

function mulDec(a: string, b: string): string {
  const pa = parseDec(a);
  const pb = parseDec(b);
  return fmtDec(pa.neg !== pb.neg, pa.digits * pb.digits, pa.scale + pb.scale);
}

function addSubDec(a: string, b: string, subtract: boolean): string {
  const pa = parseDec(a);
  const pb = parseDec(b);
  const scale = Math.max(pa.scale, pb.scale);
  const sa = (pa.neg ? -1n : 1n) * pa.digits * 10n ** BigInt(scale - pa.scale);
  const sb = (pb.neg !== subtract ? -1n : 1n) * pb.digits * 10n ** BigInt(scale - pb.scale);
  const sum = sa + sb;
  const neg = sum < 0n;
  return fmtDec(neg, neg ? -sum : sum, scale);
}

/** A finite, non-exponent JS number → CD-1 decimal string (for minPct/maxPct percentages). */
function numToDec(n: number): string {
  const s = String(n);
  if (!Number.isFinite(n) || /[eE]/.test(s)) throw new Error(`percentage not a plain finite decimal: ${s}`);
  return canonicalDecimal(s);
}

/** Inclusive negotiable band bounds [lower, upper] as CD-1 strings (§8.5.2). Exposed for golden vectors. */
export function negotiableBand(bandCenter: string, minPct: number, maxPct: number): { lower: string; upper: string } {
  // lower = bandCenter×(100−minPct)/100, upper = bandCenter×(100+maxPct)/100 — divided by 100 = scale shift.
  const lowerX100 = mulDec(bandCenter, addSubDec("100", numToDec(minPct), true));
  const upperX100 = mulDec(bandCenter, addSubDec("100", numToDec(maxPct), false));
  // divide by 100: subtract 2 from the implied scale by multiplying by "0.01".
  return { lower: mulDec(lowerX100, "0.01"), upper: mulDec(upperX100, "0.01") };
}

/**
 * §8.5.2 listing-conformance validation. `committedAt` is the anchored SR-2
 * commitment timestamp (§8.6), in unix ms — the objective anti-backdating clock,
 * NOT the agreement's self-reported generatedAt.
 */
export function validateAgreement(
  agreement: AgreementDocument,
  listing: ListingForValidation,
  committedAt: number,
): AgreementValidation {
  const t = agreement.terms;

  // Currency equality FIRST — a band/equality comparison across currencies MUST be rejected before any amount compare.
  const listingCurrency = listing.pricing.kind === "fixed" ? listing.pricing.price.currency : listing.pricing.bandCenter.currency;
  if (t.price.currency !== listingCurrency) {
    return { ok: false, failedAt: "currency", reason: `agreement currency ${t.price.currency} != listing ${listingCurrency}` };
  }

  // CD-1 (§8.5.1): the SIGNED terms.price.amount MUST be in minimal canonical form. §14.4 sanctions
  // "rejected per implementation policy"; we reject rather than silently normalize, so a producer's CD-1
  // violation surfaces instead of being masked — consistent with the DACS-4 settlement lane (which enforces
  // the same on the payment input == agreement price) and with the priceAnchor.price check below.
  if (!isCanonicalDecimal(t.price.amount)) {
    return { ok: false, failedAt: "price", reason: "terms.price.amount not CD-1 canonical (§8.5.1)" };
  }

  // Price-band / equality (CD-1 full-precision).
  if (listing.pricing.kind === "fixed") {
    if (cmpDec(t.price.amount, listing.pricing.price.amount) !== 0) {
      return { ok: false, failedAt: "price", reason: "fixed price != listed price (CD-1)" };
    }
  } else {
    const { bandCenter, minPct, maxPct } = listing.pricing;
    if (agreement.derivedFromPattern === "fixed-price") {
      // PS-3: a fixed-price agreement over negotiable pricing MUST equal bandCenter exactly, not merely lie within the band.
      if (cmpDec(t.price.amount, bandCenter.amount) !== 0) {
        return { ok: false, failedAt: "price", reason: "PS-3: fixed-price over negotiable must equal bandCenter exactly" };
      }
    } else {
      // price×100 ≥ bandCenter×(100−minPct) AND price×100 ≤ bandCenter×(100+maxPct) — inclusive, no division.
      const priceX100 = mulDec(t.price.amount, "100");
      const lowerX100 = mulDec(bandCenter.amount, addSubDec("100", numToDec(minPct), true));
      const upperX100 = mulDec(bandCenter.amount, addSubDec("100", numToDec(maxPct), false));
      if (cmpDec(priceX100, lowerX100) < 0) return { ok: false, failedAt: "price", reason: "price below band lower bound" };
      if (cmpDec(priceX100, upperX100) > 0) return { ok: false, failedAt: "price", reason: "price above band upper bound" };
    }
  }

  // Rail acceptance.
  if (!listing.acceptedRails.includes(t.rail)) {
    return { ok: false, failedAt: "rail", reason: `rail ${t.rail} not in listing.acceptedRails` };
  }

  // Deliverable conformance: deliverableType + canonical hash + schemaUrl (both absent, or both present and equal).
  const od = listing.offering.deliverable;
  if (t.deliverable.deliverableType !== od.deliverableType) {
    return { ok: false, failedAt: "deliverable", reason: "deliverableType != listing offering.deliverable kind" };
  }
  if (t.deliverable.hash !== deliverableSpecHash(od)) {
    return { ok: false, failedAt: "deliverable", reason: "deliverable hash != canonical DeliverableRef.hash of listing spec" };
  }
  const aSchema = t.deliverable.schemaUrl;
  const lSchema = od.schemaUrl;
  if ((aSchema === undefined) !== (lSchema === undefined) || (aSchema !== undefined && aSchema !== lSchema)) {
    return { ok: false, failedAt: "deliverable", reason: "schemaUrl mismatch" };
  }

  // Negotiation pattern.
  if (agreement.derivedFromPattern !== listing.pattern) {
    return { ok: false, failedAt: "pattern", reason: "derivedFromPattern != listing pipeline pattern" };
  }

  // committedAt-relative checks (anchored committedAt, NOT generatedAt).
  if (t.deadline > committedAt + listing.terms.deadlineSecAfterCommit * 1000) {
    return { ok: false, failedAt: "deadline", reason: "deadline > committedAt + deadlineSecAfterCommit" };
  }
  if (listing.validity?.notAfter !== undefined && listing.validity.notAfter < committedAt) {
    return { ok: false, failedAt: "notAfter", reason: "listing.validity.notAfter < committedAt (expired between read and commit)" };
  }

  // priceAnchor (optional): absence MUST NOT cause rejection; when present, price MUST be CD-1 and
  // attestationRef.contentHash MUST be present. `!= null` treats a JSON `null` the same as absent
  // (a verifier consuming external agreement JSON may see `"priceAnchor": null`) — not a crash.
  if (t.priceAnchor != null) {
    if (!isCanonicalDecimal(t.priceAnchor.price)) {
      return { ok: false, failedAt: "priceAnchor", reason: "priceAnchor.price not CD-1 canonical" };
    }
    if (typeof t.priceAnchor.attestationRef?.contentHash !== "string" || t.priceAnchor.attestationRef.contentHash.length === 0) {
      return { ok: false, failedAt: "priceAnchor", reason: "priceAnchor.attestationRef.contentHash missing" };
    }
  }

  return { ok: true };
}
