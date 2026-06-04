import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { DOMAIN_SEPARATOR_REGISTRY } from "../src/signing.ts";
import {
  bundleAddress,
  bundleHash,
  verifyBundle,
  type AnchoredByRole,
  type AttestationBundle,
  type AttestationRef,
  type BundleFetch,
  type BundleKeyResolver,
  type BundleOutcome,
  type BundlePhaseEntry,
  type BundleSignature,
  type AgreementPriceResolver,
  type RatingRecord,
  type RatingResolver,
} from "../src/dacs5/index.ts";
import { keypairFromSeed, signArtifact, type Keypair } from "./issuer-kit.ts";
import { buildAttestationBundle0004, buildAttestationBundle0004Seller } from "./attestation-bundle-0004.ts";

const BUYER_SEED = "a1".repeat(32);
const SELLER_SEED = "c3".repeat(32);

export const VERIFY_DIVERGENT_JOB_ID = "DACS-VERIFY-0004";
export const VERIFY_ONE_SIDED_JOB_ID = "DACS-VERIFY-L3-ONE-SIDED";
export const VERIFY_REPUTATION_WINDOW_START = 1_780_050_000_000;
export const VERIFY_REPUTATION_WINDOW_END = 1_780_050_010_000;
export const VERIFY_REPUTATION_COMPUTED_AT = 1_780_050_020_000;
export const VERIFY_BUYER_CLAIM = "did:demos:buyer";
export const VERIFY_SELLER_CLAIM = "did:demos:seller";
export const VERIFY_MISANCHORED_JOB_ID = "DACS-VERIFY-L3-MISANCHORED";
export const VERIFY_RATING_JOB_ID = "DACS-VERIFY-L3-RATING";
export const VERIFY_RECONCILE_JOB_ID = "DACS-VERIFY-L3-RECONCILE";
export const VERIFY_MIXEDROLE_JOB_ID = "DACS-VERIFY-L3-MIXEDROLE-B";

function ref(kind: string, id: string, doc: Record<string, unknown>): AttestationRef {
  return { kind, id, contentHash: sha256Hex(canonicalize(doc)) };
}

function publicKeys(buyer: Keypair, seller: Keypair): Record<string, string> {
  return {
    [VERIFY_BUYER_CLAIM]: buyer.publicKeyB64u,
    [VERIFY_SELLER_CLAIM]: seller.publicKeyB64u,
  };
}

function signBundle(unsigned: Omit<AttestationBundle, "signatures">, signers: [string, Keypair][]): AttestationBundle {
  const signingDoc = { ...unsigned, signatures: [] };
  const separator = DOMAIN_SEPARATOR_REGISTRY["dacs-5-bundle"];
  const signatures: BundleSignature[] = signers.map(([party, kp]) => ({
    party,
    algorithm: "ed25519",
    value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, kp.privateKey, ["signatures"]),
  }));
  return { ...unsigned, signatures };
}

function makeBundle(input: {
  jobId: string;
  outcome: BundleOutcome;
  finalisedAt: number;
  phase: BundlePhaseEntry;
  signers?: "both" | "buyer" | "seller";
  anchoredByRole?: AnchoredByRole;
  ratingRefs?: AttestationRef[];
  roleClaims?: { buyer: string; seller: string };
}): AttestationBundle {
  const buyer = keypairFromSeed(BUYER_SEED);
  const seller = keypairFromSeed(SELLER_SEED);
  // role → primaryClaim binding. Default: buyer-role=VERIFY_BUYER_CLAIM, seller-role=VERIFY_SELLER_CLAIM. A
  // `roleClaims` override lets a party play the OFF role (e.g. VERIFY_BUYER_CLAIM AS the seller in a mixed-role
  // session). Keypairs stay bound to the CLAIM (keys are claim-indexed via resolveKey), so the bundle is signed by
  // the role's claim with that claim's key and PASSES verifyBundle. The default reproduces prior fixtures byte-for-byte.
  const roleClaims = input.roleClaims ?? { buyer: VERIFY_BUYER_CLAIM, seller: VERIFY_SELLER_CLAIM };
  const kpForClaim = (claim: string): Keypair => (claim === VERIFY_SELLER_CLAIM ? seller : buyer);
  const buyerRoleKp = kpForClaim(roleClaims.buyer);
  const sellerRoleKp = kpForClaim(roleClaims.seller);
  const listingRef = {
    listingId: `listing-${input.jobId.toLowerCase()}`,
    version: 1,
    contentHash: sha256Hex(canonicalize({
      dacsVersion: "1",
      listingId: `listing-${input.jobId.toLowerCase()}`,
      listingVersion: 1,
      seller: roleClaims.seller,
      pipeline: ["verify-l3"],
      price: "5",
      asset: "usdc",
    })),
  };
  const agreementRef = ref("dacs-3-agreement", `agreement-${input.jobId}`, {
    agreementVersion: "1",
    jobId: input.jobId,
    buyer: roleClaims.buyer,
    seller: roleClaims.seller,
    listingRef,
    committedAt: input.finalisedAt - 5_000,
  });
  const evidenceRef = ref("dacs-4-evidence", `evidence-${input.jobId}`, {
    evidenceVersion: "1",
    jobId: input.jobId,
    outcome: input.phase.outcome,
    checkedAt: input.finalisedAt - 1_000,
  });
  const unsigned: Omit<AttestationBundle, "signatures"> = {
    bundleVersion: "1",
    jobId: input.jobId,
    outcome: input.outcome,
    anchoredByRole: input.anchoredByRole ?? "buyer",
    listingRef,
    agreementRef,
    ...(input.ratingRefs !== undefined ? { ratingRefs: input.ratingRefs } : {}),
    parties: [
      {
        role: "buyer",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: roleClaims.buyer, publicKey: buyerRoleKp.publicKeyB64u })),
        primaryClaim: roleClaims.buyer,
      },
      {
        role: "seller",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: roleClaims.seller, publicKey: sellerRoleKp.publicKeyB64u })),
        primaryClaim: roleClaims.seller,
      },
    ],
    phaseSummary: [{ ...input.phase, attestationRef: evidenceRef }],
    vetRecords: [],
    settlementEvidence: [evidenceRef],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: input.finalisedAt,
  };
  const signerChoice = input.signers ?? "both";
  const signers: [string, Keypair][] = signerChoice === "buyer"
    ? [[roleClaims.buyer, buyerRoleKp]]
    : signerChoice === "seller"
      ? [[roleClaims.seller, sellerRoleKp]]
      : [[roleClaims.buyer, buyerRoleKp], [roleClaims.seller, sellerRoleKp]];
  return signBundle(unsigned, signers);
}

export function makeBundleFetch(jobId: string, buyer?: AttestationBundle, seller?: AttestationBundle): BundleFetch {
  const entries = new Map<string, AttestationBundle>();
  if (buyer !== undefined) entries.set(bundleAddress(jobId, "buyer"), buyer);
  if (seller !== undefined) entries.set(bundleAddress(jobId, "seller"), seller);
  return (storAddress) => entries.get(storAddress);
}

export function buildSessionBundleFixtures(): {
  divergentBuyer: AttestationBundle;
  divergentSeller: AttestationBundle;
  oneSidedBuyer: AttestationBundle;
  misanchoredSellerBundle: AttestationBundle;
  reputationBundles: AttestationBundle[];
  ratingBundle: AttestationBundle;
  reconcileVictimBuyer: AttestationBundle;
  reconcileWithdrawerSeller: AttestationBundle;
  mixedRoleSellerBundle: AttestationBundle;
  resolveRating: RatingResolver;
  resolveAgreement: AgreementPriceResolver;
  publicKeys: Record<string, string>;
  seeds: Record<string, string>;
  resolveKey: BundleKeyResolver;
  fetchDivergent: BundleFetch;
  fetchUnified: BundleFetch;
  fetchOneSided: BundleFetch;
  fetchAbsent: BundleFetch;
  fetchMisanchored: BundleFetch;
  decisions: Record<string, string>;
} {
  const buyer = keypairFromSeed(BUYER_SEED);
  const seller = keypairFromSeed(SELLER_SEED);
  const divergentBuyer = buildAttestationBundle0004().bundle;
  const divergentSeller = buildAttestationBundle0004Seller().bundle;
  const oneSidedBuyer = makeBundle({
    jobId: VERIFY_ONE_SIDED_JOB_ID,
    outcome: "aborted-by-other",
    finalisedAt: VERIFY_REPUTATION_WINDOW_START + 1_000,
    phase: { index: 0, kind: "verify-one-sided", outcome: "fail", errorClass: "counterparty" },
    signers: "buyer",
  });
  // A seller-signed aborted-by-other bundle — used to verify that placing it at the BUYER address is rejected
  // (role-signature binding, §10.4.2/§10.11): the buyer-role party did not sign it, so it is not the buyer's bundle.
  const misanchoredSellerBundle = makeBundle({
    jobId: VERIFY_MISANCHORED_JOB_ID,
    outcome: "aborted-by-other",
    finalisedAt: VERIFY_REPUTATION_WINDOW_START + 6_000,
    phase: { index: 0, kind: "verify-misanchored", outcome: "fail", errorClass: "counterparty" },
    signers: "seller",
    anchoredByRole: "seller",
  });
  const reputationBundles = [
    makeBundle({
      jobId: "DACS-VERIFY-L3-REP-COMPLETED",
      outcome: "completed",
      finalisedAt: VERIFY_REPUTATION_WINDOW_START + 1_000,
      phase: { index: 0, kind: "verify-reputation", outcome: "ok" },
    }),
    makeBundle({
      jobId: "DACS-VERIFY-L3-REP-COUNTERPARTY",
      outcome: "failed-counterparty",
      finalisedAt: VERIFY_REPUTATION_WINDOW_START + 2_000,
      phase: { index: 0, kind: "verify-reputation", outcome: "fail", errorClass: "counterparty" },
    }),
    makeBundle({
      jobId: "DACS-VERIFY-L3-REP-SUBSTRATE",
      outcome: "failed-substrate",
      finalisedAt: VERIFY_REPUTATION_WINDOW_START + 3_000,
      phase: { index: 0, kind: "verify-reputation", outcome: "fail", errorClass: "substrate" },
    }),
    makeBundle({
      jobId: "DACS-VERIFY-L3-REP-ABORT-SELF",
      outcome: "aborted-by-self",
      finalisedAt: VERIFY_REPUTATION_WINDOW_START + 4_000,
      phase: { index: 0, kind: "verify-reputation", outcome: "fail", errorClass: "counterparty" },
      signers: "buyer",
    }),
    makeBundle({
      jobId: "DACS-VERIFY-L3-REP-ABORT-OTHER",
      outcome: "aborted-by-other",
      finalisedAt: VERIFY_REPUTATION_WINDOW_START + 5_000,
      phase: { index: 0, kind: "verify-reputation", outcome: "fail", errorClass: "counterparty" },
      signers: "buyer",
    }),
    makeBundle({
      jobId: "DACS-VERIFY-L3-REP-OUTSIDE",
      outcome: "completed",
      finalisedAt: VERIFY_REPUTATION_WINDOW_END + 1_000,
      phase: { index: 0, kind: "verify-reputation", outcome: "ok" },
    }),
  ];
  // §10.5.1 rating de-duplication fixture: a buyer-anchored completed bundle carrying THREE ratingRefs.
  // rating-a and rating-b share the SAME (rater=seller, jobId, targetRole=buyer) tuple with different ratedAt
  // (rating-b later → wins, value 5); rating-self is rater=buyer (the scored party) → excluded (no self-rating).
  const ratingT1 = VERIFY_REPUTATION_WINDOW_START + 100;
  const ratingT2 = VERIFY_REPUTATION_WINDOW_START + 200;
  const ratingRecordA: RatingRecord = {
    ratingVersion: "1", jobId: VERIFY_RATING_JOB_ID, rater: VERIFY_SELLER_CLAIM, target: VERIFY_BUYER_CLAIM,
    targetRole: "buyer", value: 3, ratedAt: ratingT1, signature: { algorithm: "ed25519", signer: VERIFY_SELLER_CLAIM, value: "rating-a-sig" },
  };
  const ratingRecordB: RatingRecord = {
    ratingVersion: "1", jobId: VERIFY_RATING_JOB_ID, rater: VERIFY_SELLER_CLAIM, target: VERIFY_BUYER_CLAIM,
    targetRole: "buyer", value: 5, ratedAt: ratingT2, signature: { algorithm: "ed25519", signer: VERIFY_SELLER_CLAIM, value: "rating-b-sig" },
  };
  const ratingRecordSelf: RatingRecord = {
    ratingVersion: "1", jobId: VERIFY_RATING_JOB_ID, rater: VERIFY_BUYER_CLAIM, target: VERIFY_SELLER_CLAIM,
    targetRole: "seller", value: 2, ratedAt: ratingT1, signature: { algorithm: "ed25519", signer: VERIFY_BUYER_CLAIM, value: "rating-self-sig" },
  };
  const ratingRecords: Record<string, RatingRecord> = { "rating-a": ratingRecordA, "rating-b": ratingRecordB, "rating-self": ratingRecordSelf };
  const ratingRefs: AttestationRef[] = [
    ref("dacs-5-rating", "rating-a", ratingRecordA as unknown as Record<string, unknown>),
    ref("dacs-5-rating", "rating-b", ratingRecordB as unknown as Record<string, unknown>),
    ref("dacs-5-rating", "rating-self", ratingRecordSelf as unknown as Record<string, unknown>),
  ];
  const ratingBundle = makeBundle({
    jobId: VERIFY_RATING_JOB_ID,
    outcome: "completed",
    finalisedAt: VERIFY_REPUTATION_WINDOW_START + 1_500,
    phase: { index: 0, kind: "rate", outcome: "ok" },
    anchoredByRole: "buyer",
    ratingRefs,
  });
  // §10.5.1 fetch_and_verify_rating / fetch_and_verify_agreement — deterministic in-memory resolvers. In production
  // these do the SR-2 anchor read + contentHash + signature verification; here they map a ref to its pinned record.
  const resolveRating: RatingResolver = (r) => ratingRecords[r.id] ?? null;
  const resolveAgreement: AgreementPriceResolver = (r) => (r.kind === "dacs-3-agreement" ? { amount: "5", currency: "usdc" } : null);

  // §10.5.1 two-sided reconciliation fixture: ONE jobId, TWO copies. The buyer (victim V) anchored
  // `aborted-by-other`; the seller (withdrawer W) anchored `aborted-by-self`. Each records the abort from ITS
  // anchorer's perspective. Scoring V over both copies must yield exactly ONE aborted-by-other (self_copy wins,
  // no double-count); scoring V over only W's copy must perspective_flip to aborted-by-other (§10.11 guarantee).
  const reconcileVictimBuyer = makeBundle({
    jobId: VERIFY_RECONCILE_JOB_ID,
    outcome: "aborted-by-other",
    finalisedAt: VERIFY_REPUTATION_WINDOW_START + 7_000,
    phase: { index: 0, kind: "verify-reconcile", outcome: "fail", errorClass: "counterparty" },
    signers: "buyer",
    anchoredByRole: "buyer",
  });
  const reconcileWithdrawerSeller = makeBundle({
    jobId: VERIFY_RECONCILE_JOB_ID,
    outcome: "aborted-by-self",
    finalisedAt: VERIFY_REPUTATION_WINDOW_START + 7_000,
    phase: { index: 0, kind: "verify-reconcile", outcome: "fail", errorClass: "counterparty" },
    signers: "seller",
    anchoredByRole: "seller",
  });
  // §10.5.1 mixed-role fixture: the scored claim (VERIFY_BUYER_CLAIM) genuinely plays the SELLER in THIS job — it is
  // the seller-role party AND the seller-anchored signer (roleClaims swap → signed by VERIFY_BUYER_CLAIM with its own
  // key). A REAL signed bundle that PASSES verifyBundle, not a mutated-signature copy: the per-job role-binding
  // regression must rest on honest conformance evidence. aborted-by-self is non-terminal-
  // required (§10.4.1) so the single anchorer signature suffices.
  const mixedRoleSellerBundle = makeBundle({
    jobId: VERIFY_MIXEDROLE_JOB_ID,
    outcome: "aborted-by-self",
    finalisedAt: VERIFY_REPUTATION_WINDOW_START + 8_000,
    phase: { index: 0, kind: "verify-mixedrole", outcome: "fail", errorClass: "counterparty" },
    signers: "seller",
    anchoredByRole: "seller",
    roleClaims: { buyer: VERIFY_SELLER_CLAIM, seller: VERIFY_BUYER_CLAIM },
  });

  const keys = new Map<string, Uint8Array>([
    [VERIFY_BUYER_CLAIM, buyer.publicKeyRaw],
    [VERIFY_SELLER_CLAIM, seller.publicKeyRaw],
  ]);
  const resolveKey: BundleKeyResolver = (claim) => keys.get(claim);
  return {
    divergentBuyer,
    divergentSeller,
    oneSidedBuyer,
    misanchoredSellerBundle,
    reputationBundles,
    ratingBundle,
    reconcileVictimBuyer,
    reconcileWithdrawerSeller,
    mixedRoleSellerBundle,
    resolveRating,
    resolveAgreement,
    publicKeys: publicKeys(buyer, seller),
    seeds: { buyer: BUYER_SEED, seller: SELLER_SEED },
    resolveKey,
    fetchDivergent: makeBundleFetch(VERIFY_DIVERGENT_JOB_ID, divergentBuyer, divergentSeller),
    fetchUnified: makeBundleFetch(VERIFY_DIVERGENT_JOB_ID, divergentBuyer, divergentBuyer),
    fetchOneSided: makeBundleFetch(VERIFY_ONE_SIDED_JOB_ID, oneSidedBuyer),
    fetchAbsent: makeBundleFetch("DACS-VERIFY-L3-ABSENT"),
    // the seller-signed bundle placed at the BUYER address (buyer slot) — role-signature binding must reject it.
    fetchMisanchored: makeBundleFetch(VERIFY_MISANCHORED_JOB_ID, misanchoredSellerBundle),
    decisions: {
      divergentBuyer: verifyBundle(divergentBuyer, resolveKey),
      divergentSeller: verifyBundle(divergentSeller, resolveKey),
      oneSidedBuyer: verifyBundle(oneSidedBuyer, resolveKey),
      reputationAll: reputationBundles.every((bundle) => verifyBundle(bundle, resolveKey) === "pass") ? "pass" : "fail",
      // the mixed-role seller-anchored bundle must independently verify — derive() assumes verified inputs (§10.4.3),
      // so an honest mixed-role conformance vector requires the fixture to PASS verifyBundle, not merely be shaped right.
      mixedRoleSellerBundle: verifyBundle(mixedRoleSellerBundle, resolveKey),
    },
  };
}

export function sessionBundleFixtureSummary(): Record<string, unknown> {
  const fixtures = buildSessionBundleFixtures();
  return {
    divergent: {
      jobId: VERIFY_DIVERGENT_JOB_ID,
      buyerBundleHash: bundleHash(fixtures.divergentBuyer),
      sellerBundleHash: bundleHash(fixtures.divergentSeller),
    },
    oneSided: {
      jobId: VERIFY_ONE_SIDED_JOB_ID,
      buyerBundleHash: bundleHash(fixtures.oneSidedBuyer),
    },
    reputation: fixtures.reputationBundles.map((bundle) => ({
      jobId: bundle.jobId,
      outcome: bundle.outcome,
      finalisedAt: bundle.finalisedAt,
      bundleHash: bundleHash(bundle),
    })),
    decisions: fixtures.decisions,
    seeds: fixtures.seeds,
  };
}
