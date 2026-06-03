import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { DOMAIN_SEPARATOR_REGISTRY } from "../src/signing.ts";
import {
  bundleAddress,
  bundleHash,
  verifyBundle,
  type AttestationBundle,
  type AttestationRef,
  type BundleFetch,
  type BundleKeyResolver,
  type BundleOutcome,
  type BundlePhaseEntry,
  type BundleSignature,
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
}): AttestationBundle {
  const buyer = keypairFromSeed(BUYER_SEED);
  const seller = keypairFromSeed(SELLER_SEED);
  const listingRef = {
    listingId: `listing-${input.jobId.toLowerCase()}`,
    version: 1,
    contentHash: sha256Hex(canonicalize({
      dacsVersion: "1",
      listingId: `listing-${input.jobId.toLowerCase()}`,
      listingVersion: 1,
      seller: VERIFY_SELLER_CLAIM,
      pipeline: ["verify-l3"],
      price: "5",
      asset: "usdc",
    })),
  };
  const agreementRef = ref("dacs-3-agreement", `agreement-${input.jobId}`, {
    agreementVersion: "1",
    jobId: input.jobId,
    buyer: VERIFY_BUYER_CLAIM,
    seller: VERIFY_SELLER_CLAIM,
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
    listingRef,
    agreementRef,
    parties: [
      {
        role: "buyer",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: VERIFY_BUYER_CLAIM, publicKey: buyer.publicKeyB64u })),
        primaryClaim: VERIFY_BUYER_CLAIM,
      },
      {
        role: "seller",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: VERIFY_SELLER_CLAIM, publicKey: seller.publicKeyB64u })),
        primaryClaim: VERIFY_SELLER_CLAIM,
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
    ? [[VERIFY_BUYER_CLAIM, buyer]]
    : signerChoice === "seller"
      ? [[VERIFY_SELLER_CLAIM, seller]]
      : [[VERIFY_BUYER_CLAIM, buyer], [VERIFY_SELLER_CLAIM, seller]];
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
