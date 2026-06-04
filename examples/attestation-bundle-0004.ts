import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import { DOMAIN_SEPARATOR_REGISTRY } from "../src/signing.ts";
import { bundleHash, BUNDLE_SIGNED_SCOPE_OMIT, type AttestationBundle, type AttestationRef } from "../src/dacs5/index.ts";
import { keypairFromSeed, signArtifact } from "./issuer-kit.ts";

const BUYER_SEED = "a1".repeat(32);
const SELLER_SEED = "c3".repeat(32);

export const ATTESTATION_BUNDLE_0004_JOB_ID = "DACS-VERIFY-0004";
export const ATTESTATION_BUNDLE_0004_FINALISED_AT = 1_780_004_000_000;
export const ATTESTATION_BUNDLE_0004_BUYER_CLAIM = "did:demos:buyer";
export const ATTESTATION_BUNDLE_0004_SELLER_CLAIM = "did:demos:seller";
export const ATTESTATION_BUNDLE_HTLC9_JOB_ID = "DACS-VERIFY-HTLC9";
export const ATTESTATION_BUNDLE_HTLC9_FINALISED_AT = 1_780_009_000_000;
export const ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF = "polygon-amoy:0xreveal9c1a-htlc-reveal";

function ref(kind: string, id: string, doc: Record<string, unknown>): AttestationRef {
  return { kind, id, contentHash: sha256Hex(canonicalize(doc)) };
}

export function buildAttestationBundle0004(): {
  bundle: AttestationBundle;
  bundleHash: string;
  publicKeys: Record<string, string>;
  seeds: Record<string, string>;
} {
  const buyer = keypairFromSeed(BUYER_SEED);
  const seller = keypairFromSeed(SELLER_SEED);

  const listingRef = {
    listingId: "listing-dacs-verify-0004",
    version: 1,
    contentHash: sha256Hex(canonicalize({
      dacsVersion: "1",
      listingId: "listing-dacs-verify-0004",
      listingVersion: 1,
      seller: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
      pipeline: ["vet-counterparty", "settle-testnet"],
      price: "5",
      asset: "usdc",
    })),
  };

  const agreementRef = ref("dacs-3-agreement", "agreement-dacs-verify-0004", {
    agreementVersion: "1",
    jobId: ATTESTATION_BUNDLE_0004_JOB_ID,
    buyer: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
    seller: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
    listingRef,
    committedAt: ATTESTATION_BUNDLE_0004_FINALISED_AT - 8_000,
  });
  const vetRef = ref("dacs-4-evidence", "vet-dacs-verify-0004", {
    evidenceVersion: "1",
    jobId: ATTESTATION_BUNDLE_0004_JOB_ID,
    kind: "counterparty-vet",
    outcome: "ok",
    checkedAt: ATTESTATION_BUNDLE_0004_FINALISED_AT - 6_000,
  });
  const settlementRef = ref("dacs-4-evidence", "settlement-dacs-verify-0004", {
    evidenceVersion: "1",
    jobId: ATTESTATION_BUNDLE_0004_JOB_ID,
    phaseIndex: 0,
    kind: "settlement",
    outcome: "ok",
    txHash: "demos-testnet:tx-dacs-verify-0004-settle",
    checkedAt: ATTESTATION_BUNDLE_0004_FINALISED_AT - 1_000,
  });

  const unsigned: Omit<AttestationBundle, "signatures"> = {
    bundleVersion: "1",
    jobId: ATTESTATION_BUNDLE_0004_JOB_ID,
    outcome: "completed",
    anchoredByRole: "buyer",
    listingRef,
    agreementRef,
    parties: [
      {
        role: "buyer",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: ATTESTATION_BUNDLE_0004_BUYER_CLAIM, publicKey: buyer.publicKeyB64u })),
        primaryClaim: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
      },
      {
        role: "seller",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: ATTESTATION_BUNDLE_0004_SELLER_CLAIM, publicKey: seller.publicKeyB64u })),
        primaryClaim: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
      },
    ],
    phaseSummary: [
      { index: 0, kind: "vet-counterparty", outcome: "ok", attestationRef: vetRef },
      {
        index: 1,
        kind: "settle-testnet",
        outcome: "ok",
        txRefs: [{ rail: "demos-testnet", txHash: "demos-testnet:tx-dacs-verify-0004-settle", kind: "settlement" }],
        attestationRef: settlementRef,
      },
    ],
    vetRecords: [vetRef],
    settlementEvidence: [settlementRef],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: ATTESTATION_BUNDLE_0004_FINALISED_AT,
  };

  const signingDoc = { ...unsigned, signatures: [] };
  const separator = DOMAIN_SEPARATOR_REGISTRY["dacs-5-bundle"];
  const bundle: AttestationBundle = {
    ...unsigned,
    signatures: [
      {
        party: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
        algorithm: "ed25519",
        value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, buyer.privateKey, [...BUNDLE_SIGNED_SCOPE_OMIT]),
      },
      {
        party: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
        algorithm: "ed25519",
        value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, seller.privateKey, [...BUNDLE_SIGNED_SCOPE_OMIT]),
      },
    ],
  };

  return {
    bundle,
    bundleHash: bundleHash(bundle),
    publicKeys: {
      [ATTESTATION_BUNDLE_0004_BUYER_CLAIM]: buyer.publicKeyB64u,
      [ATTESTATION_BUNDLE_0004_SELLER_CLAIM]: seller.publicKeyB64u,
    },
    seeds: { buyer: BUYER_SEED, seller: SELLER_SEED },
  };
}

export function buildAttestationBundle0004Seller(): {
  bundle: AttestationBundle;
  bundleHash: string;
  publicKeys: Record<string, string>;
  seeds: Record<string, string>;
} {
  const buyer = keypairFromSeed(BUYER_SEED);
  const seller = keypairFromSeed(SELLER_SEED);

  const listingRef = {
    listingId: "listing-dacs-verify-0004",
    version: 1,
    contentHash: sha256Hex(canonicalize({
      dacsVersion: "1",
      listingId: "listing-dacs-verify-0004",
      listingVersion: 1,
      seller: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
      pipeline: ["vet-counterparty", "settle-testnet"],
      price: "5",
      asset: "usdc",
    })),
  };

  const agreementRef = ref("dacs-3-agreement", "agreement-dacs-verify-0004", {
    agreementVersion: "1",
    jobId: ATTESTATION_BUNDLE_0004_JOB_ID,
    buyer: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
    seller: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
    listingRef,
    committedAt: ATTESTATION_BUNDLE_0004_FINALISED_AT - 8_000,
  });
  const vetRef = ref("dacs-4-evidence", "vet-dacs-verify-0004", {
    evidenceVersion: "1",
    jobId: ATTESTATION_BUNDLE_0004_JOB_ID,
    kind: "counterparty-vet",
    outcome: "ok",
    checkedAt: ATTESTATION_BUNDLE_0004_FINALISED_AT - 6_000,
  });
  const settlementRef = ref("dacs-4-evidence", "settlement-dacs-verify-0004-seller", {
    evidenceVersion: "1",
    jobId: ATTESTATION_BUNDLE_0004_JOB_ID,
    phaseIndex: 0,
    kind: "settlement",
    outcome: "fail",
    errorClass: "counterparty",
    reason: "seller-observed-counterparty-non-performance",
    txHash: "demos-testnet:tx-dacs-verify-0004-seller-fail",
    checkedAt: ATTESTATION_BUNDLE_0004_FINALISED_AT - 1_000,
  });

  const unsigned: Omit<AttestationBundle, "signatures"> = {
    bundleVersion: "1",
    jobId: ATTESTATION_BUNDLE_0004_JOB_ID,
    outcome: "failed-counterparty",
    anchoredByRole: "seller",
    listingRef,
    agreementRef,
    parties: [
      {
        role: "buyer",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: ATTESTATION_BUNDLE_0004_BUYER_CLAIM, publicKey: buyer.publicKeyB64u })),
        primaryClaim: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
      },
      {
        role: "seller",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: ATTESTATION_BUNDLE_0004_SELLER_CLAIM, publicKey: seller.publicKeyB64u })),
        primaryClaim: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
      },
    ],
    phaseSummary: [
      { index: 0, kind: "vet-counterparty", outcome: "ok", attestationRef: vetRef },
      {
        index: 1,
        kind: "settle-testnet",
        outcome: "fail",
        errorClass: "counterparty",
        txRefs: [{ rail: "demos-testnet", txHash: "demos-testnet:tx-dacs-verify-0004-seller-fail", kind: "settlement-fail" }],
        attestationRef: settlementRef,
      },
    ],
    vetRecords: [vetRef],
    settlementEvidence: [settlementRef],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: ATTESTATION_BUNDLE_0004_FINALISED_AT,
  };

  const signingDoc = { ...unsigned, signatures: [] };
  const separator = DOMAIN_SEPARATOR_REGISTRY["dacs-5-bundle"];
  const bundle: AttestationBundle = {
    ...unsigned,
    signatures: [
      {
        party: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
        algorithm: "ed25519",
        value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, buyer.privateKey, [...BUNDLE_SIGNED_SCOPE_OMIT]),
      },
      {
        party: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
        algorithm: "ed25519",
        value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, seller.privateKey, [...BUNDLE_SIGNED_SCOPE_OMIT]),
      },
    ],
  };

  return {
    bundle,
    bundleHash: bundleHash(bundle),
    publicKeys: {
      [ATTESTATION_BUNDLE_0004_BUYER_CLAIM]: buyer.publicKeyB64u,
      [ATTESTATION_BUNDLE_0004_SELLER_CLAIM]: seller.publicKeyB64u,
    },
    seeds: { buyer: BUYER_SEED, seller: SELLER_SEED },
  };
}

export function buildAttestationBundleHtlc9(): {
  bundle: AttestationBundle;
  bundleHash: string;
  publicKeys: Record<string, string>;
  seeds: Record<string, string>;
} {
  const buyer = keypairFromSeed(BUYER_SEED);
  const seller = keypairFromSeed(SELLER_SEED);

  const listingRef = {
    listingId: "listing-dacs-verify-htlc9",
    version: 1,
    contentHash: sha256Hex(canonicalize({
      dacsVersion: "1",
      listingId: "listing-dacs-verify-htlc9",
      listingVersion: 1,
      seller: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
      pipeline: ["vet-counterparty", "pay-cross-chain-htlc"],
      acceptedRails: ["ethereum-sepolia", "polygon-amoy"],
      price: "5",
      asset: "usdc",
    })),
  };

  const agreementRef = ref("dacs-3-agreement", "agreement-dacs-verify-htlc9", {
    agreementVersion: "1",
    jobId: ATTESTATION_BUNDLE_HTLC9_JOB_ID,
    buyer: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
    seller: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
    listingRef,
    committedAt: ATTESTATION_BUNDLE_HTLC9_FINALISED_AT - 8_000,
  });
  const vetRef = ref("dacs-4-evidence", "vet-dacs-verify-htlc9", {
    evidenceVersion: "1",
    jobId: ATTESTATION_BUNDLE_HTLC9_JOB_ID,
    kind: "counterparty-vet",
    outcome: "ok",
    checkedAt: ATTESTATION_BUNDLE_HTLC9_FINALISED_AT - 6_000,
  });
  const settlementTxRefs = [
    { rail: "polygon-amoy", txHash: ATTESTATION_BUNDLE_HTLC9_REVEAL_TX_REF, kind: "htlc-reveal" },
    { rail: "ethereum-sepolia", txHash: "ethereum-sepolia:0xsource-unclaimed-htlc9", kind: "source-claim-unclaimed" },
  ];
  const settlementRef = ref("dacs-4-evidence", "settlement-dacs-verify-htlc9", {
    evidenceVersion: "1",
    jobId: ATTESTATION_BUNDLE_HTLC9_JOB_ID,
    phaseIndex: 0,
    kind: "cross-chain-htlc-settlement",
    outcome: "fail",
    errorClass: "settlement-atomicity",
    reason: "dest-revealed-source-unclaimed",
    txRefs: settlementTxRefs,
    checkedAt: ATTESTATION_BUNDLE_HTLC9_FINALISED_AT - 1_000,
  });

  const unsigned: Omit<AttestationBundle, "signatures"> = {
    bundleVersion: "1",
    jobId: ATTESTATION_BUNDLE_HTLC9_JOB_ID,
    outcome: "failed-counterparty",
    anchoredByRole: "buyer",
    listingRef,
    agreementRef,
    parties: [
      {
        role: "buyer",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: ATTESTATION_BUNDLE_0004_BUYER_CLAIM, publicKey: buyer.publicKeyB64u })),
        primaryClaim: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
      },
      {
        role: "seller",
        bundleHash: sha256Hex(canonicalize({ primaryClaim: ATTESTATION_BUNDLE_0004_SELLER_CLAIM, publicKey: seller.publicKeyB64u })),
        primaryClaim: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
      },
    ],
    phaseSummary: [
      { index: 0, kind: "vet-counterparty", outcome: "ok", attestationRef: vetRef },
      {
        index: 1,
        kind: "pay-cross-chain-htlc",
        outcome: "fail",
        errorClass: "settlement-atomicity",
        txRefs: settlementTxRefs,
        attestationRef: settlementRef,
      },
    ],
    vetRecords: [vetRef],
    settlementEvidence: [settlementRef],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: ATTESTATION_BUNDLE_HTLC9_FINALISED_AT,
  };

  const signingDoc = { ...unsigned, signatures: [] };
  const separator = DOMAIN_SEPARATOR_REGISTRY["dacs-5-bundle"];
  const bundle: AttestationBundle = {
    ...unsigned,
    signatures: [
      {
        party: ATTESTATION_BUNDLE_0004_BUYER_CLAIM,
        algorithm: "ed25519",
        value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, buyer.privateKey, [...BUNDLE_SIGNED_SCOPE_OMIT]),
      },
      {
        party: ATTESTATION_BUNDLE_0004_SELLER_CLAIM,
        algorithm: "ed25519",
        value: signArtifact(separator, signingDoc as unknown as Record<string, unknown>, seller.privateKey, [...BUNDLE_SIGNED_SCOPE_OMIT]),
      },
    ],
  };

  return {
    bundle,
    bundleHash: bundleHash(bundle),
    publicKeys: {
      [ATTESTATION_BUNDLE_0004_BUYER_CLAIM]: buyer.publicKeyB64u,
      [ATTESTATION_BUNDLE_0004_SELLER_CLAIM]: seller.publicKeyB64u,
    },
    seeds: { buyer: BUYER_SEED, seller: SELLER_SEED },
  };
}

export function emitAttestationBundle0004(outDir = join(import.meta.dir, "..", "conformance", "fixtures")): void {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "attestation-bundle-0004.json"), JSON.stringify(buildAttestationBundle0004().bundle, null, 2) + "\n");
}

export function emitAttestationBundle0004Seller(outDir = join(import.meta.dir, "..", "conformance", "fixtures")): void {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "attestation-bundle-0004-seller.json"), JSON.stringify(buildAttestationBundle0004Seller().bundle, null, 2) + "\n");
}

export function emitAttestationBundleHtlc9(outDir = join(import.meta.dir, "..", "conformance", "fixtures")): void {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "attestation-bundle-htlc9.json"), JSON.stringify(buildAttestationBundleHtlc9().bundle, null, 2) + "\n");
}

export function emitAttestationBundleFixtures(outDir = join(import.meta.dir, "..", "conformance", "fixtures")): void {
  emitAttestationBundle0004(outDir);
  emitAttestationBundle0004Seller(outDir);
  emitAttestationBundleHtlc9(outDir);
}

if (import.meta.main) {
  emitAttestationBundleFixtures();
}
