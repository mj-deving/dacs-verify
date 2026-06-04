import { canonicalize } from "../src/canonicalize.ts";
import { sha256Hex } from "../src/hash.ts";
import {
  evidenceHash,
  paymentEvidenceAddress,
  type PaymentPhaseInput,
  type PhaseHandlerResult,
  type SettlementEvidence,
} from "../src/dacs4/index.ts";
import type { ClaimReference } from "../src/dacs1.ts";
import { keypairFromSeed, signArtifact } from "./issuer-kit.ts";

const ORCHESTRATOR_SEED = "e4".repeat(32);
const PAYER_SEED = "a1".repeat(32);
const PAYEE_SEED = "c3".repeat(32);

export const SETTLEMENT_EVIDENCE_PAYMENT_JOB_ID = "DACS-VERIFY-SETTLE-0001";
export const SETTLEMENT_EVIDENCE_DELIVERY_JOB_ID = "DACS-VERIFY-DELIVER-0001";
export const SETTLEMENT_EVIDENCE_NOW = 1_780_014_400_000;
export const SETTLEMENT_ORCHESTRATOR_CLAIM = "did:demos:orchestrator";
export const SETTLEMENT_PAYER_CLAIM = "did:demos:buyer";
export const SETTLEMENT_PAYEE_CLAIM = "did:demos:seller";
export const SETTLEMENT_PHASE_INDEX = 0;

function bundleHash(claim: ClaimReference, key: string): string {
  return sha256Hex(canonicalize({ primaryClaim: claim, publicKey: key }));
}

export function buildSettlementPaymentSuccess(): {
  result: PhaseHandlerResult;
  evidence: SettlementEvidence;
  paymentInput: PaymentPhaseInput;
  expectedOrchestrator: ClaimReference;
  evidenceHash: string;
  publicKeys: Record<ClaimReference, string>;
  seeds: Record<string, string>;
} {
  const orchestrator = keypairFromSeed(ORCHESTRATOR_SEED);
  const payer = keypairFromSeed(PAYER_SEED);
  const payee = keypairFromSeed(PAYEE_SEED);
  const railId = "polygon-amoy-usdc";
  const jobId = SETTLEMENT_EVIDENCE_PAYMENT_JOB_ID;
  const amount = { amount: "5", currency: "USDC" };
  const paymentInput: PaymentPhaseInput = {
    jobId,
    agreement: {
      agreementVersion: "1",
      terms: { price: amount },
    },
    rail: {
      railVersion: 1,
      railId,
      railType: "evm-erc20",
      asset: { kind: "erc20", chainId: 80002, contract: "0x0000000000000000000000000000000000000001", symbol: "USDC", decimals: 6 },
      network: { kind: "evm", chainId: 80002, rpcAttestation: "evm-rpc" },
      phaseHandler: "pay-evm-erc20",
      parameters: { finalityBlocks: 1 },
      availability: "mocked",
      governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: SETTLEMENT_EVIDENCE_NOW - 10_000, anchoring: "in-code" },
      signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-rail-signature" },
    },
    payer: {
      bundleHash: bundleHash(SETTLEMENT_PAYER_CLAIM, payer.publicKeyB64u),
      primaryClaim: SETTLEMENT_PAYER_CLAIM,
      payingKey: SETTLEMENT_PAYER_CLAIM,
    },
    payee: {
      bundleHash: bundleHash(SETTLEMENT_PAYEE_CLAIM, payee.publicKeyB64u),
      primaryClaim: SETTLEMENT_PAYEE_CLAIM,
      payeeAddress: "0x00000000000000000000000000000000000000aa",
    },
    amount,
    sessionContext: { route: "dacs-verify-reference" },
  };

  const unsigned: Omit<SettlementEvidence, "signature"> = {
    evidenceVersion: "1",
    jobId,
    phase: "pay-evm-erc20",
    phaseIndex: SETTLEMENT_PHASE_INDEX,
    outcome: "success",
    paymentTxRefs: [{ rail: railId, txHash: "polygon-amoy:0xsettle0001", kind: "payment" }],
    paymentAmount: amount,
    settlementFinality: { model: "block-depth", finalityBlocks: 1, finalityObservedAt: SETTLEMENT_EVIDENCE_NOW + 1_000 },
    observedAt: SETTLEMENT_EVIDENCE_NOW,
  };
  const evidence: SettlementEvidence = {
    ...unsigned,
    signature: {
      algorithm: "ed25519",
      signer: SETTLEMENT_ORCHESTRATOR_CLAIM,
      value: signArtifact("dacs-evidence:v1:", unsigned as unknown as Record<string, unknown>, orchestrator.privateKey, ["signature"]),
    },
  };
  const hash = evidenceHash(evidence);
  const result: PhaseHandlerResult = {
    ok: true,
    txRefs: [{ rail: railId, txHash: "polygon-amoy:0xsettle0001", kind: "payment" }],
    attestationRef: { kind: "dacs-4-evidence", id: paymentEvidenceAddress(jobId, railId, SETTLEMENT_PHASE_INDEX), contentHash: hash },
  };

  return {
    result,
    evidence,
    paymentInput,
    expectedOrchestrator: SETTLEMENT_ORCHESTRATOR_CLAIM,
    evidenceHash: hash,
    publicKeys: { [SETTLEMENT_ORCHESTRATOR_CLAIM]: orchestrator.publicKeyB64u },
    seeds: { orchestrator: ORCHESTRATOR_SEED, payer: PAYER_SEED, payee: PAYEE_SEED },
  };
}

export function buildSettlementDeliverySuccess(): {
  result: PhaseHandlerResult;
  evidence: SettlementEvidence;
  expectedOrchestrator: ClaimReference;
  evidenceHash: string;
  publicKeys: Record<ClaimReference, string>;
  seeds: Record<string, string>;
} {
  const orchestrator = keypairFromSeed(ORCHESTRATOR_SEED);
  const jobId = SETTLEMENT_EVIDENCE_DELIVERY_JOB_ID;
  const contentHash = sha256Hex(canonicalize({ deliverable: "storage-program-output", jobId }));
  const unsigned: Omit<SettlementEvidence, "signature"> = {
    evidenceVersion: "1",
    jobId,
    phase: "deliver-storage-program",
    phaseIndex: 0,
    outcome: "success",
    deliverableContentHash: contentHash,
    deliverableAnchor: { kind: "storage-program", locator: "stor-dacs-verify-delivery-0001" },
    observedAt: SETTLEMENT_EVIDENCE_NOW + 2_000,
  };
  const evidence: SettlementEvidence = {
    ...unsigned,
    signature: {
      algorithm: "ed25519",
      signer: SETTLEMENT_ORCHESTRATOR_CLAIM,
      value: signArtifact("dacs-evidence:v1:", unsigned as unknown as Record<string, unknown>, orchestrator.privateKey, ["signature"]),
    },
  };
  const hash = evidenceHash(evidence);
  const result: PhaseHandlerResult = {
    ok: true,
    attestationRef: { kind: "dacs-4-evidence", id: `dacs4:deliverable:${jobId}`, contentHash: hash },
  };

  return {
    result,
    evidence,
    expectedOrchestrator: SETTLEMENT_ORCHESTRATOR_CLAIM,
    evidenceHash: hash,
    publicKeys: { [SETTLEMENT_ORCHESTRATOR_CLAIM]: orchestrator.publicKeyB64u },
    seeds: { orchestrator: ORCHESTRATOR_SEED },
  };
}
