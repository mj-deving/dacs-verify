import { test, expect } from "bun:test";

import {
  evidenceHash,
  paymentEvidenceAddress,
  settlementTxId,
  verifySettlementEvidence,
  verifySettlementTxUniqueness,
  type PaymentPhaseInput,
  type PhaseHandlerResult,
  type RailDefinition,
  type SettlementEvidence,
} from "../src/dacs4/index.ts";
import type { ClaimReference } from "../src/dacs1.ts";
import { keypairFromSeed, signArtifact } from "../examples/issuer-kit.ts";
import {
  SETTLEMENT_PHASE_INDEX,
  SETTLEMENT_ORCHESTRATOR_CLAIM,
  buildSettlementDeliverySuccess,
  buildSettlementPaymentSuccess,
} from "../examples/settlement-evidence.ts";

const ORCHESTRATOR_SEED = "e4".repeat(32);
const WRONG_SEED = "f5".repeat(32);

function keyMap(publicKeys: Record<ClaimReference, string>): Record<ClaimReference, Uint8Array> {
  return Object.fromEntries(
    Object.entries(publicKeys).map(([claim, key]) => [claim, new Uint8Array(Buffer.from(key, "base64url"))]),
  ) as Record<ClaimReference, Uint8Array>;
}

function resolveFrom(publicKeys: Record<ClaimReference, string>) {
  const keys = keyMap(publicKeys);
  return (claim: ClaimReference): Uint8Array | undefined => keys[claim];
}

function signEvidence(unsigned: Omit<SettlementEvidence, "signature">): SettlementEvidence {
  const orchestrator = keypairFromSeed(ORCHESTRATOR_SEED);
  return {
    ...unsigned,
    signature: {
      algorithm: "ed25519",
      signer: SETTLEMENT_ORCHESTRATOR_CLAIM,
      value: signArtifact("dacs-evidence:v1:", unsigned as unknown as Record<string, unknown>, orchestrator.privateKey, ["signature"]),
    },
  };
}

function paymentAttestationId(jobId: string, railId: string, phaseIndex: number, resolved = false): string {
  return paymentEvidenceAddress(jobId, railId, phaseIndex, resolved);
}

function refreshRef(result: PhaseHandlerResult, evidence: SettlementEvidence, paymentInput?: PaymentPhaseInput): PhaseHandlerResult {
  const currentId = result.attestationRef?.id;
  const nextId = paymentInput !== undefined && currentId?.startsWith("dacs4:payment:")
    ? paymentAttestationId(evidence.jobId, paymentInput.rail.railId, evidence.phaseIndex, currentId.endsWith(":resolved"))
    : currentId;
  return {
    ...result,
    attestationRef: {
      ...result.attestationRef!,
      ...(nextId !== undefined ? { id: nextId } : {}),
      contentHash: evidenceHash(evidence),
    },
  };
}

function paymentCase(over: {
  result?: Partial<PhaseHandlerResult>;
  evidence?: Partial<Omit<SettlementEvidence, "signature">>;
  paymentInput?: (input: PaymentPhaseInput) => PaymentPhaseInput;
  refreshHash?: boolean;
  omitEvidence?: ("reason" | "settlementFinality")[];
} = {}) {
  const base = buildSettlementPaymentSuccess();
  const { signature: _signature, ...unsignedBase } = base.evidence;
  const unsigned = { ...unsignedBase, ...over.evidence };
  for (const key of over.omitEvidence ?? []) delete unsigned[key];
  const evidence = signEvidence(unsigned);
  const paymentInput = over.paymentInput?.(base.paymentInput) ?? base.paymentInput;
  const resultBase = over.refreshHash === false ? base.result : refreshRef(base.result, evidence, paymentInput);
  const result = { ...resultBase, ...over.result };
  return { ...base, result, evidence, paymentInput };
}

const HTLC_PARAMETERS = {
  timelockSourceSec: 3_600,
  timelockDestSec: 1_800,
  sourceFinalitySec: 900,
  safetyWindowSec: 600,
};

function htlcRail(parameters: Record<string, unknown> = HTLC_PARAMETERS): RailDefinition {
  return {
    railVersion: 1,
    railId: "sepolia-polygon-htlc-usdc",
    railType: "cross-chain-htlc",
    asset: {
      kind: "stablecoin-cross-chain",
      canonicalSymbol: "USDC",
      routes: [{ sourceChainId: "eip155:11155111", destChainId: "eip155:80002" }],
    },
    network: { kind: "cross-chain", mechanism: "htlc" },
    phaseHandler: "pay-cross-chain-htlc",
    parameters,
    availability: "mocked",
    governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
    signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-htlc-rail-signature" },
  };
}

function htlcPaymentCase(parameters: Record<string, unknown> = HTLC_PARAMETERS) {
  return paymentCase({
    evidence: {
      phase: "pay-cross-chain-htlc",
      settlementFinality: { model: "htlc-reveal", finalityObservedAt: 1_780_014_501_000 },
      paymentTxRefs: [{ rail: "sepolia-polygon-htlc-usdc", txHash: "polygon-amoy:0xhtlc-reveal-0001", kind: "htlc-reveal" }],
    },
    result: {
      txRefs: [{ rail: "sepolia-polygon-htlc-usdc", txHash: "polygon-amoy:0xhtlc-reveal-0001", kind: "htlc-reveal" }],
    },
    paymentInput: (input) => ({ ...input, rail: htlcRail(parameters) }),
  });
}

function liquidityTankPaymentCase() {
  return paymentCase({
    evidence: {
      phase: "pay-cross-chain-liquidity-tank",
      settlementFinality: { model: "liquidity-tank", finalityObservedAt: 1_780_014_502_000 },
      paymentTxRefs: [{ rail: "base-arbitrum-tank-usdc", txHash: "arbitrum:0xtank-completed-0001", kind: "liquidity-tank-completed" }],
    },
    result: {
      txRefs: [{ rail: "base-arbitrum-tank-usdc", txHash: "arbitrum:0xtank-completed-0001", kind: "liquidity-tank-completed" }],
    },
    paymentInput: (input) => ({
      ...input,
      rail: {
        railVersion: 1,
        railId: "base-arbitrum-tank-usdc",
        railType: "cross-chain-liquidity-tank",
        asset: {
          kind: "stablecoin-cross-chain",
          canonicalSymbol: "USDC",
          routes: [{ sourceChainId: "eip155:8453", destChainId: "eip155:42161" }],
        },
        network: { kind: "cross-chain", mechanism: "liquidity-tank" },
        phaseHandler: "pay-cross-chain-liquidity-tank",
        parameters: { routeId: "base-arbitrum-usdc" },
        availability: "mocked",
        governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
        signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-tank-rail-signature" },
      },
    }),
  });
}

function x402Rail(): RailDefinition {
  return {
    railVersion: 1,
    railId: "base-usdc-x402",
    railType: "x402",
    asset: { kind: "erc20", chainId: 8453, contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", decimals: 6 },
    network: { kind: "x402-resource", resourceBaseUrl: "https://pay.example/x402/resource" },
    phaseHandler: "pay-x402",
    parameters: { finalityBlocks: 1 },
    availability: "live",
    governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
    signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-x402-rail-signature" },
  };
}

function x402ProviderReceiptPaymentCase() {
  const txRef = { rail: "base-usdc-x402", txHash: "provider-receipt:pay.example:receipt-0001", kind: "provider-receipt" };
  return paymentCase({
    evidence: {
      phase: "pay-x402",
      settlementFinality: { model: "provider-receipt", finalityObservedAt: 1_780_014_503_000 },
      paymentTxRefs: [txRef],
    },
    result: {
      txRefs: [txRef],
    },
    paymentInput: (input) => ({
      ...input,
      rail: x402Rail(),
    }),
  });
}

function x402BlockDepthPaymentCase(txRef: NonNullable<SettlementEvidence["paymentTxRefs"]>[number]) {
  return paymentCase({
    evidence: {
      phase: "pay-x402",
      settlementFinality: { model: "block-depth", finalityBlocks: 1, finalityObservedAt: 1_780_014_504_000 },
      paymentTxRefs: [txRef],
    },
    result: {
      txRefs: [txRef],
    },
    paymentInput: (input) => ({ ...input, rail: x402Rail() }),
  });
}

test("payment success settlement evidence passes PC-1..PC-6 and signature", () => {
  const c = buildSettlementPaymentSuccess();
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
});

test("x402 provider-receipt fallback settlement evidence passes", () => {
  const c = x402ProviderReceiptPaymentCase();
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
  expect(verifySettlementTxUniqueness([c.evidence]).decision).toBe("pass");
});

test("x402 block-depth payment without event coordinates fails instead of falling back", () => {
  const txRef = {
    rail: "base-usdc-x402",
    txHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    kind: "payment",
  };
  const c = x402BlockDepthPaymentCase(txRef);

  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
  expect(verifySettlementTxUniqueness([c.evidence]).decision).toBe("error");
});

test("x402 block-depth payment cannot use provider-receipt fallback kind", () => {
  const txRef = {
    rail: "base-usdc-x402",
    txHash: "provider-receipt:pay.example:receipt-0002",
    kind: "provider-receipt",
  };
  const c = x402BlockDepthPaymentCase(txRef);

  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
  expect(verifySettlementTxUniqueness([c.evidence]).decision).toBe("error");
});

test("delivery success settlement evidence passes without settlementFinality", () => {
  const c = buildSettlementDeliverySuccess();
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
});

test("currency mismatch that settled returns fail", () => {
  const c = paymentCase({
    evidence: { paymentAmount: { amount: "5", currency: "DAI" } },
    paymentInput: (input) => ({ ...input, amount: { amount: "5", currency: "DAI" } }),
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("success payment missing settlementFinality returns fail", () => {
  const c = paymentCase({ omitEvidence: ["settlementFinality"] });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("delivery evidence with settlementFinality returns fail", () => {
  const base = buildSettlementDeliverySuccess();
  const { signature: _signature, ...unsignedBase } = base.evidence;
  const evidence = signEvidence({
    ...unsignedBase,
    settlementFinality: { model: "provider-receipt", finalityObservedAt: 1_780_014_500_000 },
  });
  const result = refreshRef(base.result, evidence);
  expect(verifySettlementEvidence({ result, evidence, expectedOrchestrator: base.expectedOrchestrator, resolveKey: resolveFrom(base.publicKeys) })).toBe("fail");
});

test("ok true with errorClass returns fail", () => {
  const c = paymentCase({ result: { errorClass: "permanent" } });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("ok false without errorClass returns fail", () => {
  const c = paymentCase({
    result: { ok: false },
    evidence: { outcome: "failure", reason: "rail-rejected" },
    omitEvidence: ["settlementFinality"],
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("wrong anchor returns fail", () => {
  const c = paymentCase({ result: { attestationRef: { ...buildSettlementPaymentSuccess().result.attestationRef!, id: "dacs4:payment:wrong:rail" } } });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("payment anchor includes phaseIndex and accepts discriminated payment addresses", () => {
  const c = paymentCase({ evidence: { phaseIndex: 1 } });
  expect(c.result.attestationRef?.id).toBe(paymentAttestationId(c.evidence.jobId, c.paymentInput.rail.railId, 1));
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
});

test("payment anchor CF-4-encodes colon-bearing railId", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "evm-erc20:1:USDC", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    result: {
      txRefs: [{ rail: "evm-erc20:1:USDC", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    paymentInput: (input) => ({ ...input, rail: { ...input.rail, railId: "evm-erc20:1:USDC" } }),
  });
  expect(c.result.attestationRef?.id).toBe(`dacs4:payment:${c.evidence.jobId}:evm-erc20%3A1%3AUSDC:${c.evidence.phaseIndex}`);
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
});

test("same jobId and railId with the wrong phaseIndex anchor fails instead of colliding", () => {
  const c = paymentCase({
    evidence: { phaseIndex: 1 },
    result: {
      attestationRef: {
        ...buildSettlementPaymentSuccess().result.attestationRef!,
        id: paymentAttestationId(buildSettlementPaymentSuccess().evidence.jobId, buildSettlementPaymentSuccess().paymentInput.rail.railId, SETTLEMENT_PHASE_INDEX),
      },
    },
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("SB-1 EVM settlement-tx-id is event-level and normalises hex spelling", () => {
  const upper = "0xABCDEF0000000000000000000000000000000000000000000000000000000001";
  const lower = "abcdef0000000000000000000000000000000000000000000000000000000001";

  expect(settlementTxId({
    rail: "polygon-amoy-usdc",
    txHash: upper,
    kind: "payment",
    chainId: 80002,
    logIndex: 7,
  })).toBe(`evm:80002:${lower}:7`);
  expect(settlementTxId({
    rail: "polygon-amoy-usdc",
    txHash: lower,
    kind: "payment",
    chainId: "80002",
    logIndex: 7,
  })).toBe(`evm:80002:${lower}:7`);
});

test("SB-1 Solana settlement-tx-id is instruction-level", () => {
  expect(settlementTxId({
    rail: "solana-devnet-usdc",
    txHash: "5Vxj8a6gQ4exampleSignature",
    kind: "payment",
    cluster: "devnet",
    signature: "5Vxj8a6gQ4exampleSignature",
    instructionIndex: 2,
  })).toBe("solana:devnet:5Vxj8a6gQ4exampleSignature:2");
});

test("SB-1 Solana txHash/signature aliases are rejected", () => {
  expect(() => settlementTxId({
    rail: "solana-devnet-usdc",
    txHash: "5Vxj8a6gQ4exampleSignatureA",
    kind: "payment",
    cluster: "devnet",
    signature: "5Vxj8a6gQ4exampleSignatureB",
    instructionIndex: 2,
  }, "pay-solana-spl")).toThrow("signature must match txHash");
});

test("SB-1 mixed EVM and Solana settlement coordinates are rejected", () => {
  expect(() => settlementTxId({
    rail: "solana-devnet-usdc",
    txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    kind: "payment",
    chainId: 80002,
    logIndex: 0,
    cluster: "devnet",
    signature: "5Vxj8a6gQ4exampleSignature",
    instructionIndex: 2,
  }, "pay-solana-spl")).toThrow("must not be mixed");
});

test("SB-2 malformed event-level settlement refs return error instead of minting a new key", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xnot-hex", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    result: {
      txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xnot-hex", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
  });

  expect(verifySettlementTxUniqueness([c.evidence]).decision).toBe("error");
});

test("SB-2 prefixed EVM event txHash returns error", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    result: {
      txRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
  });

  expect(verifySettlementTxUniqueness([c.evidence]).decision).toBe("error");
});

test("SB-2 EVM/x402 settlement refs without event coordinates return error", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment" }],
    },
    result: {
      txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment" }],
    },
  });

  expect(verifySettlementTxUniqueness([c.evidence]).decision).toBe("error");
});

test("SB-2 Solana txHash/signature aliases return error", () => {
  const c = paymentCase({
    evidence: {
      phase: "pay-solana-spl",
      paymentTxRefs: [{
        rail: "solana-devnet-usdc",
        txHash: "5Vxj8a6gQ4exampleSignatureA",
        kind: "payment",
        cluster: "devnet",
        signature: "5Vxj8a6gQ4exampleSignatureB",
        instructionIndex: 0,
      }],
    },
    result: {
      txRefs: [{
        rail: "solana-devnet-usdc",
        txHash: "5Vxj8a6gQ4exampleSignatureA",
        kind: "payment",
        cluster: "devnet",
        signature: "5Vxj8a6gQ4exampleSignatureB",
        instructionIndex: 0,
      }],
    },
  });

  expect(verifySettlementTxUniqueness([c.evidence]).decision).toBe("error");
});

test("SB-2 non-minimal EVM chainId spelling returns error", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{
        rail: "polygon-amoy-usdc",
        txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        kind: "payment",
        chainId: "080002",
        logIndex: 0,
      }],
    },
    result: {
      txRefs: [{
        rail: "polygon-amoy-usdc",
        txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        kind: "payment",
        chainId: "080002",
        logIndex: 0,
      }],
    },
  });

  expect(verifySettlementTxUniqueness([c.evidence]).decision).toBe("error");
});

test("SB-2 duplicate settlement-tx-id across two jobIds fails in one consumer view", () => {
  const first = paymentCase();
  const second = paymentCase({ evidence: { jobId: "DACS-VERIFY-SETTLE-0002" } });

  expect(verifySettlementTxUniqueness([first.evidence, second.evidence])).toEqual({
    decision: "fail",
    conflict: {
      settlementTxId: settlementTxId(first.evidence.paymentTxRefs![0]!),
      first: { jobId: first.evidence.jobId, phaseIndex: first.evidence.phaseIndex },
      second: { jobId: second.evidence.jobId, phaseIndex: second.evidence.phaseIndex },
    },
    consumed: [{
      settlementTxId: settlementTxId(first.evidence.paymentTxRefs![0]!),
      jobId: first.evidence.jobId,
      phaseIndex: first.evidence.phaseIndex,
    }],
  });
});

test("SB-2 same settlement-tx-id for the same job across two phases fails", () => {
  const phase0 = paymentCase();
  const phase1 = paymentCase({ evidence: { phaseIndex: 1 } });

  expect(verifySettlementTxUniqueness([phase0.evidence, phase1.evidence]).decision).toBe("fail");
});

test("SB-2 same settlement-tx-id for the same obligation is idempotent", () => {
  const c = paymentCase();

  expect(verifySettlementTxUniqueness([c.evidence, c.evidence])).toEqual({
    decision: "pass",
    consumed: [{
      settlementTxId: settlementTxId(c.evidence.paymentTxRefs![0]!),
      jobId: c.evidence.jobId,
      phaseIndex: c.evidence.phaseIndex,
    }],
  });
});

test("SB-2 uniqueness is scoped to one consumer reconciliation set", () => {
  const first = paymentCase();
  const second = paymentCase({ evidence: { jobId: "DACS-VERIFY-SETTLE-0002" } });

  expect(verifySettlementTxUniqueness([first.evidence]).decision).toBe("pass");
  expect(verifySettlementTxUniqueness([second.evidence]).decision).toBe("pass");
});

test("attestationRef hash mismatch returns fail", () => {
  const c = paymentCase({ refreshHash: false, evidence: { paymentAmount: { amount: "6", currency: "USDC" } } });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("failure evidence without reason returns fail", () => {
  const c = paymentCase({
    result: { ok: false, errorClass: "permanent" },
    evidence: { outcome: "failure" },
    omitEvidence: ["reason", "settlementFinality"],
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("interim payment record without supersedesEvidenceRef remains accepted", () => {
  const c = buildSettlementPaymentSuccess();
  expect(c.result.attestationRef?.id).toBe(paymentAttestationId(c.evidence.jobId, c.paymentInput.rail.railId, c.evidence.phaseIndex));
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
});

test("resolved payment record with supersedesEvidenceRef passes", () => {
  const base = buildSettlementPaymentSuccess();
  const { signature: _signature, ...unsignedBase } = base.evidence;
  const evidence = signEvidence({
    ...unsignedBase,
    supersedesEvidenceRef: {
      kind: "dacs-4-evidence",
      id: paymentAttestationId(base.evidence.jobId, base.paymentInput.rail.railId, base.evidence.phaseIndex),
      contentHash: base.evidenceHash,
    },
  });
  const result = refreshRef({
    ...base.result,
    attestationRef: {
      ...base.result.attestationRef!,
      id: paymentAttestationId(base.evidence.jobId, base.paymentInput.rail.railId, base.evidence.phaseIndex, true),
    },
  }, evidence, base.paymentInput);
  expect(verifySettlementEvidence({ result, evidence, expectedOrchestrator: base.expectedOrchestrator, paymentInput: base.paymentInput, resolveKey: resolveFrom(base.publicKeys) })).toBe("pass");
});

test("resolved payment record without supersedesEvidenceRef returns fail", () => {
  const base = buildSettlementPaymentSuccess();
  const result = refreshRef({
    ...base.result,
    attestationRef: {
      ...base.result.attestationRef!,
      id: paymentAttestationId(base.evidence.jobId, base.paymentInput.rail.railId, base.evidence.phaseIndex, true),
    },
  }, base.evidence, base.paymentInput);
  expect(verifySettlementEvidence({ result, evidence: base.evidence, expectedOrchestrator: base.expectedOrchestrator, paymentInput: base.paymentInput, resolveKey: resolveFrom(base.publicKeys) })).toBe("fail");
});

test("wrong signer key returns fail", () => {
  const c = buildSettlementPaymentSuccess();
  const wrong = keypairFromSeed(WRONG_SEED);
  expect(verifySettlementEvidence({ ...c, resolveKey: () => wrong.publicKeyRaw })).toBe("fail");
});

test("malformed resolved key returns error", () => {
  const c = buildSettlementPaymentSuccess();
  expect(verifySettlementEvidence({ ...c, resolveKey: () => new Uint8Array([1, 2, 3]) })).toBe("error");
});

test("unresolvable signer key returns indeterminate", () => {
  const c = buildSettlementPaymentSuccess();
  expect(verifySettlementEvidence({ ...c, resolveKey: () => undefined })).toBe("indeterminate");
});

test("evidence.phase not matching the pinned rail.phaseHandler returns fail", () => {
  // §9.4.1 / §9.14: one-to-one phase↔pinned-rail — a pay-solana-spl evidence against an evm-erc20 rail must fail.
  const c = paymentCase({ evidence: { phase: "pay-solana-spl" } });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("handler-return txRefs not matching signed evidence.paymentTxRefs returns fail", () => {
  // PC-1/PC-3: the signature covers paymentTxRefs; an unsigned result advertising different txRefs is inconsistent.
  const c = paymentCase({ result: { txRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xUNSIGNED", kind: "payment" }] } });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("payment success with malformed EVM event txRef returns fail", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xnot-hex", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    result: {
      txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xnot-hex", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
  });

  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("payment success with prefixed EVM event txHash returns fail", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    result: {
      txRefs: [{ rail: "polygon-amoy-usdc", txHash: "polygon-amoy:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
  });

  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("payment success with missing EVM event coordinates returns fail", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment" }],
    },
    result: {
      txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment" }],
    },
  });

  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("payment success with event chainId not matching the selected rail returns fail", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 1, logIndex: 0 }],
    },
    result: {
      txRefs: [{ rail: "polygon-amoy-usdc", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 1, logIndex: 0 }],
    },
  });

  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("payment success with txRef rail not matching the selected rail returns fail", () => {
  const c = paymentCase({
    evidence: {
      paymentTxRefs: [{ rail: "other-polygon-rail", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
    result: {
      txRefs: [{ rail: "other-polygon-rail", txHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", kind: "payment", chainId: 80002, logIndex: 0 }],
    },
  });

  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("Solana payment success with event cluster not matching the selected rail returns fail", () => {
  const txRef = { rail: "solana-devnet-usdc", txHash: "5Vxj8a6gQ4exampleSignature", kind: "payment", cluster: "mainnet", signature: "5Vxj8a6gQ4exampleSignature", instructionIndex: 0 };
  const c = paymentCase({
    evidence: {
      phase: "pay-solana-spl",
      settlementFinality: { model: "commitment-level", finalityCommitmentLevel: "confirmed", finalityObservedAt: 1_780_014_505_000 },
      paymentTxRefs: [txRef],
    },
    result: {
      txRefs: [txRef],
    },
    paymentInput: (input) => ({
      ...input,
      rail: {
        railVersion: 1,
        railId: "solana-devnet-usdc",
        railType: "solana-spl",
        asset: { kind: "spl", cluster: "devnet", mint: "Es9vMFrzaCERexampleMint", symbol: "USDC", decimals: 6 },
        network: { kind: "solana", cluster: "devnet" },
        phaseHandler: "pay-solana-spl",
        parameters: { commitmentLevel: "confirmed" },
        availability: "mocked",
        governance: { proposedBy: SETTLEMENT_ORCHESTRATOR_CLAIM, acceptedAt: 1_780_014_390_000, anchoring: "in-code" },
        signature: { algorithm: "ed25519", signer: SETTLEMENT_ORCHESTRATOR_CLAIM, value: "fixture-solana-rail-signature" },
      },
    }),
  });

  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("non-canonical PriceTerm.amount returns fail (CD-1)", () => {
  const c = paymentCase({
    evidence: { paymentAmount: { amount: "1.50", currency: "USDC" } },
    paymentInput: (input) => ({ ...input, amount: { amount: "1.50", currency: "USDC" } }),
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("non-positive PriceTerm.amount returns fail (§9.3)", () => {
  const c = paymentCase({
    evidence: { paymentAmount: { amount: "0", currency: "USDC" } },
    paymentInput: (input) => ({ ...input, amount: { amount: "0", currency: "USDC" } }),
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("attestationRef.kind not dacs-4-evidence returns fail", () => {
  const base = buildSettlementPaymentSuccess();
  const c = paymentCase({ result: { attestationRef: { ...base.result.attestationRef!, kind: "dacs-5-bundle" } } });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("evidence signed by a non-orchestrator claim returns fail", () => {
  // §9.7: the signer must be the authorized orchestrator, not merely a claim whose key resolves.
  const base = buildSettlementPaymentSuccess();
  const attacker = keypairFromSeed("99".repeat(32));
  const { signature: _s, ...unsigned } = base.evidence;
  const evidence: SettlementEvidence = {
    ...unsigned,
    signature: { algorithm: "ed25519", signer: "did:attacker:x", value: signArtifact("dacs-evidence:v1:", unsigned as unknown as Record<string, unknown>, attacker.privateKey, ["signature"]) },
  };
  const result = refreshRef(base.result, evidence);
  const resolveKey = (c: ClaimReference): Uint8Array | undefined => (c === "did:attacker:x" ? attacker.publicKeyRaw : resolveFrom(base.publicKeys)(c));
  expect(verifySettlementEvidence({ result, evidence, expectedOrchestrator: base.expectedOrchestrator, paymentInput: base.paymentInput, resolveKey })).toBe("fail");
});

test("success payment omitting paymentTxRefs returns fail", () => {
  // exactOptionalPropertyTypes: omit the key (don't set undefined) to model an absent field.
  const base = buildSettlementPaymentSuccess();
  const { signature: _s, paymentTxRefs: _ptr, ...unsigned } = base.evidence;
  const evidence = signEvidence(unsigned);
  const { txRefs: _tr, ...resultNoTx } = base.result;
  const result = refreshRef(resultNoTx, evidence);
  expect(verifySettlementEvidence({ result, evidence, expectedOrchestrator: base.expectedOrchestrator, paymentInput: base.paymentInput, resolveKey: resolveFrom(base.publicKeys) })).toBe("fail");
});

test("success payment omitting paymentAmount returns fail", () => {
  const base = buildSettlementPaymentSuccess();
  const { signature: _s, paymentAmount: _pa, ...unsigned } = base.evidence;
  const evidence = signEvidence(unsigned);
  const result = refreshRef(base.result, evidence);
  expect(verifySettlementEvidence({ result, evidence, expectedOrchestrator: base.expectedOrchestrator, paymentInput: base.paymentInput, resolveKey: resolveFrom(base.publicKeys) })).toBe("fail");
});

test("delivery success omitting deliverableContentHash/anchor returns fail", () => {
  const base = buildSettlementDeliverySuccess();
  const { signature: _s, deliverableContentHash: _dch, deliverableAnchor: _da, ...unsigned } = base.evidence;
  const evidence = signEvidence(unsigned);
  const result = refreshRef(base.result, evidence);
  expect(verifySettlementEvidence({ result, evidence, expectedOrchestrator: base.expectedOrchestrator, resolveKey: resolveFrom(base.publicKeys) })).toBe("fail");
});

test("delivery deliverableContentHash not a valid 64-hex hash returns fail", () => {
  const base = buildSettlementDeliverySuccess();
  const { signature: _s, ...unsigned } = base.evidence;
  const evidence = signEvidence({ ...unsigned, deliverableContentHash: "not-a-hash" });
  const result = refreshRef(base.result, evidence);
  expect(verifySettlementEvidence({ result, evidence, expectedOrchestrator: base.expectedOrchestrator, resolveKey: resolveFrom(base.publicKeys) })).toBe("fail");
});

test("deliver-storage-program anchored in the entitlement namespace returns fail", () => {
  const base = buildSettlementDeliverySuccess();
  const result = { ...base.result, attestationRef: { ...base.result.attestationRef!, id: `dacs4:entitlement:${base.evidence.jobId}:0` } };
  expect(verifySettlementEvidence({ result, evidence: base.evidence, expectedOrchestrator: base.expectedOrchestrator, resolveKey: resolveFrom(base.publicKeys) })).toBe("fail");
});

test("negative paymentFee returns fail", () => {
  const c = paymentCase({ evidence: { paymentFee: { amount: "-1", currency: "USDC" } } });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("payment amount not equal to agreement price returns fail (underpayment)", () => {
  // §9.5.1 / PIPE-5: PaymentPhaseInput.amount MUST equal agreement.terms.price.
  const c = paymentCase({
    evidence: { paymentAmount: { amount: "1", currency: "USDC" } },
    paymentInput: (input) => ({ ...input, amount: { amount: "1", currency: "USDC" } }),
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("incoherent rail (railType ≠ phaseHandler) returns fail", () => {
  // RD-5: an evm-erc20 rail paired with a pay-solana-spl handler is rejected.
  const c = paymentCase({
    evidence: { phase: "pay-solana-spl" },
    paymentInput: (input) => ({ ...input, rail: { ...input.rail, phaseHandler: "pay-solana-spl" } }),
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("rail whose railType does not match its network kind returns fail", () => {
  // RD-5: an evm-erc20 rail with a solana network is incoherent.
  const c = paymentCase({
    paymentInput: (input) => ({ ...input, rail: { ...input.rail, network: { kind: "solana", cluster: "mainnet" } } }),
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("HTLC payment with pinned source finality and safety margin passes", () => {
  const c = htlcPaymentCase();
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
});

test("HTLC payment missing sourceFinalitySec returns fail", () => {
  const { sourceFinalitySec: _sourceFinalitySec, ...parameters } = HTLC_PARAMETERS;
  const c = htlcPaymentCase(parameters);
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("HTLC payment missing safetyWindowSec returns fail", () => {
  const { safetyWindowSec: _safetyWindowSec, ...parameters } = HTLC_PARAMETERS;
  const c = htlcPaymentCase(parameters);
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("HTLC payment with insufficient source timelock margin returns fail", () => {
  const c = htlcPaymentCase({ ...HTLC_PARAMETERS, timelockSourceSec: 3_300 });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("fail");
});

test("cross-chain anchor-pending payment may omit attestationRef at return time (PC-7)", () => {
  const c = liquidityTankPaymentCase();
  const { attestationRef: _attestationRef, ...result } = c.result;
  expect(verifySettlementEvidence({ ...c, result, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
});

// POSITIVE locks — documenting the deliberate conformance-scope interpretation (advisor commitment-boundary review).
test("rail with matching kinds but differing chainIds passes (RD-5 binds kinds, not chainId-equality)", () => {
  const c = paymentCase({
    paymentInput: (input) => ({ ...input, rail: { ...input.rail, asset: { kind: "erc20", chainId: 1, contract: "0x0000000000000000000000000000000000000001", symbol: "USDC", decimals: 6 }, network: { kind: "evm", chainId: 80002, rpcAttestation: "evm-rpc" } } }),
  });
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
});

test("delivery evidence carrying an extra payment field passes (SIG-5 preserve-unknown / open-world)", () => {
  const base = buildSettlementDeliverySuccess();
  const { signature: _s, ...unsigned } = base.evidence;
  const evidence = signEvidence({ ...unsigned, paymentAmount: { amount: "5", currency: "USDC" } });
  const result = refreshRef(base.result, evidence);
  expect(verifySettlementEvidence({ result, evidence, expectedOrchestrator: base.expectedOrchestrator, resolveKey: resolveFrom(base.publicKeys) })).toBe("pass");
});
