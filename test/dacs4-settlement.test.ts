import { test, expect } from "bun:test";

import {
  evidenceHash,
  verifySettlementEvidence,
  type PaymentPhaseInput,
  type PhaseHandlerResult,
  type SettlementEvidence,
} from "../src/dacs4/index.ts";
import type { ClaimReference } from "../src/dacs1.ts";
import { keypairFromSeed, signArtifact } from "../examples/issuer-kit.ts";
import {
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

function refreshRef(result: PhaseHandlerResult, evidence: SettlementEvidence): PhaseHandlerResult {
  return {
    ...result,
    attestationRef: {
      ...result.attestationRef!,
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
  const resultBase = over.refreshHash === false ? base.result : refreshRef(base.result, evidence);
  const result = { ...resultBase, ...over.result };
  return { ...base, result, evidence, paymentInput };
}

test("payment success settlement evidence passes PC-1..PC-6 and signature", () => {
  const c = buildSettlementPaymentSuccess();
  expect(verifySettlementEvidence({ ...c, resolveKey: resolveFrom(c.publicKeys) })).toBe("pass");
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
