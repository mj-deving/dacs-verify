import { canonicalize, withoutSignature } from "../canonicalize.ts";
import { sha256Hex } from "../hash.ts";
import { verifyArtifactSignature } from "../signing.ts";
import { canonicalDecimal, assertPositiveAmount } from "../decimal.ts";
import { schemeOf, type ClaimReference } from "../dacs1.ts";
import type { AttestationRef, ChainTxRef } from "../dacs5/bundle.ts";

// §9.4.3 / signing registry: the canonical AttestationRef.kind label for a DACS-4 SettlementEvidence reference.
const DACS4_EVIDENCE_KIND = "dacs-4-evidence";

export type SettlementDecision = "pass" | "fail" | "indeterminate" | "error";

// §5 (L222) — phase handler return
export type PhaseHandlerResult = {
  ok: boolean;
  reason?: string;
  txRefs?: ChainTxRef[];
  explorerUrls?: string[];
  contextDelta?: Record<string, unknown>;
  attestationRef?: AttestationRef;
  errorClass?: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity";
};

// §9.7 (L2696) — uniform settlement record
export type SettlementEvidence = {
  evidenceVersion: "1";
  jobId: string;
  phase: PaymentPhaseType | DeliveryPhaseType;
  outcome: "success" | "failure";
  reason?: string;
  paymentTxRefs?: ChainTxRef[];
  paymentAmount?: PriceTerm;
  paymentFee?: PriceTerm;
  deliverableContentHash?: string;
  deliverableAnchor?: { kind: string; locator: string };
  attestationRef?: AttestationRef;
  settlementFinality?: SettlementFinalityRecord;
  amendmentRefs?: AttestationRef[];
  observedAt: number;
  signature: ComponentSignature;
};

export type SettlementFinalityRecord = {
  model: "block-depth" | "commitment-level" | "provider-receipt" | "htlc-reveal" | "liquidity-tank";
  finalityBlocks?: number;
  finalityCommitmentLevel?: "processed" | "confirmed" | "finalized";
  finalityObservedAt: number;
};

export type PaymentPhaseType = "pay-evm-erc20" | "pay-solana-spl" | "pay-cross-chain-htlc" | "pay-cross-chain-liquidity-tank" | "pay-ap2" | "pay-x402";
export type DeliveryPhaseType = "deliver-storage-program" | "deliver-entitlement" | "deliver-attested-payload";

export type ComponentSignature = {
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate";
  signer: ClaimReference;
  value: string;
};

export type PriceTerm = { amount: string; currency: string };

// §9.4.1 (L2424)
export type RailDefinition = {
  railVersion: number;   // §9.4.1 L2426 / RD-3 L2534: the spec field IS railVersion (NOT registryVersion — that is the distinct railRegistryVersion on SessionContext/AttestationBundle)
  railId: string;
  railType: "evm-erc20" | "solana-spl" | "cross-chain-htlc" | "cross-chain-liquidity-tank" | "ap2" | "x402";
  asset: AssetSpec;
  network: NetworkSpec;
  phaseHandler: PaymentPhaseType;
  parameters: Record<string, unknown>;
  availability: RailAvailability;
  governance: { proposedBy: ClaimReference; acceptedAt: number; supersedes?: number; anchoring: "in-code" | "single-signer" | "multisig"; emergency?: { isEmergency: true; failureObservation: string }; deprecated?: boolean; deprecationReason?: string };
  signature: { algorithm: string; signer: ClaimReference; value: string };
};
export type RailAvailability = "live" | "operator_gated" | "closed_data" | "bilateral" | "mocked" | "disabled" | "failed";
export type AssetSpec =
  | { kind: "erc20"; chainId: number; contract: string; symbol: string; decimals: number }
  | { kind: "spl"; cluster: "mainnet" | "devnet" | "testnet"; mint: string; symbol: string; decimals: number }
  | { kind: "native-evm"; chainId: number; symbol: string; decimals: number }
  | { kind: "native-solana"; cluster: "mainnet" | "devnet" | "testnet"; symbol: "SOL"; decimals: 9 }
  | { kind: "fiat-via-ap2"; isoCurrency: string; provider: string }
  | { kind: "stablecoin-cross-chain"; canonicalSymbol: string; routes: unknown[] };
export type NetworkSpec =
  | { kind: "evm"; chainId: number; rpcAttestation: "consensus-backed-proxy" | "evm-rpc" }
  | { kind: "solana"; cluster: "mainnet" | "devnet" | "testnet" }
  | { kind: "ap2-provider"; providerEndpoint: string }
  | { kind: "x402-resource"; resourceBaseUrl: string }
  | { kind: "cross-chain"; mechanism: "htlc" | "liquidity-tank" | "substrate-native" };

// §9.5.1 (L2562)
export type PaymentPhaseInput = {
  jobId: string;
  agreement: Record<string, unknown>;
  rail: RailDefinition;
  payer: { bundleHash: string; primaryClaim: ClaimReference; payingKey: ClaimReference };
  payee: { bundleHash: string; primaryClaim: ClaimReference; payeeAddress: string };
  amount: PriceTerm;
  sessionContext: Record<string, unknown>;
};

export const PAYMENT_PHASE_TYPES: ReadonlySet<PaymentPhaseType> = new Set([
  "pay-evm-erc20",
  "pay-solana-spl",
  "pay-cross-chain-htlc",
  "pay-cross-chain-liquidity-tank",
  "pay-ap2",
  "pay-x402",
]);

export const DELIVERY_PHASE_TYPES: ReadonlySet<DeliveryPhaseType> = new Set([
  "deliver-storage-program",
  "deliver-entitlement",
  "deliver-attested-payload",
]);

const ERROR_CLASSES: ReadonlySet<string> = new Set(["permanent", "transient", "counterparty", "substrate", "settlement-atomicity"]);
const SIGNATURE_ALGORITHMS: ReadonlySet<string> = new Set(["ed25519", "ecdsa-secp256k1", "sr1-aggregate"]);
const FINALITY_COMMITMENTS: ReadonlySet<string> = new Set(["processed", "confirmed", "finalized"]);
const HASH_RE = /^[0-9a-f]{64}$/;

export function evidenceHash(evidence: SettlementEvidence): string {
  return sha256Hex(canonicalize(withoutSignature(evidence as unknown as Record<string, unknown>, "signature")));
}

export function currencyResolves(amount: PriceTerm, asset: AssetSpec): boolean {
  switch (asset.kind) {
    case "erc20":
    case "spl":
    case "native-evm":
    case "native-solana":
      return amount.currency === asset.symbol;
    case "fiat-via-ap2":
      return amount.currency === asset.isoCurrency;
    case "stablecoin-cross-chain":
      return amount.currency === asset.canonicalSymbol;
  }
}

export function verifySettlementEvidence(input: {
  result: PhaseHandlerResult;
  evidence: SettlementEvidence;
  expectedOrchestrator: ClaimReference;   // the authorized phase-orchestrator signer (§9.7); caller supplies it from the session
  paymentInput?: PaymentPhaseInput;
  resolveKey: (signer: ClaimReference) => Uint8Array | null | undefined;
}): SettlementDecision {
  try {
    const { result, evidence, expectedOrchestrator, paymentInput, resolveKey } = input;

    // PC-1 (§9.5.1 L2559): handler result and evidence MUST match the closed structural shape.
    if (!isStructurallySupported(result, evidence, paymentInput)) return "fail";

    const isPayment = PAYMENT_PHASE_TYPES.has(evidence.phase as PaymentPhaseType);
    const isDelivery = DELIVERY_PHASE_TYPES.has(evidence.phase as DeliveryPhaseType);
    if (isPayment && paymentInput === undefined) return "fail";
    if (isDelivery && paymentInput !== undefined) return "fail";
    if (!isPayment && !isDelivery) return "fail";
    if (paymentInput !== undefined && evidence.jobId !== paymentInput.jobId) return "fail";

    // §9.4.1 (L2436) / §9.14 (L2624): one-to-one phase↔pinned-rail — evidence.phase MUST equal the rail's
    // declared phaseHandler. Otherwise signed evidence could claim a different handler than the rail selected
    // (e.g. a pay-solana-spl evidence verified against an evm-erc20 rail).
    if (isPayment && evidence.phase !== paymentInput!.rail.phaseHandler) return "fail";

    // PC-4 (§9.5.1 L2559): success has no errorClass; failure MUST carry a valid errorClass.
    if (result.ok === true && result.errorClass !== undefined) return "fail";
    if (result.ok === false && (result.errorClass === undefined || !ERROR_CLASSES.has(result.errorClass))) return "fail";
    // PC-4 (§9.7 L2696): settlement outcome records the phase-handler classification.
    if ((result.ok && evidence.outcome !== "success") || (!result.ok && evidence.outcome !== "failure")) return "fail";
    // PC-4 (§9.7 L2706): failure settlement evidence MUST explain the reason.
    if (evidence.outcome === "failure" && (typeof evidence.reason !== "string" || evidence.reason.length === 0)) return "fail";

    // PC-2 (§9.5.1 L2559): handler return MUST address the expected DACS-4 anchor.
    if (result.attestationRef === undefined) return "fail";
    // PC-3 (§9.5.1 L2559): the anchored reference MUST be labelled as DACS-4 evidence, not another artifact kind —
    // a consumer dispatching on AttestationRef.kind must not mistake a mislabelled ref for settlement evidence.
    if (result.attestationRef.kind !== DACS4_EVIDENCE_KIND) return "fail";
    if (isPayment) {
      const railId = paymentInput!.rail.railId;
      if (result.attestationRef.id !== `dacs4:payment:${evidence.jobId}:${railId}`) return "fail";
    } else if (evidence.phase === "deliver-entitlement") {
      // §9.6 (L2683): dacs4:entitlement:{jobId}:{renewalSeq} (renewalSeq a non-negative integer; 0 for the original grant).
      if (!new RegExp(`^dacs4:entitlement:${escapeRegExp(evidence.jobId)}:\\d+$`).test(result.attestationRef.id)) return "fail";
    } else {
      // §9.6 (L2647/L2689): deliver-storage-program / deliver-attested-payload anchor at dacs4:deliverable:{jobId}.
      if (result.attestationRef.id !== `dacs4:deliverable:${evidence.jobId}`) return "fail";
    }

    const computedHash = evidenceHash(evidence);
    if (!HASH_RE.test(computedHash)) return "error";

    // PC-3 (§9.5.1 L2559): result.attestationRef MUST point to this exact signature-free evidence hash.
    if (result.attestationRef.contentHash !== computedHash) return "fail";

    if (isPayment) {
      // PC-1/PC-3 (§9.5.1 L2559, §5 L228): the unsigned handler-return txRefs MUST match the signed evidence's
      // paymentTxRefs. The dacs-4-evidence signature covers paymentTxRefs only; a result advertising different
      // txRefs would let a consumer reading the handler return accept an uncovered settlement transaction.
      if (!txRefsEqual(result.txRefs, evidence.paymentTxRefs)) return "fail";

      // §9.5.1 (L2590) / PIPE-5 (L2837): PaymentPhaseInput.amount MUST equal agreement.terms.price — settling less
      // than the agreed price (underpayment) MUST NOT verify.
      const price = agreementPrice(paymentInput!.agreement);
      if (price === undefined || !priceEq(price, paymentInput!.amount)) return "fail";

      // PC-5 (§9.5.1 L2559): paymentAmount, when present, MUST equal paymentInput.amount.
      if (evidence.paymentAmount !== undefined && !priceEq(evidence.paymentAmount, paymentInput!.amount)) return "fail";

      // PC-5 (§9.5.1 L2559): handlers MUST NOT settle unresolved amount.currency.
      if (!currencyResolves(paymentInput!.amount, paymentInput!.rail.asset)) {
        if (!(result.ok === false && result.errorClass === "permanent")) return "fail";
      }
    }

    if (isPayment && evidence.outcome === "success") {
      // PC-6 (§9.7 L2724): success payment evidence MUST carry settlementFinality.
      if (evidence.settlementFinality === undefined) return "fail";
      if (!validPaymentFinality(evidence.settlementFinality, paymentInput!.rail)) return "fail";
    } else {
      // PC-6 (§9.7 L2724): delivery evidence and failure payment evidence MUST NOT carry settlementFinality.
      if (evidence.settlementFinality !== undefined) return "fail";
    }

    // §9.5.2-§9.6: the per-phase procedures populate phase-specific evidence on success — a success record that
    // omits it is not a valid settlement (defeats the audit value SettlementEvidence exists for).
    if (evidence.outcome === "success") {
      if (isPayment) {
        // §9.5.2-§9.5.7: EVERY payment success constructs a txRef of its kind (evm/solana/liquidity-tank/ap2/x402) —
        // incl. provider-receipt AP2 (L2630) and x402 even in the no-settlement-tx fallback (L2636). So a non-empty
        // paymentTxRefs requirement on payment success is correct for all rails, not over-constraining.
        if (evidence.paymentTxRefs === undefined || evidence.paymentTxRefs.length === 0) return "fail";
        if (evidence.paymentAmount === undefined) return "fail";
      } else {
        // §9.6 (L2647/L2689): storage-program & attested-payload deliveries produce a content hash + anchor;
        // attested-payload additionally carries the DACS-2 attestationRef. (deliver-entitlement anchors the
        // EntitlementRecord separately and is not required to carry a deliverableContentHash here.)
        if (evidence.phase === "deliver-storage-program" || evidence.phase === "deliver-attested-payload") {
          if (evidence.deliverableContentHash === undefined || evidence.deliverableAnchor === undefined) return "fail";
        }
        if (evidence.phase === "deliver-attested-payload" && evidence.attestationRef === undefined) return "fail";
        // SCOPE (open-world, SIG-5 §7.7 L290): §9.7 / PC-6 explicitly forbid only `settlementFinality` on delivery
        // evidence (enforced above). The spec does NOT forbid paymentTxRefs/paymentAmount/paymentFee on delivery, and
        // SIG-5 "preserve-unknown" mandates a verifier MAY ignore the meaning of inapplicable/unknown fields but MUST
        // NOT reject on their presence. So this §14 conformance verifier does not reject them — the consumer dispatches
        // on `phase`. (Whether the spec SHOULD close delivery-evidence shape is a steward-facing question, not a verifier
        // bug; see ISA Decisions / findings — escalate, don't unilaterally out-strict the reference.)
      }
    }

    // §9.7 (L2777): the evidence signer MUST be the authorized phase orchestrator — not merely a claim whose key
    // happens to resolve. (Mirrors §10.4.1 / bundle.ts binding each signature to a declared party.)
    if (evidence.signature.signer !== expectedOrchestrator) return "fail";

    if (evidence.signature.algorithm !== "ed25519") return "indeterminate";
    const publicKeyRaw = resolveKey(evidence.signature.signer);
    if (publicKeyRaw === null || publicKeyRaw === undefined) return "indeterminate";
    if (publicKeyRaw.length !== 32) return "error";

    const signatureRaw = new Uint8Array(Buffer.from(evidence.signature.value, "base64url"));
    const sigResult = verifyArtifactSignature({
      kind: "dacs-4-evidence",
      doc: evidence as unknown as Record<string, unknown>,
      publicKeyRaw,
      signatureRaw,
      signatureFields: ["signature"],
    });
    // §9.7 L2786: signature covers "dacs-evidence:v1:" || evidence_hash.
    if (sigResult.artifactHash !== computedHash) return "error";
    if (!sigResult.ok) return "fail";

    return "pass";
  } catch {
    return "error";
  }
}

function isStructurallySupported(result: PhaseHandlerResult, evidence: SettlementEvidence, paymentInput: PaymentPhaseInput | undefined): boolean {
  if (typeof result?.ok !== "boolean") return false;
  if (result.attestationRef !== undefined && !isAttestationRef(result.attestationRef)) return false;
  if (result.errorClass !== undefined && !ERROR_CLASSES.has(result.errorClass)) return false;
  if (result.txRefs !== undefined && (!Array.isArray(result.txRefs) || result.txRefs.some((tx) => !isChainTxRef(tx)))) return false;

  if (evidence?.evidenceVersion !== "1") return false;
  if (typeof evidence.jobId !== "string" || evidence.jobId.length === 0) return false;
  if (!PAYMENT_PHASE_TYPES.has(evidence.phase as PaymentPhaseType) && !DELIVERY_PHASE_TYPES.has(evidence.phase as DeliveryPhaseType)) return false;
  if (evidence.outcome !== "success" && evidence.outcome !== "failure") return false;
  if (!Number.isSafeInteger(evidence.observedAt)) return false;
  if (!isComponentSignature(evidence.signature)) return false;
  if (evidence.paymentTxRefs !== undefined && (!Array.isArray(evidence.paymentTxRefs) || evidence.paymentTxRefs.some((tx) => !isChainTxRef(tx)))) return false;
  // §9.3 + CD-1: a settled paymentAmount MUST be canonical and positive; paymentFee MUST be canonical and non-negative.
  if (evidence.paymentAmount !== undefined && (!isPriceTerm(evidence.paymentAmount) || !isCanonicalPositiveAmount(evidence.paymentAmount.amount))) return false;
  if (evidence.paymentFee !== undefined && (!isPriceTerm(evidence.paymentFee) || !isCanonicalNonNegativeAmount(evidence.paymentFee.amount))) return false;
  if (evidence.attestationRef !== undefined && !isAttestationRef(evidence.attestationRef)) return false;
  if (evidence.amendmentRefs !== undefined && (!Array.isArray(evidence.amendmentRefs) || evidence.amendmentRefs.some((r) => !isAttestationRef(r)))) return false;
  if (evidence.deliverableAnchor !== undefined && (typeof evidence.deliverableAnchor.kind !== "string" || evidence.deliverableAnchor.kind.length === 0 || typeof evidence.deliverableAnchor.locator !== "string" || evidence.deliverableAnchor.locator.length === 0)) return false;
  // §9.6 (L2647): deliverableContentHash = sha256(canonical_payload) — MUST be a 64-char lowercase-hex hash, not arbitrary text.
  if (evidence.deliverableContentHash !== undefined && !HASH_RE.test(evidence.deliverableContentHash)) return false;
  if (evidence.settlementFinality !== undefined && !isSettlementFinality(evidence.settlementFinality)) return false;

  if (paymentInput !== undefined && !isPaymentPhaseInput(paymentInput)) return false;
  return true;
}

function isPaymentPhaseInput(input: PaymentPhaseInput): boolean {
  if (typeof input.jobId !== "string" || input.jobId.length === 0) return false;
  if (!input.agreement || typeof input.agreement !== "object" || Array.isArray(input.agreement)) return false;
  if (!isRailDefinition(input.rail)) return false;
  if (!isPartyInput(input.payer, "payingKey")) return false;
  if (!isPayeeInput(input.payee)) return false;
  // §9.3 + CD-1: the payment input amount (== agreement price) MUST be canonical and strictly positive.
  if (!isPriceTerm(input.amount) || !isCanonicalPositiveAmount(input.amount.amount)) return false;
  if (!input.sessionContext || typeof input.sessionContext !== "object" || Array.isArray(input.sessionContext)) return false;
  return true;
}

function isRailDefinition(rail: RailDefinition): boolean {
  if (!rail || typeof rail !== "object") return false;
  if (!Number.isSafeInteger(rail.railVersion)) return false;
  if (typeof rail.railId !== "string" || rail.railId.length === 0) return false;
  if (!["evm-erc20", "solana-spl", "cross-chain-htlc", "cross-chain-liquidity-tank", "ap2", "x402"].includes(rail.railType)) return false;
  if (!isAssetSpec(rail.asset)) return false;
  if (!rail.parameters || typeof rail.parameters !== "object" || Array.isArray(rail.parameters)) return false;
  // RD-5 (§9.4.3 L2534): railType ↔ phaseHandler is one-to-one — an incoherent pairing is rejected.
  if (RAIL_TYPE_TO_HANDLER[rail.railType] !== rail.phaseHandler) return false;
  // RD-5: railType MUST match the asset AND network kinds (e.g. an evm-erc20 rail with a Solana network is rejected).
  if (!isNetworkSpec(rail.network)) return false;
  if (!railTypeMatchesAssetAndNetwork(rail)) return false;
  return true;
}

function isAssetSpec(asset: AssetSpec): boolean {
  if (!asset || typeof asset !== "object") return false;
  switch (asset.kind) {
    case "erc20":
      return Number.isSafeInteger(asset.chainId) && typeof asset.contract === "string" && asset.contract.length > 0 && isSymbolDecimals(asset);
    case "spl":
      return ["mainnet", "devnet", "testnet"].includes(asset.cluster) && typeof asset.mint === "string" && asset.mint.length > 0 && isSymbolDecimals(asset);
    case "native-evm":
      return Number.isSafeInteger(asset.chainId) && isSymbolDecimals(asset);
    case "native-solana":
      return ["mainnet", "devnet", "testnet"].includes(asset.cluster) && asset.symbol === "SOL" && asset.decimals === 9;
    case "fiat-via-ap2":
      return typeof asset.isoCurrency === "string" && asset.isoCurrency.length > 0 && typeof asset.provider === "string" && asset.provider.length > 0;
    case "stablecoin-cross-chain":
      return typeof asset.canonicalSymbol === "string" && asset.canonicalSymbol.length > 0 && Array.isArray(asset.routes);
  }
}

function isSymbolDecimals(asset: { symbol: string; decimals: number }): boolean {
  return typeof asset.symbol === "string" && asset.symbol.length > 0 && Number.isSafeInteger(asset.decimals);
}

function isNetworkSpec(network: NetworkSpec): boolean {
  if (!network || typeof network !== "object") return false;
  switch (network.kind) {
    case "evm":
      return Number.isSafeInteger(network.chainId) && (network.rpcAttestation === "consensus-backed-proxy" || network.rpcAttestation === "evm-rpc");
    case "solana":
      return ["mainnet", "devnet", "testnet"].includes(network.cluster);
    case "ap2-provider":
      return typeof network.providerEndpoint === "string" && network.providerEndpoint.length > 0;
    case "x402-resource":
      return typeof network.resourceBaseUrl === "string" && network.resourceBaseUrl.length > 0;
    case "cross-chain":
      return network.mechanism === "htlc" || network.mechanism === "liquidity-tank" || network.mechanism === "substrate-native";
    default:
      return false;
  }
}

// RD-5 (§9.4.3 L2534): railType MUST match both the asset kind and the network kind, per the §9.5.2-§9.5.7 procedures.
// (x402's procedure (L2636) pins only network.kind == "x402-resource", not a single asset kind, so asset is unconstrained there.)
// SCOPE: this checks asset/network KINDS — the spec's stated RD-5/§9.5.2 conformance bar. It deliberately does NOT
// require asset.chainId === network.chainId: that equality is not a spec MUST (RD-5 says "kinds"), and a §14 conformance
// verifier must not out-strict the spec and false-fail a spec-conformant rail.
function railTypeMatchesAssetAndNetwork(rail: RailDefinition): boolean {
  switch (rail.railType) {
    case "evm-erc20":
      return rail.asset.kind === "erc20" && rail.network.kind === "evm";
    case "solana-spl":
      return rail.asset.kind === "spl" && rail.network.kind === "solana";
    case "cross-chain-htlc":
      return rail.asset.kind === "stablecoin-cross-chain" && rail.network.kind === "cross-chain" && rail.network.mechanism === "htlc";
    case "cross-chain-liquidity-tank":
      return rail.asset.kind === "stablecoin-cross-chain" && rail.network.kind === "cross-chain" && rail.network.mechanism === "liquidity-tank";
    case "ap2":
      return rail.asset.kind === "fiat-via-ap2" && rail.network.kind === "ap2-provider";
    case "x402":
      return rail.network.kind === "x402-resource";
  }
}

function isPartyInput(value: { bundleHash: string; primaryClaim: ClaimReference; payingKey: ClaimReference }, key: "payingKey"): boolean {
  if (!value || typeof value !== "object") return false;
  if (!HASH_RE.test(value.bundleHash)) return false;
  if (!validClaim(value.primaryClaim)) return false;
  return key === "payingKey" && validClaim(value.payingKey);
}

function isPayeeInput(value: { bundleHash: string; primaryClaim: ClaimReference; payeeAddress: string }): boolean {
  if (!value || typeof value !== "object") return false;
  return HASH_RE.test(value.bundleHash) && validClaim(value.primaryClaim) && typeof value.payeeAddress === "string" && value.payeeAddress.length > 0;
}

function isPriceTerm(term: PriceTerm): boolean {
  return typeof term?.amount === "string" && term.amount.length > 0 && typeof term.currency === "string" && term.currency.length > 0;
}

function isComponentSignature(sig: ComponentSignature): boolean {
  return SIGNATURE_ALGORITHMS.has(sig?.algorithm) && validClaim(sig.signer) && typeof sig.value === "string" && sig.value.length > 0;
}

function isSettlementFinality(finality: SettlementFinalityRecord): boolean {
  if (!["block-depth", "commitment-level", "provider-receipt", "htlc-reveal", "liquidity-tank"].includes(finality?.model)) return false;
  if (!Number.isSafeInteger(finality.finalityObservedAt)) return false;
  if (finality.finalityBlocks !== undefined && !Number.isSafeInteger(finality.finalityBlocks)) return false;
  if (finality.finalityCommitmentLevel !== undefined && !FINALITY_COMMITMENTS.has(finality.finalityCommitmentLevel)) return false;
  return true;
}

function validPaymentFinality(finality: SettlementFinalityRecord, rail: RailDefinition): boolean {
  switch (rail.railType) {
    case "evm-erc20":
      return blockDepthFinality(finality, rail);
    case "solana-spl":
      return commitmentFinality(finality, rail);
    case "cross-chain-htlc":
      return finality.model === "htlc-reveal";
    case "cross-chain-liquidity-tank":
      return finality.model === "liquidity-tank";
    case "ap2":
      return finality.model === "provider-receipt";
    case "x402":
      // PC-6 (§9.7 L2745): x402 normally has block-depth; provider-receipt is accepted for no-settlement-tx fallback.
      return finality.model === "provider-receipt" || blockDepthFinality(finality, rail);
  }
}

function blockDepthFinality(finality: SettlementFinalityRecord, rail: RailDefinition): boolean {
  return finality.model === "block-depth"
    && Number.isSafeInteger(finality.finalityBlocks)
    && finality.finalityBlocks === rail.parameters.finalityBlocks;
}

function commitmentFinality(finality: SettlementFinalityRecord, rail: RailDefinition): boolean {
  return finality.model === "commitment-level"
    && typeof finality.finalityCommitmentLevel === "string"
    && finality.finalityCommitmentLevel === rail.parameters.commitmentLevel;
}

function isAttestationRef(ref: AttestationRef): boolean {
  return typeof ref?.kind === "string" && ref.kind.length > 0
    && typeof ref.id === "string" && ref.id.length > 0
    && HASH_RE.test(ref.contentHash);
}

function isChainTxRef(tx: ChainTxRef): boolean {
  return typeof tx?.rail === "string" && tx.rail.length > 0 && typeof tx.txHash === "string" && tx.txHash.length > 0;
}

function priceEq(a: PriceTerm, b: PriceTerm): boolean {
  return a.amount === b.amount && a.currency === b.currency;
}

// §8.5.2: AgreementDocument.terms.price is the agreed PriceTerm. Read it defensively from the opaque agreement.
function agreementPrice(agreement: Record<string, unknown>): PriceTerm | undefined {
  const terms = (agreement as { terms?: unknown }).terms;
  if (terms === null || typeof terms !== "object") return undefined;
  const price = (terms as { price?: unknown }).price;
  if (price === null || typeof price !== "object") return undefined;
  const p = price as { amount?: unknown; currency?: unknown };
  if (typeof p.amount !== "string" || typeof p.currency !== "string") return undefined;
  return { amount: p.amount, currency: p.currency };
}

// §9.4.2/§9.4.3 (RD-5): each railType has exactly one pay-* phase handler. An incoherent pairing MUST be rejected.
const RAIL_TYPE_TO_HANDLER: Record<RailDefinition["railType"], PaymentPhaseType> = {
  "evm-erc20": "pay-evm-erc20",
  "solana-spl": "pay-solana-spl",
  "cross-chain-htlc": "pay-cross-chain-htlc",
  "cross-chain-liquidity-tank": "pay-cross-chain-liquidity-tank",
  "ap2": "pay-ap2",
  "x402": "pay-x402",
};

// CD-1 (§7.1/§8.5.2 L2148): a PriceTerm.amount MUST be in minimal canonical decimal form (no leading/trailing
// zeros, no sign/exponent). canonicalDecimal throws on malformed input and normalises; equality with the input
// proves the input was already canonical.
function isCanonicalAmount(amount: string): boolean {
  try {
    return canonicalDecimal(amount) === amount;
  } catch {
    return false;
  }
}

// §9.3 + CD-1: a settled amount MUST be canonical AND strictly positive (> 0).
function isCanonicalPositiveAmount(amount: string): boolean {
  if (!isCanonicalAmount(amount)) return false;
  try {
    assertPositiveAmount(amount);
    return true;
  } catch {
    return false;
  }
}

// CD-1 + §9.7: a paymentFee MUST be canonical and non-negative — it may be "0" but never negative.
function isCanonicalNonNegativeAmount(amount: string): boolean {
  if (!isCanonicalAmount(amount)) return false;
  if (amount === "0") return true;
  try {
    assertPositiveAmount(amount);
    return true;
  } catch {
    return false;
  }
}

function txRefsEqual(a: ChainTxRef[] | undefined, b: ChainTxRef[] | undefined): boolean {
  if (a === undefined && b === undefined) return true;
  if (a === undefined || b === undefined) return false;
  if (a.length !== b.length) return false;
  return a.every((tx, i) => tx.rail === b[i]!.rail && tx.txHash === b[i]!.txHash && tx.kind === b[i]!.kind);
}

function validClaim(claim: ClaimReference): boolean {
  if (typeof claim !== "string" || claim.length === 0) return false;
  try {
    schemeOf(claim);
    return true;
  } catch {
    return false;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
