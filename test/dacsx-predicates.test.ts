import { test, expect } from "bun:test";

import {
  HASHLOCK_ALGO_BY_CHAIN,
  classifyCrossChainHtlcState,
  selectAmendmentType,
  supersessionOrder,
  type RecomputeHashlock,
  type SupersessionOutcome,
} from "../src/dacsx/index.ts";

const demoPreimage = "feedface";
const algoTaggedResolver: RecomputeHashlock = (chain, preimageHex) =>
  `${HASHLOCK_ALGO_BY_CHAIN[chain]}:${preimageHex}`;

const divergenceHashlock = algoTaggedResolver("solana", demoPreimage);

const supersessionBase: SupersessionOutcome = {
  disputeId: "d-1",
  decidedAt: 1_000,
  contentHash: "bbb",
};

test("P1 classifies dest-revealed-source-unclaimed with chain-pinned hashlock selection", () => {
  const result = classifyCrossChainHtlcState({
    destChain: "solana",
    destHashlock: divergenceHashlock,
    revealedPreimage: demoPreimage,
    sourceClaimObserved: false,
    recomputeHashlock: algoTaggedResolver,
  });

  expect(result).toEqual({
    state: "dest-revealed-source-unclaimed",
    destRevealed: true,
    sourceUnclaimed: true,
    algoUsed: "sha256",
  });
});

test("P1 wrong-chain divergence demo flips classification", () => {
  const correctChain = classifyCrossChainHtlcState({
    destChain: "solana",
    destHashlock: divergenceHashlock,
    revealedPreimage: demoPreimage,
    sourceClaimObserved: false,
    recomputeHashlock: algoTaggedResolver,
  });
  const wrongChain = classifyCrossChainHtlcState({
    destChain: "evm",
    destHashlock: divergenceHashlock,
    revealedPreimage: demoPreimage,
    sourceClaimObserved: false,
    recomputeHashlock: algoTaggedResolver,
  });

  expect(correctChain.state).toBe("dest-revealed-source-unclaimed");
  expect(correctChain.destRevealed).toBe(true);
  expect(wrongChain.state).toBe("benign-timeout");
  expect(wrongChain.destRevealed).toBe(false);
  expect(wrongChain.algoUsed).toBe("keccak256");
});

test("P1 returns settled-symmetric when destination reveal and source claim both land", () => {
  const result = classifyCrossChainHtlcState({
    destChain: "cosmos",
    destHashlock: algoTaggedResolver("cosmos", demoPreimage),
    revealedPreimage: demoPreimage,
    sourceClaimObserved: true,
    recomputeHashlock: algoTaggedResolver,
  });

  expect(result.state).toBe("settled-symmetric");
  expect(result.sourceUnclaimed).toBe(false);
});

test("P1 surfaces resolver throw with clear wrapper error", () => {
  expect(() =>
    classifyCrossChainHtlcState({
      destChain: "evm",
      destHashlock: "ignored",
      revealedPreimage: demoPreimage,
      sourceClaimObserved: false,
      recomputeHashlock: () => {
        throw new Error("boom");
      },
    }),
  ).toThrow("hashlock-resolver-failed: boom");
});

test("P1 rejects non-string resolver results before comparison", () => {
  expect(() =>
    classifyCrossChainHtlcState({
      destChain: "solana",
      destHashlock: divergenceHashlock,
      revealedPreimage: demoPreimage,
      sourceClaimObserved: false,
      recomputeHashlock: (() => 7) as unknown as RecomputeHashlock,
    }),
  ).toThrow("hashlock-resolver-invalid: expected string result");
});

test("P1 default resolver throws for unavailable non-sha256 substrates", () => {
  expect(() =>
    classifyCrossChainHtlcState({
      destChain: "evm",
      destHashlock: "ignored",
      revealedPreimage: demoPreimage,
      sourceClaimObserved: false,
    }),
  ).toThrow(
    "hashlock-resolver-failed: hashlock-algo-unavailable: keccak256 requires substrate lib",
  );
});

test("P2 selects refund amendment for successful unwind", () => {
  expect(
    selectAmendmentType({
      outcome: "success",
      destValueReceived: true,
      sourceClaimLanded: true,
      refundOrdered: true,
      partial: false,
      refundAmount: "100",
    }),
  ).toEqual({
    amendmentType: "refund",
    isSettlementAmendment: true,
  });
});

test("P2 selects partial-refund amendment for successful partial unwind", () => {
  expect(
    selectAmendmentType({
      outcome: "success",
      destValueReceived: true,
      sourceClaimLanded: false,
      refundOrdered: true,
      partial: true,
      refundAmount: "25",
    }),
  ).toEqual({
    amendmentType: "partial-refund",
    isSettlementAmendment: true,
  });
});

test("P2 routes failure without destination value to rail timelock refund path", () => {
  expect(
    selectAmendmentType({
      outcome: "failure",
      destValueReceived: false,
      sourceClaimLanded: false,
      refundOrdered: false,
      partial: false,
    }),
  ).toEqual({
    amendmentType: "timelock-refund-path",
    isSettlementAmendment: false,
  });
});

test("P2 selects correction when failure follows destination value receipt", () => {
  expect(
    selectAmendmentType({
      outcome: "failure",
      destValueReceived: true,
      sourceClaimLanded: false,
      refundOrdered: false,
      partial: false,
    }),
  ).toEqual({
    amendmentType: "correction",
    isSettlementAmendment: true,
  });
});

test("P2 AMEND-2 throw demo rejects failure refund amendment", () => {
  expect(() =>
    selectAmendmentType({
      outcome: "failure",
      destValueReceived: true,
      sourceClaimLanded: false,
      refundOrdered: true,
      partial: true,
      refundAmount: "25",
    }),
  ).toThrow(
    "AMEND-2 violation: failure outcome cannot be unwound via refund amendment",
  );
});

test("P2 rejects correction input carrying refundAmount", () => {
  expect(() =>
    selectAmendmentType({
      outcome: "failure",
      destValueReceived: true,
      sourceClaimLanded: true,
      refundOrdered: false,
      partial: false,
      refundAmount: "5",
    }),
  ).toThrow("correction amendment cannot include refundAmount");
});

test("P3 returns null honored outcome for empty input", () => {
  expect(supersessionOrder([])).toEqual({
    honored: null,
    rejected: [],
  });
});

test("P3 honors maximal decidedAt with lexicographic contentHash tie-break", () => {
  const result = supersessionOrder([
    { disputeId: "d-1", decidedAt: 1_000, contentHash: "aaa" },
    { disputeId: "d-2", decidedAt: 1_000, contentHash: "bbb" },
  ]);

  expect(result.honored).toEqual({
    disputeId: "d-2",
    decidedAt: 1_000,
    contentHash: "bbb",
  });
  expect(result.rejected).toEqual([]);
});

test("P3 monotonicity + anti-backdating demo rejects both invalid outcomes", () => {
  const result = supersessionOrder([
    supersessionBase,
    {
      disputeId: "d-2",
      decidedAt: 900,
      contentHash: "ccc",
    },
    {
      disputeId: "d-3",
      decidedAt: 2_000,
      contentHash: "ddd",
      anchorTimestamp: 400_001,
    },
  ]);

  expect(result.honored).toEqual(supersessionBase);
  expect(result.rejected).toHaveLength(2);
  expect(result.rejected[0]?.reason).toBe(
    "non-monotonic: decidedAt must increase unless explicitly superseding",
  );
  expect(result.rejected[1]?.reason).toBe(
    "backdated: decidedAt diverges from anchor beyond skew",
  );
});

test("P3 accepts explicit supersession chain for non-monotonic revision", () => {
  const result = supersessionOrder([
    supersessionBase,
    {
      disputeId: "d-2",
      decidedAt: 1_000,
      contentHash: "aaa",
      supersedes: "d-1",
    },
    {
      disputeId: "d-3",
      decidedAt: 1_500,
      contentHash: "zzz",
    },
  ]);

  expect(result.rejected).toEqual([]);
  expect(result.honored).toEqual({
    disputeId: "d-3",
    decidedAt: 1_500,
    contentHash: "zzz",
  });
});

test("P3 rejects supersedes references that do not name a prior accepted outcome", () => {
  const result = supersessionOrder([
    supersessionBase,
    {
      disputeId: "d-2",
      decidedAt: 1_000,
      contentHash: "aaa",
      supersedes: "missing",
    },
  ]);

  expect(result.honored).toEqual(supersessionBase);
  expect(result.rejected).toEqual([
    {
      outcome: {
        disputeId: "d-2",
        decidedAt: 1_000,
        contentHash: "aaa",
        supersedes: "missing",
      },
      reason:
        "non-monotonic: supersedes must name a prior disputeId or contentHash",
    },
  ]);
});
