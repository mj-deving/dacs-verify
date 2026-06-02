# DACS-X Interface Contract — v0.1

> **Status: PROPOSED · NON-NORMATIVE · DRAFT.**
> This is a *contributor-coordination* artifact, not a DACS normative document. The DACS steward (KyneSys) owns the `dacs-x-*` namespace and every normative/ratification decision. Nothing here changes DACS v0.1. It exists so two independent implementations can target the **same artifact shape and the same state transitions** while DACS-X (§11.2.1 dispute / execution-verification) is still forward-design.
>
> **Scope of this contract:** the seam between a DACS-X **dispute layer** (producer) and a DACS-5 **verification + DACS-4 settlement layer** (consumer). Concretely, the seam between this repo's dispute prototype and PATH-OS's `verify-bundle` / `settlement-evidence-verifier` / forthcoming `DisputeOutcome` reference verifier.
>
> **Contract version v0.1.** Reference implementation: `mj-deving/dacs-verify` (`src/dacsx/`). Coordinated with PATH-OS-Labs.

---

## 0. Why this exists

DACS-X is unspecified in v0.1. Two impls are now building against the same idea: a dispute layer that consumes a DACS-5 `AttestationBundle` and emits an arbitrated outcome that supersedes the disputed session's reputation contribution and, for the HTLC-9 asymmetric-settlement case, closes the settlement. Without a pinned interface the two will drift — different field names, different binding rules, an outcome one side signs and the other can't verify.

This contract pins exactly three things and nothing more:

1. The **`DisputeOutcome`** artifact shape + how it's hashed and signed (§1–§3).
2. The **§11.2.1 supersession** semantics — how an outcome reweights the disputed contribution (§4).
3. The **HTLC-9 `correction` emission** rule — the settlement seam (§5).

Everything is **composition of DACS v0.1 primitives already in the spec** (§7.2 content hash, §7.7 domain-separated signing, DACS-1/2 `matchRequirement`, CD-1 decimal, §9.7.1 SettlementAmendment). No new cryptography, no new separators beyond the SIG-4 extension namespace the spec itself prescribes.

---

## 1. The `DisputeOutcome` artifact

Both sides exchange one signed artifact: the arbitrator-signed `DisputeOutcome`. Exact field set (7 fields — a consumer MUST reject an outcome that is missing or extends this set):

| field | type | rule |
|-------|------|------|
| `dacsXVersion` | string | MUST equal `"1"` (artifact wire version; distinct from this contract's v0.1) |
| `disputeId` | string | MUST equal the `DisputeRecord.disputeId` it resolves |
| `disputeRecordHash` | string | sha256 hex of the `DisputeRecord` **signed scope** (§7.2; `signature` omitted). Binds the outcome to one open. |
| `arbitrator` | `ClaimReference` (string) | the arbitrator's primary claim reference (§6.3) |
| `remedy` | `RemedyDecision` | one of the closed union in §2 |
| `decidedAt` | number | integer epoch; subject to §7.1 numeric-safe-integer rule |
| `signature` | string | Ed25519 over the signed bytes (§3), base64url of the raw 64-byte value |

**Binding invariants (a consumer MUST enforce all three):**

- `outcome.disputeId === record.disputeId`
- `outcome.disputeRecordHash === sha256Hex(JCS(record \ signature))`
- `outcome.signature` verifies against the arbitrator's resolved Ed25519 key under the §3 separator.

A `DisputeRecord` (the dispute-open the outcome binds to) carries: `dacsXVersion:"1"`, `disputeId`, `initiator` (`ClaimReference`), `disputed: {jobId, bundleHash}[]`, `contestedClaim`, `requestedRemedy`, `arbitration:{ruleRef}`, `openedAt`, `signature`. The arbitrator is credentialed against a content-hashed `arbitration.ruleRef` (§8.4.3) so the arbitrator set cannot be swapped after the outcome is known — but arbitrator credentialing is producer-internal and **out of scope for this interface**; the consumer only needs the `DisputeOutcome` and the `DisputeRecord` it names.

---

## 2. `RemedyDecision` — closed union (4 kinds)

A consumer MUST reject an unknown `kind` (no pass-through). Per DACS §7.1, every fractional quantity is a **CD-1 canonical decimal string**, never a bare JSON number.

```
RefundOrder              { kind: "refund-ordered",     amount: CD1-string (> 0, §9.3), asset: string }
ReputationCorrection     { kind: "reputation-corrected", weightMultiplier: CD1-string ∈ [0,1], favors: "initiator" | "respondent" }
NoFault                  { kind: "no-fault" }
CorrectionAmendmentOrder { kind: "correction-ordered", correctedOutcome: "failure", reason: string, revealTxRef: string }
```

- **`refund-ordered`** — `amount` MUST be CD-1 canonical and strictly `> 0` (§9.3); `asset` is an opaque rail identifier.
- **`reputation-corrected`** — `weightMultiplier` MUST be CD-1 canonical and in `[0,1]`.
- **`no-fault`** — outcome stands; the contribution is *adjudicated* (§4).
- **`correction-ordered`** — the HTLC-9 seam; see §5.

---

## 3. Hashing & signing (§7.2 + §7.7 / SIG-4)

Identical to DACS §7.7, using the SIG-4 extension namespace for unlisted artifact kinds. **Both sides MUST compute the signed bytes the same way or no outcome verifies.**

```
signed_scope   := the artifact with its `signature` field removed
content_hash   := lowercase-hex sha256( RFC-8785-JCS( signed_scope ) )     // §7.2
signed_bytes   := utf8(domain_separator) || ascii(content_hash)            // §7.7, no separator byte
signature      := Ed25519( signed_bytes )                                  // base64url, raw 64 bytes
```

**SIG-4 domain separators (frozen for this contract):**

| artifact kind | separator |
|---------------|-----------|
| dispute-open | `dacs-x-dispute-record:v1:` |
| dispute-outcome | `dacs-x-dispute-outcome:v1:` |

These live in a **separate registry, disjoint from the §7.7 closed set** — `isRegisteredSeparator()` MUST stay `false` for both. This is exactly §7.7's prescribed extension mechanism (SIG-4) and keeps signature provenance honest: a verifier can tell a spec-native artifact from a proposed-extension artifact by its separator alone. Domain separation also gives cross-artifact replay resistance for free — a dispute-record signature does not verify as a dispute-outcome.

JCS canonicalization is byte-exact (key-sort + RFC 8785 escaping); §7.1 numeric-safe-integer enforcement applies (non-safe-integer numbers are a serialization error; fractionals are CD-1 strings).

---

## 4. §11.2.1 supersession — reweight semantics

A `DisputeOutcome` supersedes/annotates the disputed session's DACS-5 §10.5 reputation contribution. The reweight is **NON-DESTRUCTIVE**: the prior weight is preserved (audit trail — a dispute record must show *why* a weight changed), an effective weight is derived, and the outcome's content hash rides as provenance.

```
ReputationReweight { jobId, priorWeight: number, effectiveWeight: number, adjudicated: true, adjudicatedBy: string }
adjudicatedBy := sha256Hex( JCS( outcome \ signature ) )   // the DisputeOutcome content hash
```

**Remedy → `effectiveWeight` mapping (a consumer MUST derive identically):**

| remedy | `effectiveWeight` |
|--------|-------------------|
| `refund-ordered` | `0` — delivery was not as agreed → contribution voided |
| `reputation-corrected` | `priorWeight × Number(weightMultiplier)` |
| `no-fault` | `priorWeight` — stands, but now adjudicated → immune to re-farming |
| `correction-ordered` | `0` — HTLC-9 failure; weighted strictly worse than a clean timeout (§9.8) |

> **OPEN QUESTION (steward's call, not ours):** whether ratified DACS-5 wants this **non-destructive** shape (preserve prior + derive effective, append-only) or a **destructive supersede**. This contract implements the non-destructive default and flags the choice rather than asserting a §10.5 mandate.

---

## 5. HTLC-9 `correction` emission — the settlement seam

This is the load-bearing interop point with the settlement lane. HTLC-9 (§9.5.4) defines the asymmetric cross-chain state **`dest-revealed-source-unclaimed`**: the payee was paid on the destination chain (preimage revealed) but the source-chain claim failed. §9.8 specifies how to *represent* this state but **DEFERS its resolution to "dispute or manual intervention"** — i.e. to DACS-X. This contract pins that resolution.

**Invariant (a settlement consumer MUST enforce — this is a physics constraint, not a policy choice):**

An asymmetric `dest-revealed-source-unclaimed` settlement resolves to a **§9.7.1 SettlementAmendment of type `correction`**, emitted as the `correction-ordered` remedy:

```
CorrectionAmendmentOrder {
  kind:             "correction-ordered",
  correctedOutcome: "failure",          // MUST be "failure" — never "success", never a refund
  reason:           "dest-revealed-source-unclaimed" | <structured string>,
  revealTxRef:      <htlc-reveal txRef> // the destination-chain preimage-reveal txRef, already in §9.5.4 paymentTxRefs
}
```

- `correctedOutcome` MUST be `"failure"`. A consumer MUST reject `success`/refund closure: **refunding double-pays a payee who already received on the destination chain** (§9.8). This is the one rule the settlement lane cannot relax.
- `reason` MUST be a non-empty structured string.
- `revealTxRef` MUST reference the `htlc-reveal` txRef already present in the session's settlement evidence (§9.5.4).

**Consumption:** the dispute layer (producer) emits the `correction-ordered` `DisputeOutcome`; the settlement layer (`settlement-evidence-verifier`) validates that the named `revealTxRef` matches the session's HTLC-9 evidence and closes the settlement as a §9.7.1 `correction`. The reputation reweight (§4) voids the contribution. This closes the hole §9.8 leaves open.

### 5.1 What v0.1 does NOT pin — deferred to v0.2 (the silent-divergence class)

v0.1 pins the **outputs and the one transition**: the artifact shape (§1–§3), the reweight mapping (§4), and the HTLC-9 *consequent* — *when* the state is `dest-revealed-source-unclaimed`, emit `correction`/`failure`/never-refund (§5). It does **not** pin the **resolution predicates that decide the state** — and that is the class where two contract-honoring impls can still silently disagree and reach different *irreversible* terminal states from identical facts:

- **claim/preimage→key binding** — which revealed preimage binds to which HTLC/key. `dest-revealed-source-unclaimed` is a *derived* predicate over this resolution; the reference impl treats claim→key resolution as substrate-dependent and outside the read-only verifier. If two impls resolve the binding differently, one sees the HTLC-9 trigger and emits `correction`, the other classifies a different HTLC-9 substate and emits a plain `failure` — and `never-refund` is irreversible.
- **§9.7.1 three-way branch predicate** — the exact, shared predicate selecting `correction` vs the other §9.7.1 amendment outcomes from the settlement evidence.
- **`decidedAt` monotonicity + multi-outcome supersession total-order** — when an outcome is revised, which one settlement honors (a sub-component of the §11.2.1 supersession ordering, §4).

Crucially these fail **silently**: both impls can pass v0.1 conformance and still disagree, unlike a shape or JCS mismatch which fails **loud** (verify rejects). **v0.2 headline = pin the claim→key / preimage-binding predicate and the §9.7.1 branch predicate first; the supersession total-order (incl. `decidedAt`) second.** Until then, read v0.1 as *outputs pinned, resolution predicates deferred* — NOT "the seam is fully deterministic across impls."

---

## 6. Interop boundary — who produces what

| responsibility | side | artifact / function |
|----------------|------|---------------------|
| `DisputeRecord` (dispute-open) + signature | **producer** (dispute layer) | `dacs-x-dispute-record:v1:` |
| Arbitrator credentialing (DACS-1/2 `matchRequirement` + content-hashed `ruleRef`) | **producer**, internal | — (not on this interface) |
| `DisputeOutcome` (signed) | **producer** | `dacs-x-dispute-outcome:v1:` |
| §11.2.1 reputation reweight | **producer** emits, **consumer** may re-derive | `ReputationReweight` |
| Validate the disputed `AttestationBundle` the `DisputeRecord` pins | **consumer** | `verify-bundle` (§10.4.1 co-signed two-sided walk; §10.4.3 fetch-both addressing) |
| Validate HTLC-9 evidence + close §9.7.1 `correction` | **consumer** | `settlement-evidence-verifier` |
| `DisputeOutcome` reference verifier | **consumer** | (forthcoming, their side) |

The producer never touches a private key in its verifier path (read-only); all signing is confined to a clearly-marked demo issuer kit. The consumer never needs the producer's keys — only the public artifacts and the `DisputeRecord` they name.

---

## 7. Vector loop (anti-drift)

The reference impl emits **illustrative, non-normative** fixtures, byte-stable across runs (deterministic seeds), as candidate §14 dispute vectors:

| path | scenario |
|------|----------|
| `vectors/dacs-x/*.json` | §10.4.3 divergent-bundle dispute → credentialed arbitrator → arbitrated outcome → reweight |
| `vectors/dacs-x/htlc9/*.json` | HTLC-9 asymmetric-settlement dispute → `correction` amendment → contribution voided |

**The loop:** the producer publishes vectors as it produces them; the consumer runs them through `verify-bundle` + `settlement-evidence-verifier` (+ the forthcoming `DisputeOutcome` verifier) and reports PASS/FAIL. Any disagreement is a drift signal against this contract — resolved by fixing whichever side diverges from §1–§5, or by amending this contract (§8). These vectors prove **internal self-consistency between two impls**, NOT spec conformance — DACS-X is unratified.

---

## 8. Versioning & status

- **Contract version v0.1.** Mirrors DACS draft versioning: **additive = minor**, **breaking = major**, editorial = no bump. A new remedy kind or field is a minor bump; changing the HTLC-9 invariant or a separator is a major bump.
- **Artifact wire version** is the `dacsXVersion: "1"` field — distinct from this document's version.
- **PROPOSED / NON-NORMATIVE.** The steward owns the `dacs-x-*` namespace and ratification. If/when DACS-X is specified normatively, this contract is superseded by the spec text; until then it is two contributors agreeing on a shape so their code interoperates.
- **v0.2 roadmap (committed):** close the silent-divergence class in §5.1 — pin the claim→key / preimage-binding predicate and the §9.7.1 three-way branch predicate first, the supersession total-order (incl. `decidedAt` monotonicity) second. v0.1 deliberately pins outputs only; the resolution predicates are the v0.2 headline.

## Changelog

- v0.1 (2026-06-02) — initial contract. Pins the `DisputeOutcome` 7-field shape (§1), the closed 4-kind `RemedyDecision` union (§2), §7.2/§7.7-SIG-4 hashing & signing with the two `dacs-x-*` separators (§3), the non-destructive §11.2.1 reweight + remedy→effectiveWeight mapping (§4), and the HTLC-9 `dest-revealed-source-unclaimed` → §9.7.1 `correction`/`failure`/never-refund emission rule (§5). All shapes mirror `mj-deving/dacs-verify` `src/dacsx/` as shipped.
