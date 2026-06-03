# DACS v0.1 — conformance vectors

An independent, third-party set of executable conformance vectors for DACS v0.1, run against the verifier in this repo. Point your own DACS implementation at the same inputs and diff the outputs.

> Proposed / non-normative. MIT. The steward owns all normative and namespace calls — this is a contributor artifact, not part of the standard.

Surface labels travel with each vector:

- **GOLDEN (107)** — byte-stable and accepted by this reference verifier: 24 primitive checks, 4 checks in one §10.4 bundle area, 18 dispute/disclosure checks pinned to DACS-VERIFY-0004 bundle refs, 30 §14.4 settlement-evidence checks, and 31 §14.5 verify checks.
- **CANDIDATE (0)** — no current candidate vectors.

## Why

The spec's §14 conformance chapter defines conformant behaviour but ships no second independent verifier and no published vectors. This is one: 24 golden primitive vectors, DACS-VERIFY-0004 §10.4 AttestationBundle fixtures, 18 golden vectors exercising the proposed DACS-X dispute + disclosure flow against pinned bundle refs, 30 golden §14.4 SettlementEvidence vectors (PC-1..6, RD-5 rail coherence, CD-1 amounts), and 31 golden §14.5 Verify vectors (two-sided lookup, §10.4.3(a-d) consumption, ST-1..7 transitions, reputation derivation).

## Run

```sh
bun conformance/run.ts          # run all 107 vectors → exit non-zero on any failure
bun conformance/run.ts --emit   # regenerate MANIFEST.json + vectors/golden.json
```

Deterministic by construction: every key and signature is derived from a fixed public seed (`examples/issuer-kit.ts`) and every timestamp is pinned, so each run is byte-stable. No private key material is stored — seeds are public test inputs. DACS-X inputs are constructed in `run.ts` itself and pin bundle fixtures by `(jobId,bundleHash)`.

## Coverage

- `canonicalize`: 7 golden vectors, §7.1 JCS canonicalization and §7.2 signed scope.
- `decimal`: 5 golden vectors, §14.4 CD-1 canonical decimals and §9.3 positivity.
- `signing`: 5 golden vectors, §7.7 domain-separated Ed25519 (SIG-2 / SIG-4).
- `dacs1`: 7 golden vectors, §6.3 identity bundles, requirement matching, listing validation.
- `bundle`: 4 golden vectors, §10.4 / §10.4.1 AttestationBundle verification.
- `dispute`: 9 golden vectors, §11.2.1 DACS-X dispute flow with the 4-value decision (`pass`/`fail`/`indeterminate`/`error`).
- `disclosure`: 9 golden vectors, §8.7 DACS-X arbitrator transcript-disclosure (step 3, DP-1).
- `settlement`: 30 golden vectors, §14.4 SettlementEvidence verification — PC-1..6 (anchor, attestationRef→evidence hash, outcome classification, currency-resolution, settlementFinality), RD-5 railType↔asset/network coherence, §9.5.1/PIPE-5 amount==agreement.terms.price, CD-1/§9.3 amount canonicalisation, and the `dacs-4-evidence` signature.
- `verify`: 31 golden vectors, §14.5 DACS-5 Verify — two-sided lookup `stor-{sha256(jobId+"-bundle-"+role)}` (§10.4.2) with jobId binding, §10.4.3(a-d) consumption (one-sided→aborted-by-self per §10.11, unified, divergent — "divergent" is a **consumer verdict, NOT an `outcome` enum value**), ST-1..7 transition table + state→outcome mapping (§10.3.1), and reputation derivation (§10.5.1 — `party_fault_denom` excludes `failed-substrate`, null≠zero, anchorer-relative scoping, session dedup).

## §8.7 arbitrator-disclosure (step 3)

The disclosure vectors exercise DACS-X step 3 under steward sign-off **DP-1**: the full §8.7 channel transcript is disclosed to the **named arbitrator only**, producing **no presentable artifact**. A `dacs-x-disclosure-grant` (SIG-4) authorizes one transcript → one credentialed arbitrator → one dispute, either by **signed party agreement** (every channel member co-signs) or by **arbitrator order**. The verifier enforces: recipient is the credentialed arbitrator (anti-swap, DP-5 bilateral selection), the disclosed transcript matches the grant's pinned hash (anti-substitution), the grant binds to the open dispute, the transcript's own member signatures verify, and the result is a bare check — nothing re-anchorable. It is structurally distinct from §11.2.7 claim-disclosure (different object, audience, and output). No new cryptography — §7.7 signing + §7.2 hashing + DACS-1 claim references only (DP-4).

## Files

- `MANIFEST.json` — the case index: every vector's `id`, `area`, spec `§`, summary, `status`, golden `reason`, and pinned `want`.
- `fixtures/attestation-bundle-0004.json` — the full byte-stable completed §10.4 AttestationBundle fixture.
- `fixtures/attestation-bundle-0004-seller.json` — the same `jobId` as DACS-VERIFY-0004 with a divergent `failed-counterparty` outcome; it verifies independently and has a different bundle hash.
- `fixtures/attestation-bundle-htlc9.json` — the full byte-stable HTLC-9 asymmetric-settlement fixture.
- `fixtures/settlement-evidence-payment-success.json` — a byte-stable pay-evm-erc20 success SettlementEvidence (§9.7) with its PaymentPhaseInput + PhaseHandlerResult, signed by a deterministic orchestrator key.
- `fixtures/settlement-evidence-delivery-success.json` — a byte-stable deliver-storage-program success SettlementEvidence (deliverable content hash + anchor, no settlementFinality).
- `fixtures/session-bundle-one-sided.json` — a one-signature `aborted-by-other` bundle for the §10.4.3(b)/§10.11 one-sided case.
- `fixtures/session-bundles-reputation.json` — a mixed-outcome bundle set (completed / failed-counterparty / failed-substrate / aborted-by-self / aborted-by-other) for §10.5.1 reputation derivation.
- `vectors/golden.json` — pinned outputs: deterministic signature, native-address derivation, bundle refs/hashes, dispute/disclosure decision maps + seeds, the §14.4 settlement decision map, and the §14.5 verify verdict/reputation maps.
- `run.ts` — the runner; also the executable spec of how each input is constructed.

## Implementation observations (non-normative)

Vectors that double as executable evidence of implementation friction. Stated as observations for the group to confirm or correct, not as normative claims:

- **DACS-VERIFY-0001** — a `cci-lei:` claim does **not** satisfy a bare `lei` requirement (§6.3.1 registers `cci-lei`; §6.3.3/§7.4.2 use bare `lei`; `find_claim` does exact-scheme equality). Adjacent to issue **#42**'s broader `ClaimReference` canonical-equality discussion.
- **DACS-VERIFY-0002** — separators used normatively in the spec body (e.g. `dacs-session-binding:v1:`, `dacs-sealed-bid:v1:`) are absent from the §7.7 closed registry and are not `x-`-prefixed (SIG-4).
- **DACS-VERIFY-0003** — the §6.3.4 native-address rule yields `stor-<64hex>`, whereas Demos addresses `stor-<40hex>` keyed differently. A listing anchored per the spec rule would not resolve on the substrate. *Verify on substrate before relying.*
- **DACS-VERIFY-0004** — `conformance/fixtures/attestation-bundle-0004.json` is a full completed §10.4 `AttestationBundle`, signed by buyer + seller with deterministic issuer-kit keys. `conformance/fixtures/attestation-bundle-0004-seller.json` is a same-`jobId` divergent seller-side bundle with outcome `failed-counterparty`; it also verifies and has a distinct bundle hash. Divergent-bundle dispute/disclosure vectors pin both refs. The bundle verifier accepts valid bundles, rejects a completed bundle missing a required signer, and surfaces malformed resolved keys as `error`.

The published golden vectors (`dacs1-cci-lei-defect`, `dacs1-native-address`, etc.) assert the observed behaviour, so the evidence is runnable.
