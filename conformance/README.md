# DACS v0.1 — conformance vectors

An independent, third-party set of executable conformance vectors for DACS v0.1, run against the verifier in this repo. Point your own DACS implementation at the same inputs and diff the outputs.

> Proposed / non-normative. MIT. The steward owns all normative and namespace calls — this is a contributor artifact, not part of the standard.

Two surfaces, labelled per vector so nothing is mistaken for more than it is:

- **GOLDEN (24)** — byte-stable **and** accepted by the reference verifier. Pure DACS v0.1 primitives: two conformant implementations cannot disagree on them.
- **CANDIDATE (18)** — single-impl DACS-X (§11.2.1 dispute + §8.7 disclosure). Cross-impl agreement is pending the shared fixture being pinned in interface-issue **#99** (see observation 0004). Published so the shape is reviewable, explicitly **not** as reference-accepted golden.

## Why

The spec's §14 conformance chapter defines conformant behaviour but ships no second independent verifier and no published vectors. This is one: 24 golden vectors across the deterministic primitive surface a verifier must agree on byte-for-byte, plus 18 candidate vectors exercising the proposed DACS-X dispute + disclosure flow (steward-signed-off shape, cross-impl fixture pending #99).

## Run

```sh
bun conformance/run.ts          # run all 42 vectors → exit non-zero on any failure
bun conformance/run.ts --emit   # regenerate MANIFEST.json + vectors/golden.json
```

Deterministic by construction: every key and signature is derived from a fixed public seed (`examples/issuer-kit.ts`) and every timestamp is pinned, so each run is byte-stable. No private key material is stored — seeds are public test inputs. Candidate-vector inputs are constructed in `run.ts` itself (the executable spec of each input); re-run to regenerate.

## Coverage

| Area | Vectors | Spec | Surface |
|------|--------:|------|---------|
| `canonicalize` | 7 | §7.1 JCS canonicalization, §7.2 signed scope | **golden** |
| `decimal` | 5 | §14.4 CD-1 canonical decimals, §9.3 positivity | **golden** |
| `signing` | 5 | §7.7 domain-separated Ed25519 (SIG-2 / SIG-4) | **golden** |
| `dacs1` | 7 | §6.3 identity bundles, requirement matching, listing validation | **golden** |
| `dispute` | 9 | §11.2.1 DACS-X dispute flow — the 4-value decision (`pass`/`fail`/`indeterminate`/`error`) | **candidate** (pending #99) |
| `disclosure` | 9 | §8.7 DACS-X arbitrator transcript-disclosure (step 3, DP-1) | **candidate** (pending #99) |

## §8.7 arbitrator-disclosure (step 3)

The disclosure vectors exercise DACS-X step 3 under steward sign-off **DP-1**: the full §8.7 channel transcript is disclosed to the **named arbitrator only**, producing **no presentable artifact**. A `dacs-x-disclosure-grant` (SIG-4) authorizes one transcript → one credentialed arbitrator → one dispute, either by **signed party agreement** (every channel member co-signs) or by **arbitrator order**. The verifier enforces: recipient is the credentialed arbitrator (anti-swap, DP-5 bilateral selection), the disclosed transcript matches the grant's pinned hash (anti-substitution), the grant binds to the open dispute, the transcript's own member signatures verify, and the result is a bare check — nothing re-anchorable. It is structurally distinct from §11.2.7 claim-disclosure (different object, audience, and output). No new cryptography — §7.7 signing + §7.2 hashing + DACS-1 claim references only (DP-4).

## Files

- `MANIFEST.json` — the case index: every vector's `id`, `area`, spec `§`, summary, `status` (golden/candidate), and pinned `want`.
- `vectors/golden.json` — pinned outputs: the deterministic signature + native-address derivation (golden), and the dispute/disclosure decision maps + seeds (candidate).
- `run.ts` — the runner; also the executable spec of how each input is constructed.

## Implementation observations (non-normative)

Vectors that double as executable evidence of implementation friction. Stated as observations for the group to confirm or correct, not as normative claims:

- **DACS-VERIFY-0001** — a `cci-lei:` claim does **not** satisfy a bare `lei` requirement (§6.3.1 registers `cci-lei`; §6.3.3/§7.4.2 use bare `lei`; `find_claim` does exact-scheme equality). Adjacent to issue **#42**'s broader `ClaimReference` canonical-equality discussion.
- **DACS-VERIFY-0002** — separators used normatively in the spec body (e.g. `dacs-session-binding:v1:`, `dacs-sealed-bid:v1:`) are absent from the §7.7 closed registry and are not `x-`-prefixed (SIG-4).
- **DACS-VERIFY-0003** — the §6.3.4 native-address rule yields `stor-<64hex>`, whereas Demos addresses `stor-<40hex>` keyed differently. A listing anchored per the spec rule would not resolve on the substrate. *Verify on substrate before relying.*
- **DACS-VERIFY-0004** — the dispute/disclosure vectors run against **minimal** dispute-layer fixtures. Fed to PATH-OS's unmodified DACS-5 `verify-bundle`, a minimal fixture is out of scope — the verifier **correctly** returns §7.5.1 `indeterminate`, because it consumes a full §10.4 `AttestationBundle`. The two implementations currently target **different artifacts**; reconciling them onto one shared full-`AttestationBundle` fixture is the cross-impl seam tracked in issue **#99**. The candidate vectors are labelled as such while that fixture is open — single-impl, not cross-impl golden.

The published golden vectors (`dacs1-cci-lei-defect`, `dacs1-native-address`, etc.) assert the observed behaviour, so the evidence is runnable.
