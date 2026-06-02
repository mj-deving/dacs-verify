# DACS v0.1 — primitive conformance vectors

An independent, third-party set of **byte-stable golden conformance vectors** for the deterministic DACS v0.1 **primitive** surface, executable against — and accepted by — the verifier in this repo. Point your own DACS implementation at the same inputs and diff the outputs. This is the primitive surface (24 vectors), not a complete conformance suite.

> Proposed / non-normative. MIT. The steward owns all normative and namespace calls — this is a contributor artifact, not part of the standard.

## Why

The spec's §14 conformance chapter defines conformant behaviour but ships no second independent verifier and no published golden files. This is one: **24 published vectors** across the deterministic surface a verifier must agree on byte-for-byte — canonicalization, signing, decimals, and identity-bundle validation. These are pure DACS v0.1: two conformant implementations cannot disagree on them.

The §11.2.1 DACS-X dispute vectors are **held from the published golden set** pending a cross-implementation fixture agreement — see observation 0004 and the note on the coverage table.

## Run

```sh
bun conformance/run.ts          # verify the 24 published primitive vectors → exit non-zero on any failure
bun conformance/run.ts --emit   # regenerate MANIFEST.json + vectors/golden.json
bun conformance/run.ts --full   # also run the §11.2.1 dispute vectors (held — see observation 0004)
```

Deterministic by construction: every key and signature is derived from a fixed public seed (`examples/issuer-kit.ts`) and every timestamp is pinned, so each run is byte-stable. No private key material is stored — seeds are public test inputs.

## Coverage

| Area | Vectors | Spec | Status |
|------|--------:|------|--------|
| `canonicalize` | 7 | §7.1 JCS canonicalization, §7.2 signed scope | **published golden** |
| `decimal` | 5 | §14.4 CD-1 canonical decimals, §9.3 positivity | **published golden** |
| `signing` | 5 | §7.7 domain-separated Ed25519 (SIG-2 / SIG-4) | **published golden** |
| `dacs1` | 7 | §6.3 identity bundles, requirement matching, listing validation | **published golden** |
| `dispute` | 9 | §11.2.1 DACS-X dispute flow — the 4-value decision (`pass`/`fail`/`indeterminate`/`error`) | **`--full` only — held pending #99** (observation 0004) |

## Files

- `MANIFEST.json` — the case index: every published vector's `id`, `area`, spec `§`, summary, and pinned `want`.
- `vectors/golden.json` — pinned byte-level outputs (the deterministic signature, the native-address derivation).
- `run.ts` — the runner; also the executable spec of how each input is constructed.

## Implementation observations (non-normative)

Vectors that double as executable evidence of implementation friction. Stated as observations for the group to confirm or correct, not as normative claims:

- **DACS-VERIFY-0001** — a `cci-lei:` claim does **not** satisfy a bare `lei` requirement (§6.3.1 registers `cci-lei`; §6.3.3/§7.4.2 use bare `lei`; `find_claim` does exact-scheme equality). Adjacent to issue **#42**'s broader `ClaimReference` canonical-equality discussion.
- **DACS-VERIFY-0002** — separators used normatively in the spec body (e.g. `dacs-session-binding:v1:`, `dacs-sealed-bid:v1:`) are absent from the §7.7 closed registry and are not `x-`-prefixed (SIG-4).
- **DACS-VERIFY-0003** — the §6.3.4 native-address rule yields `stor-<64hex>`, whereas Demos addresses `stor-<40hex>` keyed differently. A listing anchored per the spec rule would not resolve on the substrate. *Verify on substrate before relying.*
- **DACS-VERIFY-0004** — the dispute vectors run against **minimal** dispute-layer fixtures (`phaseSummary`/parties/outcome). Fed to PATH-OS's unmodified DACS-5 `verify-bundle`, a minimal fixture is out of scope — the verifier **correctly** returns §7.5.1 `indeterminate`, because it consumes a full §10.4 `AttestationBundle`. So the two implementations currently target **different artifacts**; reconciling them onto one shared full-`AttestationBundle` fixture is the cross-impl seam tracked in issue **#99**. The dispute vectors therefore stay `--full`-only and out of the published golden set while that fixture is open — single-impl, not cross-impl golden.

The published vectors (`dacs1-cci-lei-defect`, `dacs1-native-address`, etc.) assert the observed behaviour, so the evidence is runnable.
