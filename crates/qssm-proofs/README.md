# qssm-proofs

Formal invariant tracking and reduction scaffolding for cross-engine proof integrity in QSSM.

## Mandatory Formal Targets

## Pillar 1: Bit-Level Consistency

Goal: prove that 32-bit BLAKE3 word arithmetic can be lifted into
`R_q = Z_q[X]/(X^256+1)` without collision or unintended aliasing under the modeled witness path.

### Overflow Bound (modular wrap-around prevention)

The formal model must explicitly constrain all arithmetic relations so intermediate values stay
inside a safe range below `q = 8_380_417`, or are decomposed into bounded sub-relations before any
ring/field embedding:

- Boolean constraints remain in `{0,1}`.
- XOR constraints use degree-2 forms on booleans.
- Full-adder and carry relations are bounded small-integer equations.
- No unchecked direct embedding of full-width 32-bit aggregates into field equations that could wrap.

This preserves "Math is Law": soundness is tied to bounded equations, not accidental mod-`q` wrap.

## Pillar 2: Path Integrity

Goal: prove soundness of the 7-step Merkle path (depth 128) in the R1CS layer with identical
domain-separated parent hashing as runtime verification.

Target obligations:

- Correct sibling orientation at each level.
- Deterministic path-index binding.
- Root recomputation equivalence against the canonical Merkle parent definition.

## Pillar 3: Non-Interactive Binding

Goal: formalize Fiat-Shamir binding between Engine B `fs_v2` challenges and the Engine A
Lyubashevsky-style transcript, including explicit domain separation and replay resistance.

### Cross-Protocol Digest (domain separation)

The model must show that transcripts are bound under separate domains and a shared binding digest:

- Engine A transcript domain: `QSSM-LE-FS-LYU-v1.0`.
- Engine B FS context: `DOMAIN_MS` with label `fs_v2`.
- Cross-protocol binding digest must include both transcript contexts and rollup context digest, so
  a valid transcript from one engine cannot be replayed in the other engine context.

## Security Gate Policy

- Target class: 128-bit security.
- CI enforcement floor: 112 bits.
- Structural preconditions (compiler-synced): `C_POLY_SIZE >= 64` and digest coefficient vector size `>= 64`.
- A mandatory test in `qssm-proofs` fails when current effective security drops below 112 bits.
- Structured security evidence is read from `docs/02-protocol-specs/qssm-security-evidence.json` (with legacy markdown fallback only for migration).

This turns sovereign security policy into a compiler/test-enforced invariant.

