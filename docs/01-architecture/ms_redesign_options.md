# MS v2 canonical redesign

This note turns the current MS failure map into the single canonical redesign track.

## Problem statement

Under the frozen hidden-value ZK game, the current MS transcript is structurally blocked because the visible transcript exposes witness-dependent outputs:

- `n`
- `k`
- `bit_at_k`

The formal simulator attempt in [truth-engine/qssm-proofs/src/reduction_zk/mod.rs](../../truth-engine/qssm-proofs/src/reduction_zk/mod.rs) fails exactly at:

- `MS k/n selection`
- `MS bit_at_k extraction`
- `MS visible opening`

This is a transcript design problem, not a parameter-tuning problem.

## Solution: frozen predicate-only commitment proof

The redesign phase is over. MS v2 is now treated as the canonical fixed-point interface for reduction work.

### Transcript definition

- Visible transcript carries a public value commitment, a result bit, 64 bitness Sigma transcripts, and one comparison Sigma transcript.
- No legacy coordinate metadata (`n`, `k`, `bit_at_k`, Merkle openings) is exposed.
- In code, this surface is implemented as `qssm_ms::PredicateOnlyStatementV2` and `qssm_ms::PredicateOnlyProofV2`.
- The formal observable boundary is frozen in [ms_v2_observable_boundary_contract.md](./ms_v2_observable_boundary_contract.md).

### Verifier algorithm

1. Interpret the statement as an NP relation: there exists hidden witness material such that the predicate holds.
2. Verify the commitment-bound bitness and comparison proof against the public statement under Fiat-Shamir.
3. Reduction work is now about zero-knowledge on the frozen boundary, not about replacing a missing backend.

### Simulator sketch

1. Rebuild the public predicate-only statement from the public value commitment and public statement data.
2. Sample an accepting transcript directly from the public statement in the programmable ROM.
3. Output only frozen observable projections; do not follow the prover witness path.

### Tradeoffs

- Cleanest cryptographic shape.
- Fixed reduction target for the remaining ZK proof work.
- Loses all coordinate-level introspection.