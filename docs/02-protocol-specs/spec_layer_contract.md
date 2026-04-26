# Specification Layer Contract

Rust implementation is canonical. Specification artifacts are layered and non-overlapping.

## Level 1: Execution Spec (Code-Accurate)

Primary document:
- `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md`

Responsibilities:
- exact function surfaces
- exact transcript structs and field names
- exact FS domain strings, labels, ordering, and byte packing
- exact hash/XOF transformation framing
- exact simulator step ordering

Allowed detail level:
- byte-level and field-level precision

## Level 2: Theorem Spec (Game-Based Abstraction)

Primary document:
- `docs/02-protocol-specs/qssm-zk-theorem-spec.md`

Responsibilities:
- game sequence (`G0`, `G1`, `G2`)
- epsilon decomposition
- assumption mapping (`A1`, `A2`, `A4`)
- exact-simulation lemma placement (`MS-3a`, `MS-3b`, `MS-3c`)

Forbidden detail:
- transcript struct field inventories
- byte-level FS construction
- simulator internal hashing order

## Level 3: Engine Specs (Interface-Level Only)

Primary documents:
- `docs/02-protocol-specs/qssm-ms-engine-b.md`
- `docs/02-protocol-specs/qssm-le-engine-a.md`
- `docs/02-protocol-specs/blake3-lattice-gadget-spec.md`

Responsibilities:
- API/interface contracts for each engine
- cross-engine handshake/binding surfaces
- high-level field/interface compatibility requirements

Forbidden detail:
- theorem game decomposition
- duplicate byte-level execution internals already covered by Level 1

## Cross-Layer Rules

1. Level 1 is the only spec layer allowed to define byte-level execution and naming exactness.
2. Level 2 must reference Level 1 for execution detail, not duplicate it.
3. Level 3 must define interfaces and contracts, not theorem internals.
4. No layer may override Rust behavior; if conflict exists, Rust wins and specs are updated.
