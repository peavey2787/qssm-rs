# ROM Analysis

This file is the canonical ROM dependency analysis for the current QSSM theorem path.
Rust code remains the source of truth.

## Essential vs Non-Essential ROM Use

Essential (simulation-critical):
- MS programmed query challenges for announcement-only digests
- LE programmed FS challenge seed path

Non-essential as ROM (can be viewed as deterministic hashing/KDF use):
- statement digests
- seed derivation helpers
- Merkle parent hashing
- deterministic prover randomness derivation utilities

## MS Programmed Query Surface (Explicit)

Programmed query digests:
- `bitness_query_digest(statement_digest, bit_index, announce_zero, announce_one)`
- `comparison_query_digest(statement_digest, clauses)` from clause announcements

Challenge mapping:
- `hash_query_to_scalar(query_digest)`

This is the announcement-only contract tested in integration tests.

## LE Programmed Query Surface (Explicit)

Programmed LE challenge digest corresponds to the same transcript bytes used in verification FS recomputation:
- domain and DST constants
- cross-protocol label material
- binding context
- CRS seed
- public binding bytes
- commitment bytes
- `t` bytes

## Failure Characterization Without ROM

Expected outcome:
- binding-only algebraic checks may survive
- programmed Fiat-Shamir simulation chain does not
- composed global simulator claim therefore fails without ROM programmability

This is expected for Fiat-Shamir-based NIZK simulation arguments.

## Source Mapping

- centralized FS API in proofs crate:
  - `truth-engine/qssm-proofs/src/shared/fiat_shamir.rs`
- MS query/challenge implementation:
  - `truth-engine/qssm-ms/src/v2.rs`
- LE FS challenge implementation:
  - `truth-engine/qssm-le/src/protocol/commit.rs`
- announcement-only and sequence snapshot tests:
  - `truth-engine/qssm-proofs/tests/ms_announcement_contract.rs`
