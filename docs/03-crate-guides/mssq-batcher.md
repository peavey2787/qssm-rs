### Documentation map

* [README](../../README.md) — Project home
* [Crates overview](../01-architecture/crates-overview.md)
* [MSSQ protocol spec](../02-protocol-specs/mssq.md)
* **This document** — `mssq-batcher`: sequencing and SMT transitions

---

# `mssq-batcher` — sequencing and SMT transition logic

Crate: `crates/mssq-batcher`. Public API is re-exported from `mssq_batcher` (`src/lib.rs`).

## Role

Deterministic **MSSQ batch application**: lexicographic ordering, optional **ML-DSA** leader attestation verification, **injected** per-transaction semantic proofs (`TxProofVerifier`), and **canonical sparse Merkle proofs** on `L2Transaction::proof` before mutating state.

## Sequencing

- **`sort_lexicographical`**: sorts transactions by **`tx.id`** (32-byte key) in ascending lexicographic order (`crates/mssq-batcher/src/roles/sequencer.rs`).

## Leader lottery and attestations

- **`mssq_seed_from_anchor`**: `Seed_k = mssq_seed_k(parent_block_hash_prev, latest_qrng_value)` via `qssm_utils::mssq_seed_k`.
- **`mssq_seed_from_anchor_and_dag_tips`**: mixes the base seed with DAG tip hashes using `lattice_anchor_seed_with_tips` (`causal_dag` module).
- **`elect_leader`**: among candidates, picks the id with **minimal** `leader_score_digest(seed, id)`; on exact digest ties, retains the **first candidate in input order**.
- **`LeaderAttestation`**: slot, parent hash, QRNG limbs, claimed leader id, ML-DSA-65 public key bytes, signature, optional `smt_root_pre`.
- **`verify_leader_attestation_ctx`**: checks slot/context QRNG/parent hash, candidate membership, derived leader id from signing key, **lottery winner**, and ML-DSA signature over `leader_attestation_signing_bytes(...)` including rollup context digest.

See `crates/mssq-batcher/src/roles/leader.rs`.

## `apply_batch` pipeline

Implemented in `crates/mssq-batcher/src/state/view.rs`:

1. **Duplicate ids**: `BTreeSet` — duplicate `tx.id` → `DuplicateTxId`.
2. **`TxProofVerifier::verify_tx`**: application proof (e.g. lattice bundle) against `RollupContext` → `ProofVerificationFailed` on failure.
3. **`verify_tx_merkle_inclusion`**: `SparseMerkleProof::decode(tx.proof)` must succeed; `proof.key == tx.id`; if key absent in tree, proof must have **no** leaf value; if present, proof leaf must match; **`StateMirrorTree::verify_proof(state.root(), &proof)`** must hold.
4. **`apply_tx_transition`**: see payload kinds below.
5. **`pulse_height`** increments by 1; **`recent_roots`** pushes current `state.root()`.

## Payload kinds (v1 balance / leases)

- **Default / balance delta** (`tx_kind` = first byte, default `0x01` when empty via `unwrap_or(0x01)` — note: empty payload uses balance path with `add = 0`):

  - If `payload[0] == 0x01` and `len >= 9`: addend = `u64::from_le_bytes(payload[1..9])`; optional metadata `payload[9..]` up to **24** bytes into leaf bytes `[8..32]`.
  - Else if `len >= 8`: addend from first 8 bytes LE; metadata from `payload[8..]` up to 24 bytes into leaf tail.
  - Leaf is 32 bytes: `[0..8]` balance (LE u64), `[8..32]` metadata.

- **Storage lease** (first byte discriminant):

  - **`0x10`** — create: fixed layout `1 + 32 + 32 + 8 + 32` bytes after opcode (lease id, provider, rent LE, user_leaf_key).
  - **`0x11`** — PoR: lease id, proof length LE u16, then **`SparseMerkleProof`** bytes; verifies key matches lease’s `user_leaf_key` and `StateMirrorTree::verify_proof` against current root; rent payment when `pulse_height >= next_due_pulse`, then extends due by 1024.
  - **`0x12`** — slash: lease id; marks lease slashed/inactive.

Errors include `InvalidStorageLeasePayload`, `LeaseNotFound`, `PorFailed` (`crates/mssq-batcher/src/error.rs`).

## Pruning

- **`prune_state(state, keep_depth)`**: trims **`recent_roots`** deque to `keep_depth` entries (`usize`).

## Causal DAG and merit (library exports)

- **`CausalDag`**, **`EntropyPulse`**, **`lattice_anchor_seed_with_tips`** — DAG/tip coupling for seeds (`crates/mssq-batcher/src/dag/causal.rs`).
- **`merit_maturation`**, **`MeritState`**, **`MeritTier`** — pure time-based tier/multiplier helper (`crates/mssq-batcher/src/dag/merit.rs`). **Other crates may use this;** the `mssq-net` node currently uses a **separate** uptime-based string for UI snapshot (`Seedling` / `Mature` / `Boosted`) and does not call `merit_maturation` directly.

## Related crates

* State tree: `qssm-utils` — `StateMirrorTree`, `SparseMerkleProof`.
* Shared state container: `qssm-common` — `RollupState`, `StorageLease`.
