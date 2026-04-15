### Documentation map

* [README](../../README.md) — Project home
* [Crates overview](../01-architecture/crates-overview.md)
* [MSSQ protocol spec](../02-protocol-specs/mssq.md)
* **This document** — `qssm-common`: L1 view, `SovereignAnchor`, rollup types

---

# `qssm-common` — the Kaspa DAG view and rollup wire types

Crate: `crates/qssm-common`. **Forbidden:** `unsafe` code.

## Role

Single place for **L1-facing traits**, **L2 wire types**, and **`RollupState`** so engines, batcher, Kaspa adapter, and tests share one definition of “what the anchor said” and “what MSSQ sequenced.”

## `L1Anchor` — how QSSM reads Kaspa (finalized, not volatile tip)

Defined in `src/chain/l1_anchor.rs`. Implementations must be **`Send + Sync`**.

The trait is explicitly **finality-aware**: rollup proofs and seeds use **settled** limbs, not tip-only volatile fields.

| Method | Role in QSSM |
|--------|----------------|
| `get_current_slot` | Logical MSSQ / rollup slot counter (tests and adapters set this explicitly). |
| `get_ledger_entropy` | 32-byte ledger-entropy limb (mock mixes slot + genesis; production adapter maps from Kaspa). |
| `parent_block_hash_prev` | **Previous finalized block hash** for the current rollup — primary limb for **`RollupContext.finalized_block_hash`** and **`mssq_seed_k(parent, qrng)`**. |
| `latest_qrng_value` | 32-byte QRNG limb (epoch-scoped in mock via `refresh_qrng_digest`). |
| `qrng_epoch` | Counter advanced when QRNG material rotates. |
| `finalized_blue_score` | Kaspa **blue score at the finalized boundary** included in rollup context (mock: `finalized_tick`). |
| `is_block_finalized` | Policy predicate: whether a 32-byte hash counts as finalized for this node’s view. |

**`rollup_context_from_l1`** (`src/chain/rollup.rs`) builds **`qssm_utils::RollupContext`**:

```text
finalized_block_hash  = parent_block_hash_prev()
finalized_blue_score  = finalized_blue_score()
qrng_epoch            = qrng_epoch()
qrng_value            = latest_qrng_value()
```

**`RollupContext::digest()`** (in `qssm-utils`) is **`BLAKE3(DOMAIN_MSSQ_ROLLUP_CONTEXT ‖ …)`** over those four fields — this digest binds **ML-DSA leader attestations**, **QSSM-LE** Fiat–Shamir, and **QSSM-MS** challenges across L1 view changes (anti-replay across finalized snapshots).

## `L1BatchSink` and `SovereignAnchor`

- **`L1BatchSink`**: `post_batch(&Batch) -> Result<(), Error>` — DA / L1 posting path (mock appends to a `Vec`).
- **`SovereignAnchor`**: marker trait **`L1Anchor + L1BatchSink`** — “read the finalized DAG **and** optionally post L2 batches.”

Production **`GrpcKaspaAnchor`** (`crates/qssm-kaspa`) implements **`L1Anchor`** with stub fields until gRPC is wired; **`GrpcBatchSink`** implements **`L1BatchSink`**.

## `MockKaspaAdapter` — deterministic BlockDAG for tests

Now lives in **`crates/qssm-kaspa/src/adapter/mock.rs`** (not in `qssm-common`).
It simulates **volatile** vs **finalized** depth:

- **`fast_tick`**: advances on **`tick_fast()`** (~volatile tip).
- **`finalized_tick`**: included in **`parent_hash_with_tick(finalized_tick)`** — what **`parent_block_hash_prev`** uses.
- **`auto_finalize`**: if true, each `tick_fast` also bumps `finalized_tick`; if false, volatile can run ahead until **`finalize_volatile()`** promotes depth (reorg / finality tests).

Parent hash for slot `> 0` is **`hash_domain(DOMAIN_MOCK_KASPA_BLOCK, [prev_slot_le, genesis, tick_le])`**, so changing **tick** or **slot** changes the hash seen by rollup context.

QRNG value is **`hash_domain(DOMAIN_MOCK_QRNG, [epoch_le, genesis])`**.

**`is_block_finalized`**: true for genesis hash **or** current **`parent_block_hash_prev()`** (narrow mock policy).

## Wire types (`src/types/mod.rs`)

- **`L2Transaction`**: `id` (32 B), `proof` (opaque bytes — batcher decodes **`SparseMerkleProof`**), `payload`.
- **`Batch`**: ordered `Vec<L2Transaction>`.
- **`SmtRoot`**: newtype around `[u8; 32]`.
- **`StorageLease`**: lease id, user, provider, rent, user leaf key, due pulse, active/slashed flags — carried in **`RollupState`** (`src/chain/rollup.rs`).

## `RollupState`

Holds **`StateMirrorTree`**, **`BTreeMap` of leases**, **`pulse_height`**, **`recent_roots`** (`VecDeque` of SMT roots). **`root()`** delegates to **`smt.root()`**.

## Related

* **Seeds & digest:** `qssm-utils` — `RollupContext`, `rollup_context_digest`, `mssq_seed_k`.
* **Batcher:** `mssq-batcher` re-exports `RollupState` and `rollup_context_from_l1`.
