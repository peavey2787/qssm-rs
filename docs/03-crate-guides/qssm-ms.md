### Documentation map

* [README](../../README.md) — Project home
* [Engine B protocol spec](../02-protocol-specs/qssm-ms-engine-b.md)
* [Crates overview](../01-architecture/crates-overview.md)
* **This document** — `qssm-ms`: Ghost-Mirror tree, `GhostMirrorProof`, prove/verify

---

# `qssm-ms` — Mirror-Shift fast path (`GhostMirrorProof`)

Crate: `crates/qssm-ms`. **Forbidden:** `unsafe` code.

## Role

**Ghost-Mirror** succinct inequality proofs: Merkle tree over **128** salted leaves, **ledger-anchored** leaf material, **nonce rotation** to find a crossing bit, and **Fiat–Shamir** binding **`rollup_context_digest`** (same 32-byte rollup context as LE/ML-DSA, from `qssm_utils::RollupContext`).

## Types (`src/lib.rs`)

### `Root` / `Salts`

- **`Root([u8; 32])`**: Merkle root from **`PositionAwareTree`** (`qssm_utils::merkle`) over 128 leaves.
- **`Salts`**: `[[u8; 32]; 128]` — index **`2 * i + b`** binds bit **`b ∈ {0,1}`** at position **`i ∈ [0,63]`**.

### `GhostMirrorProof`

| Field | Meaning |
|--------|---------|
| `n` | Nonce in **`0..=255`** used in `rot_for_nonce`. |
| `k` | Bit index **`0..=63`** — highest bit where rotated values differ. |
| `bit_at_k` | **`((value >> k) & 1)`** — witness bit at `k` for **original** `value`. |
| `opened_salt` | Salt at leaf index **`2*k + bit_at_k`**. |
| `path` | Merkle siblings from leaf to root (**depth 7** for width 128). |
| `challenge` | 32-byte FS output (recomputed in `verify`). |

## Leaf and tree construction

**`ms_leaf(i, bit, salt, ledger)`** = **`hash_domain(DOMAIN_MS, ["leaf", i, bit, salt, ledger])`**.

**`build_leaves(salts, ledger)`**: for `i in 0..64`, `b in 0..=1`, push `ms_leaf(i, b, salts[2*i+b], ledger)` → **128** leaves in order.

**`commit`**: derives salts deterministically from **`seed`**:

```text
salts[2*i+b] = hash_domain(DOMAIN_MS, ["salt", seed, i_le, b])
```

Then builds leaves with **`ledger_entropy`**, returns **`Root`** and **`Salts`**.

## Ledger rotation and nonce search

**`ledger_rotation(ledger_entropy)`**: first **8** bytes of `ledger_entropy` as LE `u64` → **`r`**.

**`rot_for_nonce(r, n)`**: **`hash_domain(DOMAIN_MS, ["rot_nonce", r_le, n])`**, take first **8** bytes as LE `u64` — **full-width** rotation (not `r ⊕ n`; see crate doc comment).

**`prove`** (requires **`value > target`**):

1. Build tree; **`root`** fixed.
2. For each **`n in 0..=255`**:
   - `rot = rot_for_nonce(r, n)`
   - `a_p = value.wrapping_add(rot)`, `b_p = target.wrapping_add(rot)`
   - Require **`a_p > b_p`** (strict crossing after rotation).
   - **`k = highest_differing_bit(a_p, b_p)`** (MSB down; first differing bit).
   - **`bit_at_k`** from **original** `value` at `k`.
   - Leaf index **`2*k + bit_at_k`**; open salt + **`tree.get_proof(leaf_idx)`**.
   - **`challenge = fs_challenge(root, n, k, ledger_entropy, value, target, context, rollup_context_digest)`**.
3. If no nonce works → **`MsError::NoValidRotation`**.

## Fiat–Shamir (`fs_challenge`)

**`hash_domain(DOMAIN_MS, ["fs_v2", root, n, k, ledger_entropy, value_le, target_le, context, rollup_context_digest])`**.

**`context`** is an application-specific byte slice (e.g. demo string **`b"mssq-demo-v1"`** in tests). **`rollup_context_digest`** is the **32-byte** `RollupContext` digest — **anti-replay** across L1 view.

## `verify`

1. Range checks: **`bit_at_k ∈ {0,1}`**, **`k ≤ 63`**, bit consistency with **`value`**.
2. Recompute **`leaf`**, check Merkle path with **`verify_path_to_root`** (width **128**, **`merkle_parent`** from `qssm_utils`).
3. Recompute **`fs_challenge`**; must equal **`proof.challenge`**.
4. Recompute **`rot`**, **`a_p`**, **`b_p`**; require **`a_p > b_p`** and **`highest_differing_bit(a_p, b_p) == Some(k)`**.

## API summary

| Function | Purpose |
|----------|---------|
| `commit(value, seed, ledger_entropy)` | Deterministic salts + root (value unused in salt derivation beyond API symmetry). |
| `prove(value, target, salts, ledger_entropy, context, rollup_context_digest)` | Build **`GhostMirrorProof`** or error. |
| `verify(root, proof, ledger_entropy, value, target, context, rollup_context_digest)` | Boolean. |

## Related

* **Normative hashing / Merkle:** `qssm-utils` — `DOMAIN_MS`, `merkle_parent`, `PositionAwareTree`.
* **Protocol write-up:** [`qssm-ms-engine-b.md`](../02-protocol-specs/qssm-ms-engine-b.md).
