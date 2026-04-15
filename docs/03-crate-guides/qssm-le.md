### Documentation map

* [README](../../README.md) — Project home
* [Engine A protocol spec](../02-protocol-specs/qssm-le-engine-a.md)
* [Crates overview](../01-architecture/crates-overview.md)
* **This document** — `qssm-le`: NTT, ring, Fiat–Shamir, anti-replay binding

---

# `qssm-le` — Engine A in code (NTT, CRS, rollup digest)

Crate: `crates/qssm-le`. Ring \(R_q = \mathbb{Z}_q[X]/(X^{256}+1)\), **length-512 NTT** negacyclic multiply, MLWE-style commitment, Lyubashevsky-style proofs.

Public API: `lib.rs` re-exports `prove_arithmetic`, `verify_lattice`, `commit_mlwe`, `VerifyingKey`, `PublicInstance`, `Witness`, `Commitment`, `LatticeProof`, constants from `params`, `RqPoly`, etc.

## Parameters (`src/protocol/params.rs`)

| Constant | Value | Meaning |
|----------|--------|---------|
| `N` | **256** | Polynomial degree; coefficients per `RqPoly`. |
| `Q` | **8_380_417** | Prime modulus; **512 \| (q−1)** for length-512 NTT. |
| `BETA` | 8 | \(\ell_\infty\) bound on witness `r` coefficients. |
| `MAX_MESSAGE_LEGACY` | \(2^{30}\) | Legacy single-limb compatibility bound. |
| `PUBLIC_DIGEST_COEFFS` | 64 | Digest coefficient-vector lane count. |
| `ETA`, `GAMMA` | 2048, 4096 | Masking / response norms for rejection and verification. |
| `C_POLY_SIZE` | 64 | Polynomial challenge coefficient count. |
| `C_POLY_SPAN` | 16 | Per-coefficient challenge span \([-16, 16]\). |
| `MAX_PROVER_ATTEMPTS` | 65536 | Rejection sampling loop budget. |

## NTT implementation (`src/algebra/ntt.rs`)

- **Primitive 512th root:** \(\omega = 5^{(q-1)/512} \pmod q\) via `pow_mod`.
- **`ntt_inplace(a: &mut [u32], invert)`**: Cooley–Tukey style butterfly on **power-of-two** length; bit-reverse permutation; iterative stages with `wlen` from \(\omega\). **Inverse** scales by **`n^{-1} \bmod q`** at end.
- **`negacyclic_mul(a, b)`** (`N=256`):
  1. Embed `a`, `b` into **`[u32; 512]`** (upper half zero).
  2. Forward NTT both, **pointwise multiply mod q**, inverse NTT.
  3. **Fold** negacyclic wrap: `out[i] = (fa[i] + Q - fa[i+N]) % Q` for `i < N`.

This is the kernel behind **`RqPoly::mul`** (`src/algebra/ring.rs`).

## Ring (`src/algebra/ring.rs`)

- **`RqPoly([u32; N])`**: add/sub mod `Q`, **`mul` → `ntt::negacyclic_mul`**, scalar multiply, **`embed_constant(message)`** puts `message % Q` in coeff 0.
- **`encode_rq_coeffs_le`**: 1024 bytes, coeffs as LE u32 — feeds Fiat–Shamir hashing.

Short vectors **`short_vec_to_rq` / `short_vec_to_rq_bound`** map signed coeffs into \(\mathbb{Z}_q\) with bounds checks.

## CRS (`src/crs.rs`)

**`VerifyingKey { crs_seed: [u8; 32] }`**. **`matrix_a_poly()`**: row `i` is first 4 bytes of **`hash_domain(DOMAIN_LE, ["A_row", crs_seed, i_le])`**, reduced mod `Q` — transparent **A** in \(R_q\).

## Fiat–Shamir and anti-replay (`src/protocol/commit.rs`)

### Challenge bytes

**Domain string:** `QSSM-LE-FS-LYU-v1.0` (`DOMAIN_LE_FS`).

**`fs_challenge_bytes(rollup_context_digest, vk, public, commitment, t)`** hashes (BLAKE3), in order:

1. Domain  
2. **`rollup_context_digest`** — **32 bytes**, must match **`qssm_utils::rollup_context_digest(&RollupContext)`** for the finalized L1 view the verifier uses  
3. `vk.crs_seed`  
4. `public.binding` bytes (legacy limb or digest coeff-vector encoding)  
5. `encode_rq_coeffs_le(commitment)`  
6. `encode_rq_coeffs_le(t)` (masking commitment)

So proofs are **not** valid across different finalized parents, blue scores, or QRNG limbs — **rollup context digest is the anti-replay limb** for Engine A at the LE layer.

### Polynomial challenge

**`challenge_poly(seed)`** expands transcript seed bytes into `C_POLY_SIZE` coefficients in \([-C_POLY_SPAN, C_POLY_SPAN]\), then maps that vector to an `RqPoly`.

### Prover / verifier

- **`commit_mlwe`**: \(C = A \cdot r + \mu(public\_binding)\) in \(R_q\).
- **`prove_with_witness`**: samples short `y`, sets `t = A y`, computes transcript seed, derives challenge polynomial `c(x)`, then \(z = y + c(x)\cdot r\); rejects if \(\|z\|_\infty > \gamma\), checks \(A z = t + c(x)\cdot(C-\mu)\).
- **`verify_lattice_algebraic`**: recomputes seed, requires seed equality (`challenge_seed`), re-derives `c(x)`, checks same identity and norm bound.

**`verify_lattice`** is the public wrapper calling **`verify_lattice_algebraic`** with **`rollup_context_digest`**.

## Entry points

- **`prove_arithmetic(vk, public, witness, rollup_context_digest)`**: `commit_mlwe` + `prove_with_witness` (OS RNG).
- **`verify_lattice(vk, public, commitment, proof, rollup_context_digest)`**: verifier path.

## Related

* **Normative protocol:** [`qssm-le-engine-a.md`](../02-protocol-specs/qssm-le-engine-a.md).
* **Digest definition:** `qssm-utils` — `RollupContext`, `rollup_context_digest`.
