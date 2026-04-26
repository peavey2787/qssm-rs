# ROM Necessity Map

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Purpose

Classify every ROM usage in the QSSM system as **essential** (Fiat-Shamir core — cannot be removed without protocol redesign) or **eliminable** (engineering convenience — could be replaced by standard-model primitives).

## Inventory of All Hash Oracle Call Sites

### MS Component (`qssm-ms/src/v2.rs`)

| Call Site | Function | What It Hashes | ROM Classification |
|-----------|----------|----------------|-------------------|
| Statement digest | `statement_digest()` | commitment digest, target, binding entropy/context | **ELIMINABLE** — This is a deterministic public computation. Any collision-resistant hash works. Does not require programmability. |
| Bitness query digest | `bitness_query_digest()` | statement_digest, bit_index, announce_zero, announce_one | **ESSENTIAL** — The simulator must program this oracle point. The announcement-only input structure is what makes simulation possible. |
| Comparison query digest | `comparison_query_digest()` | statement_digest, clause announcements (loop over clauses) | **ESSENTIAL** — Same as bitness. The simulator programs this to set the comparison challenge. |
| Query-to-scalar | `hash_query_to_scalar()` | query_digest → Scalar | **ESSENTIAL** — Converts programmed query digest to a challenge scalar. Part of the Fiat-Shamir chain. |
| Simulator seed derivation | Various `hash_to_scalar()` calls | simulator_seed + labels | **ELIMINABLE** — These derive simulator coins deterministically. Any PRF works. |
| Real prover alpha sampling | `hash_to_scalar("..._alpha", ...)` | prover_seed + index | **ELIMINABLE** — Deterministic coin generation. Any seeded PRNG works. |

### LE Component (`qssm-le/src/protocol/commit.rs`)

| Call Site | Function | What It Hashes | ROM Classification |
|-----------|----------|----------------|-------------------|
| FS challenge bytes | `fs_challenge_bytes()` | binding_context, vk, public, commitment, t + multiple DSTs | **ESSENTIAL** — The verifier recomputes this. The simulator must program it. Core Fiat-Shamir. |
| Challenge polynomial | `challenge_poly()` | challenge_seed + counter → coefficients | **ESSENTIAL** — Derives the challenge polynomial from the FS output. Part of the FS chain. |
| Prover CSPRNG | `Blake3Rng::new(seed)` | rng_seed → XOF stream for y sampling | **ELIMINABLE** — Deterministic masking. Any seeded CSPRNG works. Not oracle-programmed. |

### Simulator Layer (`qssm-proofs/src/reduction_zk/mod.rs`)

| Call Site | Function | What It Hashes | ROM Classification |
|-----------|----------|----------------|-------------------|
| MS simulator seed | `hash_domain("QSSM-ZK-SIM-v1.0", ["ms_seed", ...])` | simulator_seed, statement_digest | **ELIMINABLE** — Domain-separated seed derivation. Any PRF/KDF works. |
| LE simulator seed | `hash_domain("QSSM-ZK-SIM-v1.0", ["le_seed", ...])` | simulator_seed, binding_context, CRS seed | **ELIMINABLE** — Same. |
| LE simulator commitment | `sample_centered_vec_with_seed()` | simulator coins | **ELIMINABLE** — Deterministic sampling. |
| LE simulator FS program | `le_fs_programmed_query_digest()` | binding_context, vk, public, commitment, t | **ESSENTIAL** — Programs the LE FS oracle point. |

### Utility Layer (`qssm-utils/src/hashing.rs`)

| Call Site | Function | ROM Classification |
|-----------|----------|-------------------|
| `hash_domain()` | Domain-separated Blake3 | **ELIMINABLE as oracle** — Used for domain separation. Needs CR, not programmability. |
| `blake3_hash()` | Raw Blake3 | **ELIMINABLE as oracle** — Generic hash. CR only. |
| Merkle parent | `DOMAIN_MERKLE_PARENT` | **ELIMINABLE** — Merkle tree construction. CR only. |


## Summary Count

| Classification | Count | Where |
|---------------|-------|-------|
| **ESSENTIAL** | 5 | MS bitness query, MS comparison query, MS query-to-scalar, LE fs_challenge_bytes, LE challenge_poly |
| **ELIMINABLE** | 8+ | Statement digest, seed derivation, CSPRNG, Merkle parent, domain separation, alpha sampling |

## Essential ROM Uses — The Structural Core

All essential uses share one pattern: **Fiat-Shamir challenge derivation from announcement-only inputs**.

```
Real:      announcement → hash(announcement) → challenge → response
Simulator: choose (response, challenge) → compute announcement → program hash(announcement) = challenge
```

This reversal IS the ROM. It cannot be replaced by standard-model CR, PRF, or any non-programmable hash property.

## Eliminable ROM Uses — What They Actually Need

- **Collision resistance (CR):** statement digest, Merkle parent, domain separation
- **Pseudorandomness (PRF):** seed derivation, CSPRNG, coin generation

These could be instantiated with any 256-bit CR hash + PRF. No programmability needed.

## ROM Elimination Boundary

```
Minimum ROM footprint: ~66 programmed oracle queries per proof
  - 64 bitness FS queries (one per bit)
  - 1 comparison FS query
  - 1 LE FS query

Everything else is standard-model compatible.
```

The sharpest possible factoring: "ROM-free binding layer (A1)" + "ROM simulation layer (A2 + FS-A4)". MS-3a/3b/3c remain unconditional (algebraic).
