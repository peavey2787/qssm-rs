# Witness Isolation Threat Model

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Question

Can witness data leak into the simulator path via struct reuse, serialization layers, accidental hash inclusion, or future refactors?

## Witness Types Inventory

### MS Witness: `PredicateWitnessV2`
- **Location:** `qssm-ms/src/v2.rs`
- **Fields:** `value: u64`, `blinders: Vec<[u8; 32]>`
- **Protection:** `#[derive(Zeroize, ZeroizeOnDrop)]`, Debug prints `[REDACTED]`
- **Consumed by:** `prove_predicate_only_v2()` only
- **NOT consumed by:** `simulate_predicate_only_v2()` — simulator takes `(&PredicateOnlyStatementV2, simulator_seed)` only

### LE Witness: `Witness`
- **Location:** `qssm-le/src/protocol/commit.rs`
- **Fields:** `r: [i32; N]`
- **Protection:** `#[derive(Zeroize, ZeroizeOnDrop)]`, Debug prints `[REDACTED]`
- **Consumed by:** `prove_with_witness()` → `prove_arithmetic()` only
- **NOT consumed by:** `verify_lattice_algebraic()`, any simulator path

### LE Intermediate: `ScrubbedPoly`
- **Location:** `qssm-le/src/algebra/ring.rs`
- **Fields:** `coeffs: [u32; N]`
- **Protection:** `#[derive(Zeroize, ZeroizeOnDrop)]`, Debug prints `[REDACTED]`
- **Role:** Wraps witness-derived polynomial operations. Zeroizes intermediates on mul/add.

### LE Masking: `CommitmentRandomness`
- **Location:** `qssm-le/src/protocol/commit.rs`
- **Fields:** `y: [i32; N]`
- **Protection:** `#[derive(Zeroize, ZeroizeOnDrop)]`
- **Role:** Per-attempt prover randomness. Also zeroized.

## Threat 1: Struct Reuse (Witness Type in Simulator Signature)

**Attack:** A refactor accidentally adds a `&Witness` or `&PredicateWitnessV2` parameter to a simulator function.

**Current status: MITIGATED by type separation.**
- `simulate_predicate_only_v2` signature: `(&PredicateOnlyStatementV2, [u8; 32])` — no witness type
- `simulate_le_transcript` signature: `(&LePublicInput, [u8; 32])` — no witness type
- `simulate_qssm_transcript` signature: `(&QssmPublicInput, [u8; 32])` — no witness type

**Residual risk:** MEDIUM. The separation is by function signature convention, not by type system enforcement. A future developer could add a witness parameter. The verification checklist catches this at test time (SIM-INDEPENDENCE check), but not at compile time.

**Hardening opportunity:** Introduce a `SimulatorInput<T>` newtype that statically cannot wrap `Witness` or `PredicateWitnessV2`. This would make witness leakage a type error.

## Threat 2: Serialization Layer Leakage

**Attack:** Witness data serialized to JSON/bytes and accidentally included in a hash input or public output.

**Current status: MITIGATED by non-Serialize witness types.**
- `PredicateWitnessV2`: NOT `Serialize`/`Deserialize`. Only `Zeroize` + custom `Debug`.
- `Witness`: NOT `Serialize`/`Deserialize`. Only `Zeroize` + custom `Debug`.
- `ScrubbedPoly`: NOT `Serialize`/`Deserialize`.

The witness types cannot be accidentally serialized into JSON, transmitted over the wire, or fed to `serde_json::to_string()`.

**Residual risk:** LOW. The `.value` field of `PredicateWitnessV2` is a plain `u64` that could be copied into a `u64` variable and passed elsewhere. Rust's ownership system does not prevent copying primitive types out of a zeroized struct before drop.

## Threat 3: Accidental Hash Inclusion

**Attack:** A hash input (query digest, FS challenge, domain separator) accidentally includes witness material.

**Current MS analysis:**
- `bitness_query_digest()` hashes: `statement_digest, bit_index, announce_zero, announce_one` — NO witness
- `comparison_query_digest()` hashes: `statement_digest, clause announcements` — NO witness
- `statement_digest()` hashes: `commitment.digest(), target, binding_entropy, binding_context, context` — NO witness (commitment is public)

The MS announcement-only contract is enforced by the function signatures of `bitness_query_digest` and `comparison_query_digest`. Neither function accepts a witness parameter.

**Current LE analysis:**
- `fs_challenge_bytes()` hashes: `binding_context, vk, public, commitment, t` — NO witness
- `challenge_poly()` hashes: `seed + counter` — NO witness
- The prover internally computes `z = y + c*r` where `r` is witness. But `z` is the OUTPUT, not the hash INPUT.

**Residual risk:** LOW for current code. The risk is that a future verifier change might hash `z` into the challenge (creating a circular dependency). The announcement-only contract tests in qssm-proofs guard against this.

## Threat 4: Future Refactor Paths

### 4a: Adding debug logging that prints witness values
**Risk:** MITIGATED. Both `PredicateWitnessV2` and `Witness` override `Debug` to print `[REDACTED]`. A `println!("{:?}", witness)` will not leak values.

### 4b: Cloning witness into a non-zeroized container
**Risk:** MEDIUM for LE. `Witness` does not derive `Clone` (only in `#[cfg(test)]`). But `PredicateWitnessV2` derives `Clone` (implicitly through `Zeroize`). A clone of the witness struct is still `ZeroizeOnDrop`, but intermediate copies on the stack may not be zeroized.

### 4c: Passing witness through a generic API boundary
**Risk:** LOW. The witness types are crate-private or have restricted constructors. `prove_with_witness` is `pub(crate)` in qssm-le, with only `prove_arithmetic` as the public entry point.

### 4d: Adding witness to QssmPublicInput or MsHiddenValuePublicInput
**Risk:** CAUGHT AT TEST TIME. The `SIM-INDEPENDENCE` checklist item verifies the simulator's forbidden_inputs list. But this is a runtime string check, not compile-time prevention.

## Threat Summary

| Threat | Status | Risk | Compile-Time? |
|--------|--------|------|---------------|
| Struct reuse in simulator | Mitigated by signature | Medium | NO |
| Serialization leakage | Mitigated by non-Serialize | Low | YES |
| Accidental hash inclusion | Mitigated by fn signatures | Low | Partial |
| Debug logging | Mitigated by [REDACTED] | Low | YES |
| Clone into non-zeroized | Partially mitigated | Medium | NO |
| Generic API boundary | Mitigated by pub(crate) | Low | YES |
| Adding witness to public input | Caught at test time | Medium | NO |

## Recommended Hardening

1. **Type-level simulator input:** `struct SimulatorOnly<T>(T)` that cannot wrap witness types.
2. **Lint or attribute:** Mark witness types with a custom attribute that fails CI if seen in simulator function signatures.
3. **Integration test:** Verify at the qssm_ms crate level that `bitness_query_digest` and `comparison_query_digest` do not accept any parameter of witness type.

None of these are urgent — the current system is correctly isolated. These are defense-in-depth measures against future regression.
