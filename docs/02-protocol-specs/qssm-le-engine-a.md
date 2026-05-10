# QSSM-LE (Engine A) Spec

Rust implementation is authoritative. This spec mirrors current code in `truth-engine/qssm-le`.

## Parameters (Single Source of Truth)

Set B numeric parameters come from:
- `truth-engine/qssm-le/src/protocol/params.rs`

Fiat-Shamir/domain constants for Engine A live in:
- `truth-engine/qssm-le/src/protocol/commit.rs`

Current Set B values:
- `N = 256`
- `Q = 8_380_417`
- `BETA = 8`
- `ETA = 196_608`
- `GAMMA = 199_680`
- `C_POLY_SIZE = 48`
- `C_POLY_SPAN = 8`
- `MAX_PROVER_ATTEMPTS = 65_536`
- `PUBLIC_DIGEST_COEFFS = 64`
- `PUBLIC_DIGEST_COEFF_MAX = 0x0f`

No duplicate constants should be introduced in docs or dependent crates.

## Public/Secret Types

### Public Input

`PublicInstance` currently supports:
- `PublicBinding::DigestCoeffVector { coeffs: [u32; PUBLIC_DIGEST_COEFFS] }`

Constructors:
- `PublicInstance::digest_coeffs(...)` (validated path)
- `PublicInstance::from_u64_nibbles(...)` (migration helper)

### Secret Input

`Witness { r: [i32; N] }` with `|r_i| <= BETA`.

## Commitment and Proof

Commitment:
- `C = A*r + mu(public)` in `R_q`, where `A` is derived from `VerifyingKey::matrix_a_poly()`.

Proof object (`LatticeProof`) fields:
- `t: RqPoly`
- `z: RqPoly`
- `challenge_seed: [u8; 32]`

Wire-relevant encoding:
- `encode_rq_coeffs_le` for coefficient serialization.

## Fiat-Shamir Inputs (Explicit)

Boundary note:
- Real prover/verifier Fiat-Shamir for Engine A is `qssm-le::protocol::commit::fs_challenge_bytes`.
- `qssm-proofs` simulator oracle plumbing uses `DOMAIN_ZK_SIM` plus simulator labels for theorem-model construction.
- This separation is theorem-model plumbing only; it is not a protocol logic change to Engine A verifier behavior.

Engine A FS challenge bytes are defined by `fs_challenge_bytes` and hash, in order:
1. `DOMAIN_LE_FS` (`"QSSM-LE-FS-LYU-v1.0"`)
2. `DST_LE_COMMIT`
3. `DST_MS_VERIFY`
4. `CROSS_PROTOCOL_BINDING_LABEL`
5. `DOMAIN_MS` bytes
6. literal tag `"fs_v2"`
7. `binding_context`
8. `vk.crs_seed`
9. `public_binding_fs_bytes(public)`
10. `encode_rq_coeffs_le(commitment.0)`
11. `encode_rq_coeffs_le(t)`

Challenge polynomial expansion:
- `challenge_poly(seed)` using `DOMAIN_LE_CHALLENGE_POLY`
- coefficient count: `C_POLY_SIZE`
- coefficient span: `[-C_POLY_SPAN, C_POLY_SPAN]`

## Prover and Verifier Flows

Prover (`prove_arithmetic`):
1. `commit_mlwe`
2. deterministic RNG from `rng_seed` (`Blake3Rng`)
3. sample `y` with `|y_i| <= ETA`
4. derive FS challenge seed and challenge polynomial
5. compute `z = y + c*r`
6. reject until `||z||_inf <= GAMMA` (bounded by `MAX_PROVER_ATTEMPTS`)

Verifier (`verify_lattice` / `verify_lattice_algebraic`):
1. validate public input and canonical coefficients
2. norm check `||z||_inf <= GAMMA`
3. recompute FS challenge seed
4. expand challenge polynomial
5. check ring equation `A*z == t + c*(C - mu)`

## Transcript Fields (Explicit)

Visible LE transcript for proof verification:
- commitment `C`
- proof `t`
- proof `z`
- proof `challenge_seed`

No witness coefficients are transmitted.

## Bridge Interface Alignment (Engine B -> Engine A)

Bridge/handshake fields in gadget layer:
- `EngineAPublicJson` keys (canonical order):
  - `message_limb_u30`
  - `digest_coeff_vector_u4`
- `TRANSCRIPT_MAP_LAYOUT_VERSION` must equal `qssm_utils::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`.

Seam binding (`EngineABindingInput`) includes:
- `state_root`
- `ms_v2_statement_digest`
- `ms_v2_result_bit`
- `ms_v2_bitness_global_challenges_digest`
- `ms_v2_comparison_global_challenge`
- `ms_v2_transcript_digest`
- `binding_context`
- `device_entropy_link`
- `truth_digest`
- `entropy_anchor`
- `claimed_seam_commitment`
- `require_ms_verified`

This is enforced in `qssm-gadget` and must stay synchronized with LE public binding byte layout.

## Code Mapping

- LE params and constants:
  - `truth-engine/qssm-le/src/protocol/params.rs`
- LE commitment/proof core:
  - `truth-engine/qssm-le/src/protocol/commit.rs`
- LE API surface:
  - `truth-engine/qssm-le/src/lib.rs`
- Ring encoding and arithmetic:
  - `truth-engine/qssm-le/src/algebra/ring.rs`
- CRS expansion:
  - `truth-engine/qssm-le/src/crs.rs`
- Bridge handshake and transcript map alignment:
  - `truth-engine/qssm-gadget/src/circuit/handshake.rs`
  - `truth-engine/qssm-gadget/src/circuit/operators/engine_a_binding.rs`
  - `truth-engine/qssm-gadget/src/lattice/lattice_bridge.rs`
