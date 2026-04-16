//! QSSM-LE: \(R_q = \mathbb{Z}_q[X]/(X^{256}+1)\) with NTT-backed multiply, MLWE commitment
//! \(C = A r + \mu\), and Lyubashevsky-style Fiat–Shamir proofs (**witness-hiding** on the wire).
//!
//! ```
//! use qssm_le::{
//!     commit_mlwe, prove_arithmetic, verify_lattice, PublicInstance, VerifyingKey, Witness,
//! };
//! let vk = VerifyingKey::from_seed([9u8; 32]);
//! let public = PublicInstance::legacy_message(12345);
//! let witness = Witness { r: [0i32; qssm_le::N] };
//! let ctx = [7u8; 32];
//! let (commitment, proof) = prove_arithmetic(&vk, &public, &witness, &ctx).unwrap();
//! assert!(verify_lattice(&vk, &public, &commitment, &proof, &ctx).unwrap());
//! ```
#![forbid(unsafe_code)]

mod algebra;
mod crs;
mod error;
mod protocol;

pub use algebra::ring::{
    encode_rq_coeffs_le, short_vec_to_rq, short_vec_to_rq_bound, RqPoly, ScrubbedPoly,
};
pub use crs::VerifyingKey;
pub use error::LeError;
pub use protocol::commit::{
    commit_mlwe, prove_with_witness, verify_lattice_algebraic, Commitment, CommitmentRandomness,
    LatticeProof, PublicBinding, PublicInstance, SecretKey, Witness,
};
pub use protocol::params::{
    BETA, C_POLY_SIZE, C_POLY_SPAN, C_SPAN_LEGACY, ETA, GAMMA, MAX_MESSAGE_LEGACY, N,
    PUBLIC_DIGEST_COEFFS, PUBLIC_DIGEST_COEFF_MAX, Q,
};
pub use qssm_utils::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION;

/// Witness-free verifier (includes `rollup_context_digest` in FS challenge).
pub fn verify_lattice(
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    proof: &LatticeProof,
    rollup_context_digest: &[u8; 32],
) -> Result<bool, LeError> {
    verify_lattice_algebraic(vk, public, commitment, proof, rollup_context_digest)
}

/// Prove: commit + FS proof (uses OS RNG for masking / rejection).
pub fn prove_arithmetic(
    vk: &VerifyingKey,
    public: &PublicInstance,
    witness: &Witness,
    rollup_context_digest: &[u8; 32],
) -> Result<(Commitment, LatticeProof), LeError> {
    let commitment = commit_mlwe(vk, public, witness)?;
    let mut rng = rand::thread_rng();
    let proof = prove_with_witness(
        vk,
        public,
        witness,
        &commitment,
        rollup_context_digest,
        &mut rng,
    )?;
    Ok((commitment, proof))
}
