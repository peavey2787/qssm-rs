//! QSSM-LE (Beta): \(R_q = \mathbb{Z}_q[X]/(X^{64}+1)\) with NTT-backed multiply, Module-LWE-style
//! commitment \(C = A r + \mu\), and **witness-free** `verify_lattice`.
//!
//! ```
//! use qssm_le::{
//!     commit_mlwe, prove_with_witness, verify_lattice, PublicInstance, VerifyingKey, Witness,
//! };
//! let vk = VerifyingKey::from_seed([9u8; 32]);
//! let public = PublicInstance { message: 12345 };
//! let witness = Witness { r: [0i32; 64] };
//! let commitment = commit_mlwe(&vk, &public, &witness).unwrap();
//! let proof = prove_with_witness(&vk, &public, &witness, &commitment).unwrap();
//! assert!(verify_lattice(&vk, &public, &commitment, &proof).unwrap());
//! ```
#![forbid(unsafe_code)]

mod commit;
mod crs;
mod error;
mod ntt;
mod params;
mod ring;

pub use commit::{
    commit_mlwe, prove_with_witness, verify_lattice_algebraic, Commitment, LatticeProof, PublicInstance,
    Witness,
};
pub use crs::VerifyingKey;
pub use error::LeError;
pub use params::{BETA, MAX_MESSAGE, N, Q};
pub use ring::RqPoly;

/// Witness-free verifier entry point (LaBRADOR Beta: algebraic + FS binding).
pub fn verify_lattice(
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    proof: &LatticeProof,
) -> Result<bool, LeError> {
    verify_lattice_algebraic(vk, public, commitment, proof)
}

/// Prove: commit + proof bundle (prover holds [`Witness`] secret).
pub fn prove_arithmetic(
    vk: &VerifyingKey,
    public: &PublicInstance,
    witness: &Witness,
) -> Result<(Commitment, LatticeProof), LeError> {
    let commitment = commit_mlwe(vk, public, witness)?;
    let proof = prove_with_witness(vk, public, witness, &commitment)?;
    Ok((commitment, proof))
}
