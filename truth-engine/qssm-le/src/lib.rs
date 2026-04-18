//! QSSM-LE: \(R_q = \mathbb{Z}_q[X]/(X^{256}+1)\) with NTT-backed multiply, MLWE commitment
//! \(C = A r + \mu\), and Lyubashevsky-style Fiat–Shamir proofs (**witness-hiding** on the wire).
//!
//! ```
//! use qssm_le::{
//!     commit_mlwe, prove_arithmetic, verify_lattice, PublicInstance, VerifyingKey, Witness,
//!     PUBLIC_DIGEST_COEFFS,
//! };
//! let vk = VerifyingKey::from_seed([9u8; 32]);
//! let public = PublicInstance::digest_coeffs([0u32; PUBLIC_DIGEST_COEFFS]).unwrap();
//! let witness = Witness::new([0i32; qssm_le::N]);
//! let ctx = [7u8; 32];
//! let rng_seed = [42u8; 32]; // deterministic masking seed (from entropy pipeline)
//! let (commitment, proof) = prove_arithmetic(&vk, &public, &witness, &ctx, rng_seed).unwrap();
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
    commit_mlwe, verify_lattice_algebraic, Commitment, CommitmentRandomness,
    LatticeProof, PublicBinding, PublicInstance, Witness,
};
// prove_with_witness is intentionally NOT re-exported. It accepts an arbitrary
// RngCore, which would let external callers inject a weak/biased RNG and defeat
// the rejection sampling security guarantee. Use prove_arithmetic instead.
pub(crate) use protocol::commit::prove_with_witness;
pub use protocol::params::{
    BETA, C_POLY_SIZE, C_POLY_SPAN, ETA, GAMMA, N,
    PUBLIC_DIGEST_COEFFS, PUBLIC_DIGEST_COEFF_MAX, Q,
};
pub use qssm_utils::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION;

/// Witness-free verifier (includes `binding_context` in FS challenge).
pub fn verify_lattice(
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    proof: &LatticeProof,
    binding_context: &[u8; 32],
) -> Result<bool, LeError> {
    verify_lattice_algebraic(vk, public, commitment, proof, binding_context)
}

/// Prove: commit + deterministic Fiat–Shamir proof using a BLAKE3-seeded CSPRNG.
///
/// Given the same `(vk, public, witness, binding_context, rng_seed)`, this
/// function always produces the same `(Commitment, LatticeProof)`.
/// No OS entropy is consumed — the masking vector `y` and rejection loop
/// are driven entirely by the BLAKE3-XOF keyed with `rng_seed`.
///
/// `rng_seed` must come from the sovereign entropy pipeline
/// (`qssm-he::Heartbeat::to_seed()` → domain-separated derivation).
pub fn prove_arithmetic(
    vk: &VerifyingKey,
    public: &PublicInstance,
    witness: &Witness,
    binding_context: &[u8; 32],
    rng_seed: [u8; 32],
) -> Result<(Commitment, LatticeProof), LeError> {
    let commitment = commit_mlwe(vk, public, witness)?;
    let mut rng = Blake3Rng::new(rng_seed);
    let proof = prove_with_witness(
        vk,
        public,
        witness,
        &commitment,
        binding_context,
        &mut rng,
    )?;
    Ok((commitment, proof))
}

/// BLAKE3-keyed XOF as a deterministic CSPRNG (`RngCore`).
///
/// Construction: `BLAKE3-XOF(key = rng_seed)`, streaming output.
/// No OS entropy, no hardware calls — purely deterministic.
//
// SECURITY-CONCESSION: `blake3::OutputReader` is opaque and cannot be
// zeroized on drop. The XOF internal state (derived from rng_seed) may
// persist on the stack after this struct is dropped. Acceptable because:
// (1) rng_seed is a domain-separated derived value, not a master secret,
// (2) Blake3Rng is short-lived (created and consumed within prove_arithmetic),
// (3) the OutputReader holds streaming state, not the original key bytes.
struct Blake3Rng {
    reader: blake3::OutputReader,
}

impl Blake3Rng {
    fn new(seed: [u8; 32]) -> Self {
        let h = blake3::Hasher::new_keyed(&seed);
        Self {
            reader: h.finalize_xof(),
        }
    }
}

impl rand::RngCore for Blake3Rng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.reader.fill(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.reader.fill(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.reader.fill(dest);
        Ok(())
    }
}
