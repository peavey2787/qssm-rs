//! Core types: verification/proving context and proof artifact bundle.

use qssm_le::{Commitment, LatticeProof, VerifyingKey};
use qssm_ms::GhostMirrorProof;

/// Verification / proving context seeded from a 32-byte key.
#[derive(Debug, Clone)]
pub struct ProofContext {
    pub vk: VerifyingKey,
    seed: [u8; 32],
}

impl ProofContext {
    /// Create a new proof context from a 32-byte seed.
    ///
    /// Both prover and verifier must use the same seed.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            vk: VerifyingKey::from_seed(seed),
            seed,
        }
    }

    /// The seed used to create this context.
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
}

/// Bundle of all proof artifacts needed for verification.
///
/// Verifier recomputes the truth digest and LE public instance from the
/// MS transcript — the cross-engine binding is enforced, not trusted.
#[derive(Debug, Clone)]
pub struct Proof {
    /// Ghost-Mirror inequality proof.
    pub ms_root: [u8; 32],
    pub ms_proof: GhostMirrorProof,
    /// Lattice proof over the truth digest.
    pub le_commitment: Commitment,
    pub le_proof: LatticeProof,
    /// External entropy produced at prove-time (verifier needs this to
    /// recompute the digest; cannot be derived independently).
    pub external_entropy: [u8; 32],
    /// Whether external entropy beacon was included.
    pub external_entropy_included: bool,
    /// MS inputs needed for verification.
    pub value: u64,
    pub target: u64,
    pub binding_entropy: [u8; 32],
}
