//! Core types: verification/proving context and proof artifact bundle.

use qssm_le::{Commitment, LatticeProof, VerifyingKey};
use qssm_ms::GhostMirrorProof;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Verification / proving context seeded from a 32-byte key.
///
/// The seed is key-schedule material and is scrubbed from memory on drop
/// via [`ZeroizeOnDrop`]. `Clone` is intentionally omitted to prevent
/// accidental copies of secret material.
// SECURITY-CONCESSION: `vk` is a public CRS derived deterministically from
// the seed — it does not need zeroization, so we skip it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProofContext {
    #[zeroize(skip)]
    pub(crate) vk: VerifyingKey,
    seed: [u8; 32],
}

impl std::fmt::Debug for ProofContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofContext")
            .field("vk", &self.vk)
            .field("seed", &"[REDACTED]")
            .finish()
    }
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

    /// The verifying key derived from this context's seed.
    #[must_use]
    pub fn vk(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// Bundle of all proof artifacts needed for verification.
///
/// Verifier recomputes the truth digest and LE public instance from the
/// MS transcript — the cross-engine binding is enforced, not trusted.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Proof {
    /// Ghost-Mirror inequality proof.
    pub(crate) ms_root: [u8; 32],
    pub(crate) ms_proof: GhostMirrorProof,
    /// Lattice proof over the truth digest.
    pub(crate) le_commitment: Commitment,
    pub(crate) le_proof: LatticeProof,
    /// External entropy produced at prove-time (verifier needs this to
    /// recompute the digest; cannot be derived independently).
    pub(crate) external_entropy: [u8; 32],
    /// Whether external entropy beacon was included.
    pub(crate) external_entropy_included: bool,
    /// MS inputs needed for verification.
    pub(crate) value: u64,
    pub(crate) target: u64,
    pub(crate) binding_entropy: [u8; 32],
}

impl Proof {
    /// Construct a proof from all constituent artifacts.
    ///
    /// This is the only way to build a [`Proof`] from outside `qssm-api`.
    /// The [`qssm-local-prover`] crate uses this; application code should
    /// call `qssm_local_prover::prove` instead.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ms_root: [u8; 32],
        ms_proof: GhostMirrorProof,
        le_commitment: Commitment,
        le_proof: LatticeProof,
        external_entropy: [u8; 32],
        external_entropy_included: bool,
        value: u64,
        target: u64,
        binding_entropy: [u8; 32],
    ) -> Self {
        Self {
            ms_root,
            ms_proof,
            le_commitment,
            le_proof,
            external_entropy,
            external_entropy_included,
            value,
            target,
            binding_entropy,
        }
    }

    /// Ghost-Mirror Merkle root.
    #[must_use]
    pub fn ms_root(&self) -> &[u8; 32] { &self.ms_root }
    /// Ghost-Mirror inequality proof.
    #[must_use]
    pub fn ms_proof(&self) -> &GhostMirrorProof { &self.ms_proof }
    /// Lattice commitment.
    #[must_use]
    pub fn le_commitment(&self) -> &Commitment { &self.le_commitment }
    /// Lattice proof.
    #[must_use]
    pub fn le_proof(&self) -> &LatticeProof { &self.le_proof }
    /// External entropy used at prove-time.
    #[must_use]
    pub fn external_entropy(&self) -> &[u8; 32] { &self.external_entropy }
    /// Whether the external entropy beacon was included.
    #[must_use]
    pub fn external_entropy_included(&self) -> bool { self.external_entropy_included }
    /// MS input: claimed value.
    #[must_use]
    pub fn value(&self) -> u64 { self.value }
    /// MS input: claimed target.
    #[must_use]
    pub fn target(&self) -> u64 { self.target }
    /// Binding entropy for cross-engine commitment.
    #[must_use]
    pub fn binding_entropy(&self) -> &[u8; 32] { &self.binding_entropy }
}
