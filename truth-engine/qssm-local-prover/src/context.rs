//! Core types: verification/proving context and proof artifact bundle.

use qssm_le::{Commitment, LatticeProof, VerifyingKey};
use qssm_ms::{PredicateOnlyProofV2, PredicateOnlyStatementV2};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            vk: VerifyingKey::from_seed(seed),
            seed,
        }
    }

    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    #[must_use]
    pub fn vk(&self) -> &VerifyingKey {
        &self.vk
    }
}

/// Bundle of all proof artifacts needed for verification.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Proof {
    /// MS v2 value-commitment digest (first sovereign limb chunk for LE binding).
    pub(crate) ms_value_commitment_digest: [u8; 32],
    pub(crate) ms_statement: PredicateOnlyStatementV2,
    pub(crate) ms_proof: PredicateOnlyProofV2,
    pub(crate) le_commitment: Commitment,
    pub(crate) le_proof: LatticeProof,
    pub(crate) external_entropy: [u8; 32],
    pub(crate) external_entropy_included: bool,
    /// Public inequality input (not part of the MS statement hash; informational / template).
    pub(crate) value: u64,
}

impl Proof {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ms_value_commitment_digest: [u8; 32],
        ms_statement: PredicateOnlyStatementV2,
        ms_proof: PredicateOnlyProofV2,
        le_commitment: Commitment,
        le_proof: LatticeProof,
        external_entropy: [u8; 32],
        external_entropy_included: bool,
        value: u64,
    ) -> Self {
        Self {
            ms_value_commitment_digest,
            ms_statement,
            ms_proof,
            le_commitment,
            le_proof,
            external_entropy,
            external_entropy_included,
            value,
        }
    }

    /// MS v2 value-commitment digest (same role as the legacy Merkle root in the LE sovereign limb).
    #[must_use]
    pub fn ms_root(&self) -> &[u8; 32] {
        &self.ms_value_commitment_digest
    }

    #[must_use]
    pub fn ms_statement(&self) -> &PredicateOnlyStatementV2 {
        &self.ms_statement
    }

    #[must_use]
    pub fn ms_proof(&self) -> &PredicateOnlyProofV2 {
        &self.ms_proof
    }

    #[must_use]
    pub fn le_commitment(&self) -> &Commitment {
        &self.le_commitment
    }

    #[must_use]
    pub fn le_proof(&self) -> &LatticeProof {
        &self.le_proof
    }

    #[must_use]
    pub fn external_entropy(&self) -> &[u8; 32] {
        &self.external_entropy
    }

    #[must_use]
    pub fn external_entropy_included(&self) -> bool {
        self.external_entropy_included
    }

    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub fn target(&self) -> u64 {
        self.ms_statement.target()
    }

    #[must_use]
    pub fn binding_entropy(&self) -> &[u8; 32] {
        self.ms_statement.binding_entropy()
    }
}
