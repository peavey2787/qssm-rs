use super::internals::{decode_scalar, decompress_point};
use crate::MsError;
use blake3::Hasher;
use curve25519_dalek::scalar::Scalar;
use qssm_utils::{hash_domain, DOMAIN_MS};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const V2_BIT_COUNT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgrammedOracleQueryV2 {
    pub(crate) query_digest: [u8; 32],
    pub(crate) challenge: [u8; 32],
}

impl ProgrammedOracleQueryV2 {
    #[must_use]
    pub fn query_digest(&self) -> &[u8; 32] {
        &self.query_digest
    }

    #[must_use]
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueCommitmentV2 {
    bit_commitments: Vec<[u8; 32]>,
}

impl ValueCommitmentV2 {
    pub fn new(bit_commitments: Vec<[u8; 32]>) -> Result<Self, MsError> {
        if bit_commitments.len() != V2_BIT_COUNT {
            return Err(MsError::InvalidV2CommitmentField(
                "bit_commitments must contain exactly 64 compressed points",
            ));
        }
        for point in &bit_commitments {
            decompress_point(point)?;
        }
        Ok(Self { bit_commitments })
    }

    #[must_use]
    pub fn bit_commitments(&self) -> &[[u8; 32]] {
        &self.bit_commitments
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(DOMAIN_MS.as_bytes());
        hasher.update(b"predicate_only_v2_value_commitment");
        for commitment in &self.bit_commitments {
            hasher.update(commitment);
        }
        *hasher.finalize().as_bytes()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PredicateWitnessV2 {
    pub(crate) value: u64,
    pub(crate) blinders: Vec<[u8; 32]>,
}

impl std::fmt::Debug for PredicateWitnessV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PredicateWitnessV2")
            .field("value", &"[REDACTED]")
            .field("blinders", &format_args!("[{} blinders]", self.blinders.len()))
            .finish()
    }
}

impl PredicateWitnessV2 {
    pub(crate) fn new(value: u64, blinders: Vec<[u8; 32]>) -> Result<Self, MsError> {
        if blinders.len() != V2_BIT_COUNT {
            return Err(MsError::InvalidV2CommitmentField(
                "witness blinders must contain exactly 64 scalars",
            ));
        }
        for scalar in &blinders {
            decode_scalar(scalar)?;
        }
        Ok(Self { value, blinders })
    }

    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn blinder_scalar(&self, index: usize) -> Result<Scalar, MsError> {
        let Some(bytes) = self.blinders.get(index) else {
            return Err(MsError::InvalidV2CommitmentField(
                "witness blinder index out of range",
            ));
        };
        decode_scalar(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateOnlyStatementV2 {
    commitment: ValueCommitmentV2,
    target: u64,
    binding_entropy: [u8; 32],
    binding_context: [u8; 32],
    context: Vec<u8>,
}

impl PredicateOnlyStatementV2 {
    #[must_use]
    pub fn new(
        commitment: ValueCommitmentV2,
        target: u64,
        binding_entropy: [u8; 32],
        binding_context: [u8; 32],
        context: Vec<u8>,
    ) -> Self {
        Self {
            commitment,
            target,
            binding_entropy,
            binding_context,
            context,
        }
    }

    #[must_use]
    pub fn commitment(&self) -> &ValueCommitmentV2 {
        &self.commitment
    }

    #[must_use]
    pub fn target(&self) -> u64 {
        self.target
    }

    #[must_use]
    pub fn binding_entropy(&self) -> &[u8; 32] {
        &self.binding_entropy
    }

    #[must_use]
    pub fn binding_context(&self) -> &[u8; 32] {
        &self.binding_context
    }

    #[must_use]
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    #[must_use]
    pub fn statement_digest(&self) -> [u8; 32] {
        hash_domain(
            DOMAIN_MS,
            &[
                b"predicate_only_v2_statement",
                self.commitment.digest().as_slice(),
                &self.target.to_le_bytes(),
                self.binding_entropy.as_slice(),
                self.binding_context.as_slice(),
                self.context.as_slice(),
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitnessProofV2 {
    pub(crate) announce_zero: [u8; 32],
    pub(crate) announce_one: [u8; 32],
    pub(crate) challenge_zero: [u8; 32],
    pub(crate) challenge_one: [u8; 32],
    pub(crate) response_zero: [u8; 32],
    pub(crate) response_one: [u8; 32],
}

impl BitnessProofV2 {
    pub(crate) fn global_challenge(&self) -> Result<Scalar, MsError> {
        Ok(decode_scalar(&self.challenge_zero)? + decode_scalar(&self.challenge_one)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualitySubproofV2 {
    pub(crate) announcement: [u8; 32],
    pub(crate) response: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonClauseProofV2 {
    pub(crate) challenge_share: [u8; 32],
    pub(crate) subproofs: Vec<EqualitySubproofV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonProofV2 {
    pub(crate) clauses: Vec<ComparisonClauseProofV2>,
}

impl ComparisonProofV2 {
    pub(crate) fn global_challenge(&self) -> Result<Scalar, MsError> {
        self.clauses.iter().try_fold(Scalar::ZERO, |acc, clause| {
            Ok(acc + decode_scalar(&clause.challenge_share)?)
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PredicateOnlyProofV2 {
    pub(crate) result: bool,
    pub(crate) statement_digest: [u8; 32],
    pub(crate) bitness_proofs: Vec<BitnessProofV2>,
    pub(crate) comparison_proof: ComparisonProofV2,
}

impl PredicateOnlyProofV2 {
    #[must_use]
    pub fn result(&self) -> bool {
        self.result
    }

    #[must_use]
    pub fn statement_digest(&self) -> &[u8; 32] {
        &self.statement_digest
    }

    #[must_use]
    pub fn bitness_proofs(&self) -> &[BitnessProofV2] {
        &self.bitness_proofs
    }

    #[must_use]
    pub fn comparison_proof(&self) -> &ComparisonProofV2 {
        &self.comparison_proof
    }

    pub fn bitness_global_challenges(&self) -> Result<Vec<[u8; 32]>, MsError> {
        self.bitness_proofs
            .iter()
            .map(|proof| Ok(proof.global_challenge()?.to_bytes()))
            .collect()
    }

    pub fn comparison_global_challenge(&self) -> Result<[u8; 32], MsError> {
        Ok(self.comparison_proof.global_challenge()?.to_bytes())
    }

    #[must_use]
    pub fn transcript_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(DOMAIN_MS.as_bytes());
        hasher.update(b"predicate_only_v2_proof");
        hasher.update(&self.statement_digest);
        hasher.update(&[u8::from(self.result)]);
        for proof in &self.bitness_proofs {
            hasher.update(&proof.announce_zero);
            hasher.update(&proof.announce_one);
            hasher.update(&proof.challenge_zero);
            hasher.update(&proof.challenge_one);
            hasher.update(&proof.response_zero);
            hasher.update(&proof.response_one);
        }
        for clause in &self.comparison_proof.clauses {
            hasher.update(&clause.challenge_share);
            for subproof in &clause.subproofs {
                hasher.update(&subproof.announcement);
                hasher.update(&subproof.response);
            }
        }
        *hasher.finalize().as_bytes()
    }
}

impl std::fmt::Debug for PredicateOnlyProofV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PredicateOnlyProofV2")
            .field("result", &self.result)
            .field("statement_digest", &self.statement_digest)
            .field("bitness_proof_count", &self.bitness_proofs.len())
            .field("comparison_clause_count", &self.comparison_proof.clauses.len())
            .field("transcript_digest", &self.transcript_digest())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateOnlySimulationV2 {
    pub(crate) proof: PredicateOnlyProofV2,
    pub(crate) programmed_queries: Vec<ProgrammedOracleQueryV2>,
}

impl PredicateOnlySimulationV2 {
    #[must_use]
    pub fn proof(&self) -> &PredicateOnlyProofV2 {
        &self.proof
    }

    #[must_use]
    pub fn programmed_queries(&self) -> &[ProgrammedOracleQueryV2] {
        &self.programmed_queries
    }
}
