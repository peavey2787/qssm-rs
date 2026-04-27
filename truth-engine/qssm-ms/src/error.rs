use qssm_utils::MerkleError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MsError {
    #[error("no valid rotation found within nonce range (0..=255)")]
    NoValidRotation,
    #[error("invalid proof field: {0}")]
    InvalidProofField(&'static str),
    #[error("invalid predicate-only v2 commitment field: {0}")]
    InvalidV2CommitmentField(&'static str),
    #[error("invalid predicate-only v2 proof field: {0}")]
    InvalidV2ProofField(&'static str),
    #[error("predicate-only v2 witness does not satisfy the statement relation")]
    UnsatisfiedPredicateRelation,
    #[error("predicate-only v2 simulator transcript is missing a programmed oracle query")]
    MissingProgrammedOracleQuery,
    #[error(transparent)]
    Merkle(#[from] MerkleError),
}
