use qssm_utils::MerkleError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MsError {
    #[error("no valid rotation found within nonce range (0..=255)")]
    NoValidRotation,
    #[error("invalid proof field: {0}")]
    InvalidProofField(&'static str),
    #[error(transparent)]
    Merkle(#[from] MerkleError),
}
