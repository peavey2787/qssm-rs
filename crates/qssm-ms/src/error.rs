use qssm_utils::MerkleError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MsError {
    #[error("no valid rotation found within nonce range (0..=255)")]
    NoValidRotation,
    #[error(transparent)]
    Merkle(#[from] MerkleError),
}
