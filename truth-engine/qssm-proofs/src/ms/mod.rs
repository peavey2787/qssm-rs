#[path = "../reduction_blake3.rs"]
pub mod blake3;

#[path = "../reduction_ms.rs"]
pub mod soundness;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ms error: {0}")]
    Domain(String),
    #[error(transparent)]
    Shared(#[from] crate::shared::errors::Error),
}
