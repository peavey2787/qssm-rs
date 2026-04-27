pub mod blake3 {
    pub use crate::reduction_blake3::*;
}

pub mod soundness {
    pub use crate::reduction_ms::*;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ms error: {0}")]
    Domain(String),
    #[error(transparent)]
    Shared(#[from] crate::shared::errors::Error),
}
