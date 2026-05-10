pub mod core {
    pub use crate::reduction_lattice::*;
}

pub mod rejection {
    pub use crate::reduction_rejection::*;
}

pub mod external_validation;
pub mod witness_hiding {
    pub use crate::reduction_witness_hiding::*;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("lattice error: {0}")]
    Domain(String),
    #[error(transparent)]
    Shared(#[from] crate::shared::errors::Error),
}
