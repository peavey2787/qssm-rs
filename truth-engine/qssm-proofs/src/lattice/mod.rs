#[path = "../reduction_lattice.rs"]
pub mod core;

#[path = "../reduction_rejection.rs"]
pub mod rejection;

pub mod external_validation;
#[path = "../reduction_witness_hiding.rs"]
pub mod witness_hiding;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("lattice error: {0}")]
    Domain(String),
    #[error(transparent)]
    Shared(#[from] crate::shared::errors::Error),
}
