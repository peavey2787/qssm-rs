#[path = "../reduction_zk/mod.rs"]
pub mod core;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("zk error: {0}")]
    Domain(String),
    #[error(transparent)]
    Shared(#[from] crate::shared::errors::Error),
    #[error(transparent)]
    Ms(#[from] crate::ms::Error),
    #[error(transparent)]
    Lattice(#[from] crate::lattice::Error),
}
