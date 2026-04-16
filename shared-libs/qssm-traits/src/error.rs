use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("anchor operation failed: {0}")]
    Anchor(&'static str),
}
