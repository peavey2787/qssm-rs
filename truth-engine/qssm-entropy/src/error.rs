//! Error types for [`crate::HeError`].

use thiserror::Error;

/// Errors from entropy harvesting.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HeError {
    #[error("accelerometer sample: {0}")]
    Accelerometer(String),
    #[error("harvest produced insufficient raw bytes ({got}, need at least {min})")]
    InsufficientRawBytes { got: usize, min: usize },
    #[error("TSC jitter harvest did not pass density checks after stirring")]
    JitterDensityRejected,
    #[error("raw hardware jitter harvest is not implemented for this target OS/arch")]
    UnsupportedEntropyPlatform,
}
