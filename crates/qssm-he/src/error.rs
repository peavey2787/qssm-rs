//! Error types for [`crate::HeError`].

use thiserror::Error;

/// Errors from harvesting, density checks, or PMK derivation.
#[derive(Debug, Error)]
pub enum HeError {
    #[error("openentropy: {0}")]
    OpenEntropy(String),
    #[error("accelerometer sample: {0}")]
    Accelerometer(String),
    #[error("argon2: {0}")]
    Argon2(String),
    #[error("harvest produced insufficient raw bytes ({got}, need at least {min})")]
    InsufficientRawBytes { got: usize, min: usize },
    #[error("TSC jitter harvest did not pass density checks after stirring")]
    JitterDensityRejected,
    #[error("raw hardware jitter harvest is not implemented for this target OS/arch")]
    UnsupportedEntropyPlatform,
}
