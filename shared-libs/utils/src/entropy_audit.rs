//! Unified entropy audit: hardware-style density screen + χ² / distinct-byte stats.

#![forbid(unsafe_code)]

use thiserror::Error;

use crate::entropy_density::verify_density;
use crate::entropy_stats::{validate_entropy_distribution, EntropyStatsError};

/// Failure from the combined [`validate_entropy_full`] gate (density heuristics + distribution test).
#[derive(Debug, Clone, PartialEq, Error)]
pub enum EntropyAuditError {
    #[error("hardware-style density screen failed (too short or pathological pattern)")]
    DensityHeuristic,
    #[error(transparent)]
    Stats(#[from] EntropyStatsError),
}

/// Density screen (≥ [`crate::MIN_RAW_BYTES`]) then Pearson χ² vs uniform when the sample is long enough.
///
/// Short slices fail at the density step; for ≥256 bytes, both density and [`validate_entropy_distribution`] apply.
pub fn validate_entropy_full(bytes: &[u8]) -> Result<(), EntropyAuditError> {
    if !verify_density(bytes) {
        return Err(EntropyAuditError::DensityHeuristic);
    }
    validate_entropy_distribution(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_fails_density() {
        assert!(matches!(
            validate_entropy_full(&[1u8; 64]),
            Err(EntropyAuditError::DensityHeuristic)
        ));
    }

    #[test]
    fn zeros_fail() {
        let v = vec![0u8; 300];
        assert!(validate_entropy_full(&v).is_err());
    }

    #[test]
    fn uniform_random_passes_smoke() {
        let v: Vec<u8> = (0u32..400)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
            .collect();
        assert!(validate_entropy_full(&v).is_ok());
    }
}
