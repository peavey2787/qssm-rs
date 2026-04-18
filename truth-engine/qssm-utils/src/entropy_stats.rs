//! Byte-level entropy quality checks (chi-square vs uniform + simple pattern guards).

#![forbid(unsafe_code)]

const MIN_BYTES_FOR_TEST: usize = 256;
/// Approximate critical value for χ²(df=255) at **p ≈ 0.001** (upper tail); conservative gate.
const CHI2_CRITICAL_P001: f64 = 340.0;
/// Reject if fewer than this many distinct byte values appear (repeating / narrow alphabet).
const MIN_DISTINCT_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum EntropyStatsError {
    TooShort { have: usize, need: usize },
    ChiSquareUniform { statistic: f64, critical: f64 },
    LowDistinctCount { distinct: usize, min: usize },
}

impl std::fmt::Display for EntropyStatsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { have, need } => {
                write!(
                    f,
                    "need at least {need} bytes for entropy stats (have {have})"
                )
            }
            Self::ChiSquareUniform {
                statistic,
                critical,
            } => {
                write!(
                    f,
                    "chi-square vs uniform failed: statistic={statistic:.2} (critical {critical:.2})"
                )
            }
            Self::LowDistinctCount { distinct, min } => {
                write!(
                    f,
                    "too few distinct byte values: {distinct} (minimum {min} for non-degenerate source)"
                )
            }
        }
    }
}

impl std::error::Error for EntropyStatsError {}

/// Pearson χ² test for **256** byte categories vs uniform; also rejects very low **distinct** counts.
///
/// For `len < `[`MIN_BYTES_FOR_TEST`], returns **`Ok(())`** (no gate — avoid false positives on tiny buffers).
#[must_use]
pub fn validate_entropy_distribution(bytes: &[u8]) -> Result<(), EntropyStatsError> {
    if bytes.len() < MIN_BYTES_FOR_TEST {
        return Ok(());
    }

    let mut hist = [0u64; 256];
    for &b in bytes {
        hist[usize::from(b)] += 1;
    }

    let distinct = hist.iter().filter(|&&c| c > 0).count();
    if distinct < MIN_DISTINCT_BYTES {
        return Err(EntropyStatsError::LowDistinctCount {
            distinct,
            min: MIN_DISTINCT_BYTES,
        });
    }

    let n = bytes.len() as f64;
    let exp = n / 256.0;
    let mut chi2 = 0.0_f64;
    for &c in &hist {
        let o = c as f64;
        let diff = o - exp;
        chi2 += (diff * diff) / exp;
    }

    if chi2 > CHI2_CRITICAL_P001 {
        return Err(EntropyStatsError::ChiSquareUniform {
            statistic: chi2,
            critical: CHI2_CRITICAL_P001,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_fails_chi_or_distinct() {
        let v = vec![0u8; 300];
        let r = validate_entropy_distribution(&v);
        assert!(r.is_err());
    }

    #[test]
    fn alternating_two_bytes_fails_distinct() {
        let v: Vec<u8> = (0..300).map(|i| if i % 2 == 0 { 0 } else { 1 }).collect();
        let r = validate_entropy_distribution(&v);
        assert!(matches!(r, Err(EntropyStatsError::LowDistinctCount { .. })));
    }

    #[test]
    fn short_slice_skipped() {
        assert!(validate_entropy_distribution(&[1, 2, 3]).is_ok());
    }
}
