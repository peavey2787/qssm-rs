//! Witness-hiding claim for the LE Σ-protocol.
//!
//! # This module records the witness-hiding margin only.
//!
//! The committed LE Set B parameters now satisfy the encoded HVZK template in
//! the formal crate, but this module stays narrower: it records the direct
//! witness-hiding gap between the accepted z-range and the witness bound.
//!
//! With γ = 199680 and β = 8, the gap ratio γ/β = 24960 means r contributes a
//! tiny shift relative to the accepted z range. An adversary observing z gains
//! at most β/(2γ+1) ≈ 2^{-15.6} bits of information per coefficient about r.
//!
//! - Ref: \[Lyu12\] §3, Lemma 3.2 — simulation requirement
//! - Ref: \[DDLL13\] §3 — bimodal Gaussian framework

use crate::ClaimType;
use qssm_le::{BETA, GAMMA};
use serde::{Deserialize, Serialize};

/// Witness-hiding claim for the LE Σ-protocol.
///
/// The gap ratio γ/β = 24960 ensures that the witness polynomial r (with
/// ‖r‖_∞ ≤ 8) is masked by z (with ‖z‖_∞ ≤ 199680). Each coordinate of
/// z has range 399361 possible values; the witness shifts the distribution
/// by at most 8, giving per-coefficient leakage ≤ β/(2γ+1).
///
/// The `not_claimed` field explicitly lists properties we do NOT claim.
///
/// - Ref: \[Lyu12\] §3, Lemma 3.2 — witness-hiding bound used here
/// - Ref: \[DDLL13\] §3.1 — bimodal framework
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessHidingClaim {
    pub claim_type: ClaimType,
    /// Verifier acceptance bound ‖z‖_∞ ≤ γ.
    pub gamma: u32,
    /// Witness bound ‖r‖_∞ ≤ β.
    pub beta: u32,
    /// γ / β — masking gap ratio.
    pub gap_ratio: f64,
    /// Upper bound on per-coefficient information leakage: β / (2γ+1).
    pub per_coeff_leakage_bits: f64,
    /// Properties explicitly NOT claimed by this system.
    pub not_claimed: Vec<String>,
}

impl WitnessHidingClaim {
    /// Construct from γ and β.
    #[must_use]
    pub fn compute(gamma: u32, beta: u32) -> Self {
        let gap_ratio = f64::from(gamma) / f64::from(beta);
        // Leakage per coefficient: β / (2γ + 1)
        let per_coeff_leakage = f64::from(beta) / (2.0 * f64::from(gamma) + 1.0);
        let per_coeff_leakage_bits = per_coeff_leakage.log2();
        Self {
            claim_type: ClaimType::WitnessHiding,
            gamma,
            beta,
            gap_ratio,
            per_coeff_leakage_bits,
            not_claimed: vec!["full HVZK".to_string(), "simulation-based ZK".to_string()],
        }
    }

    /// Construct for the frozen qssm-le parameters.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(GAMMA, BETA)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_hiding_gap_ratio() {
        let wh = WitnessHidingClaim::for_current_params();
        assert_eq!(wh.claim_type, ClaimType::WitnessHiding);
        assert_eq!(wh.gamma, 199_680);
        assert_eq!(wh.beta, 8);
        assert!(
            wh.gap_ratio >= 24_000.0,
            "gap ratio {:.1} < 24000",
            wh.gap_ratio
        );
        // γ/β = 24960
        assert!((wh.gap_ratio - 24_960.0).abs() < 0.01);
    }

    #[test]
    fn per_coeff_leakage_is_small() {
        let wh = WitnessHidingClaim::for_current_params();
        // β/(2γ+1) = 8/399361 ≈ 0.0000200 → log2 ≈ −15.6
        assert!(
            wh.per_coeff_leakage_bits < -15.0,
            "per_coeff_leakage_bits = {:.2}, expected < -15",
            wh.per_coeff_leakage_bits
        );
    }

    #[test]
    fn not_claimed_is_non_empty() {
        let wh = WitnessHidingClaim::for_current_params();
        assert!(
            !wh.not_claimed.is_empty(),
            "not_claimed must list properties we do NOT claim"
        );
        assert!(wh.not_claimed.contains(&"full HVZK".to_string()));
        assert!(wh.not_claimed.contains(&"simulation-based ZK".to_string()));
    }
}
