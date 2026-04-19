//! Witness-hiding claim for the LE Σ-protocol.
//!
//! # We do not claim full simulation-based HVZK.
//!
//! Standard Lyubashevsky simulation (\[Lyu12\] Lemma 3.2) requires
//! η ≥ 11·‖cr‖_∞·√(ln(2N/ε)/π).  With ‖cr‖_∞ ≤ 8192 and η = 2048,
//! this requirement is not met (would need η ≈ 483,000).
//!
//! We claim **witness-hiding**: accepted z has ‖z‖_∞ ≤ γ = 4096 while
//! ‖r‖_∞ ≤ β = 8.  The gap ratio γ/β = 512 means r contributes ≤ 0.2%
//! of each coordinate's range.  An adversary observing z gains at most
//! β/(2γ+1) ≈ 2^{−10} bits of information per coefficient about r.
//!
//! - Ref: \[Lyu12\] §3, Lemma 3.2 — simulation requirement
//! - Ref: \[DDLL13\] §3 — bimodal Gaussian framework

use crate::ClaimType;
use qssm_le::{BETA, GAMMA};
use serde::{Deserialize, Serialize};

/// Witness-hiding claim for the LE Σ-protocol (NOT full HVZK).
///
/// The gap ratio γ/β = 512 ensures that the witness polynomial r (with
/// ‖r‖_∞ ≤ 8) is masked by z (with ‖z‖_∞ ≤ 4096).  Each coordinate of
/// z has range 8193 possible values; the witness shifts the distribution
/// by at most 8, giving per-coefficient leakage ≤ β/(2γ+1).
///
/// The `not_claimed` field explicitly lists properties we do NOT claim.
///
/// - Ref: \[Lyu12\] §3, Lemma 3.2 — simulation requirement not met
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
        assert_eq!(wh.gamma, 4096);
        assert_eq!(wh.beta, 8);
        assert!(wh.gap_ratio >= 256.0, "gap ratio {:.1} < 256", wh.gap_ratio);
        // γ/β = 512
        assert!((wh.gap_ratio - 512.0).abs() < 0.01);
    }

    #[test]
    fn per_coeff_leakage_is_small() {
        let wh = WitnessHidingClaim::for_current_params();
        // β/(2γ+1) = 8/8193 ≈ 0.000976 → log2 ≈ −10.0
        assert!(
            wh.per_coeff_leakage_bits < -9.0,
            "per_coeff_leakage_bits = {:.2}, expected < -9",
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
