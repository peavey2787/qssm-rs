//! Reduction scaffolding for Lyubashevsky-style soundness accounting.

use qssm_le::{C_POLY_SIZE, C_POLY_SPAN, GAMMA, Q};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatticeSoundnessModel {
    pub modulus_q: u32,
    pub challenge_poly_size: usize,
    pub challenge_coeff_span: i32,
    pub gamma_bound: u32,
    /// Optional repetition/amplification count.
    pub repetitions: u32,
}

impl Default for LatticeSoundnessModel {
    fn default() -> Self {
        Self {
            modulus_q: Q,
            challenge_poly_size: C_POLY_SIZE,
            challenge_coeff_span: C_POLY_SPAN,
            gamma_bound: GAMMA,
            repetitions: 1,
        }
    }
}

impl LatticeSoundnessModel {
    #[must_use]
    pub fn challenge_space_size(&self) -> u32 {
        ((2 * self.challenge_coeff_span + 1) as u32).saturating_pow(self.challenge_poly_size as u32)
    }

    /// Heuristic per-run soundness proxy from the scalar challenge space.
    #[must_use]
    pub fn single_run_soundness_error(&self) -> f64 {
        1.0 / f64::from(self.challenge_space_size())
    }

    /// Heuristic repetition-amplified soundness proxy.
    #[must_use]
    pub fn amplified_soundness_error(&self) -> f64 {
        self.single_run_soundness_error()
            .powi(self.repetitions as i32)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatticeReductionNotes {
    pub proven_components: Vec<String>,
    pub heuristic_components: Vec<String>,
}

#[must_use]
pub fn default_reduction_notes() -> LatticeReductionNotes {
    LatticeReductionNotes {
        proven_components: vec![
            "Verifier enforces z infinity norm bound and transcript recomputation.".into(),
            "Public parameter synchronization uses qssm-le constants directly.".into(),
        ],
        heuristic_components: vec![
            "Concrete 128-bit security claim requires external estimator-backed analysis.".into(),
            "Challenge-space-only proxy is not a full proof of knowledge/soundness bound.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syncs_to_current_modulus() {
        let m = LatticeSoundnessModel::default();
        assert_eq!(m.modulus_q, 8_380_417);
        assert_eq!(m.challenge_poly_size, 64);
        assert!(m.single_run_soundness_error() > 0.0);
    }
}
