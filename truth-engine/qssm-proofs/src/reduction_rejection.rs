//! Rejection sampling correctness and HVZK non-claim.
//!
//! # Summary
//!
//! Accept if ‖z‖_∞ ≤ γ where z = y + cr.
//!
//! - y ~ Uniform\[-η, η\]^N, ‖r‖_∞ ≤ β = 8
//! - c has C_POLY_SIZE = 48 coefficients in \[-8, 8\]
//!
//! Worst-case ‖cr‖_∞ ≤ C_POLY_SIZE · C_POLY_SPAN · β = 48 · 8 · 8 = 3072.
//!
//! With the committed Set B parameters, γ = η + ‖cr‖_∞ = 199680,
//! so the encoded support-containment rule is met exactly.
//!
//! Standard Lyubashevsky HVZK (\[Lyu12\] Lemma 3.2) requires:
//!
//!   η ≥ 11 · ‖cr‖_∞ · √(ln(2N/ε) / π)
//!
//! For ε = 2^{-128}, N = 256:
//!
//!   η ≥ 11 · 3072 · √(ln(512 · 2^{128}) / π) ≈ 185,786
//!
//! Our committed Set B uses η = 196608, so the encoded HVZK template is met.
//!
//! This does not by itself complete the full LE zero-knowledge proof. It means
//! the concrete eta/gamma/challenge parameters now satisfy the exact template
//! encoded in the formal crate.
//!
//! - Ref: \[Lyu12\] §3, Lemma 3.2 — simulation requirement
//! - Ref: \[DDLL13\] §3.1 — bimodal rejection sampling framework

use crate::ClaimType;
use qssm_le::{BETA, C_POLY_SIZE, C_POLY_SPAN, ETA, GAMMA, N};
use serde::{Deserialize, Serialize};

/// Rejection sampling correctness claim.
///
/// Documents the concrete parameters and checks whether the encoded HVZK
/// template is met under the current parameterization.
///
/// - Ref: \[Lyu12\] §3, Lemma 3.2
/// - Ref: \[DDLL13\] §3.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectionSamplingClaim {
    pub claim_type: ClaimType,
    /// Masking vector bound η.
    pub eta: u32,
    /// Verifier acceptance bound γ.
    pub gamma: u32,
    /// Witness bound β.
    pub beta: u32,
    /// Challenge coefficient span (max |c_i|).
    pub c_poly_span: i32,
    /// Challenge polynomial nonzero coefficient count.
    pub c_poly_size: usize,
    /// Deterministic worst-case ‖cr‖_∞ = C_POLY_SIZE · C_POLY_SPAN · β.
    pub worst_case_cr_inf_norm: u64,
    /// η required for standard Lyubashevsky HVZK with ε = 2^{-128}.
    /// Ref: [Lyu12] Lemma 3.2 — η ≥ 11·‖cr‖_∞·√(ln(2N/ε)/π)
    pub required_eta_for_hvzk: f64,
    /// Estimated abort probability per honest attempt (union bound).
    pub abort_probability_estimate: f64,
}

impl RejectionSamplingClaim {
    /// Compute rejection sampling parameters.
    ///
    /// `security_param_epsilon_log2` is log₂(ε) for the HVZK simulation
    /// statistical distance target (typically −128).
    #[must_use]
    pub fn compute(
        n: usize,
        eta: u32,
        gamma: u32,
        beta: u32,
        c_poly_span: i32,
        c_poly_size: usize,
        security_param_epsilon_log2: f64,
    ) -> Self {
        let worst_case_cr_inf_norm =
            c_poly_size as u64 * c_poly_span.unsigned_abs() as u64 * u64::from(beta);

        // Ref: [Lyu12] Lemma 3.2 — η ≥ 11·‖cr‖_∞·√(ln(2N/ε)/π)
        let epsilon = 2f64.powf(security_param_epsilon_log2);
        let ln_arg = (2.0 * n as f64) / epsilon;
        let required_eta_for_hvzk =
            11.0 * worst_case_cr_inf_norm as f64 * (ln_arg.ln() / std::f64::consts::PI).sqrt();

        // Abort probability estimate (union bound over N coordinates):
        // P[abort] ≤ N · P[|y_i + (cr)_i| > γ]
        // For uniform y_i ∈ [-η, η] and worst-case shift s = ‖cr‖_∞:
        // When s > γ, even y_i = 0 produces |s| > γ → abort certain.
        let s = worst_case_cr_inf_norm as f64;
        let eta_f = f64::from(eta);
        let gamma_f = f64::from(gamma);
        let abort_probability_estimate = if s > gamma_f {
            // Worst-case shift exceeds acceptance bound: abort is certain
            // for the unlucky coordinate(s).
            1.0
        } else if eta_f + s > gamma_f {
            let tail_mass = (eta_f + s - gamma_f) / (2.0 * eta_f + 1.0);
            let per_coord = (2.0 * tail_mass).min(1.0);
            1.0 - (1.0 - per_coord).powi(n as i32)
        } else {
            0.0
        };

        Self {
            claim_type: ClaimType::ZeroKnowledge,
            eta,
            gamma,
            beta,
            c_poly_span,
            c_poly_size,
            worst_case_cr_inf_norm,
            required_eta_for_hvzk,
            abort_probability_estimate,
        }
    }

    /// Compute for the frozen qssm-le parameters with ε = 2^{-128}.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(N, ETA, GAMMA, BETA, C_POLY_SPAN, C_POLY_SIZE, -128.0)
    }

    /// Returns `true` if the current η meets the HVZK requirement.
    #[must_use]
    pub fn meets_hvzk_requirement(&self) -> bool {
        f64::from(self.eta) >= self.required_eta_for_hvzk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_case_cr_norm() {
        let rs = RejectionSamplingClaim::for_current_params();
        // 48 · 8 · 8 = 3072
        assert_eq!(rs.worst_case_cr_inf_norm, 3072);
    }

    #[test]
    fn hvzk_requirement_is_met() {
        let rs = RejectionSamplingClaim::for_current_params();
        assert_eq!(rs.claim_type, ClaimType::ZeroKnowledge);
        assert!(
            rs.required_eta_for_hvzk <= f64::from(rs.eta),
            "required η for HVZK = {:.0}, actual η = {} — HVZK should be met",
            rs.required_eta_for_hvzk,
            rs.eta
        );
        assert!(
            rs.meets_hvzk_requirement(),
            "meets_hvzk_requirement() must return true for current params"
        );
    }

    #[test]
    fn required_eta_in_expected_range() {
        let rs = RejectionSamplingClaim::for_current_params();
        // Expected ≈ 185,786; allow 180,000–190,000
        assert!(
            rs.required_eta_for_hvzk > 180_000.0 && rs.required_eta_for_hvzk < 190_000.0,
            "required_eta_for_hvzk = {:.0}, expected ≈ 185,786",
            rs.required_eta_for_hvzk
        );
    }

    #[test]
    fn abort_probability_is_zero_under_support_containment() {
        let rs = RejectionSamplingClaim::for_current_params();
        assert!(
            rs.abort_probability_estimate.abs() < f64::EPSILON,
            "abort probability should be 0 when γ >= η + ‖cr‖_∞"
        );
    }

    #[test]
    fn params_sync_with_qssm_le() {
        let rs = RejectionSamplingClaim::for_current_params();
        assert_eq!(rs.eta, 196_608);
        assert_eq!(rs.gamma, 199_680);
        assert_eq!(rs.beta, 8);
        assert_eq!(rs.c_poly_span, 8);
        assert_eq!(rs.c_poly_size, 48);
    }
}
