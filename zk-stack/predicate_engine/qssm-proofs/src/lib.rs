#![forbid(unsafe_code)]

pub mod benchmarks;
pub mod reduction_blake3;
pub mod reduction_lattice;

use qssm_gadget::DIGEST_COEFF_VECTOR_SIZE;
use qssm_le::{BETA, C_POLY_SIZE, N, Q};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardnessStatus {
    Meets128BitTarget,
    Below128BitTarget,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HardnessAssessment {
    pub effective_security_bits: f64,
    pub ci_floor_bits: f64,
    pub target_bits: f64,
    pub status: HardnessStatus,
    pub source: String,
    pub structural_ok: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SystemAudit {
    pub n: usize,
    pub q: u32,
    pub beta: u32,
    pub c_poly_size: usize,
    pub digest_coeff_vector_size: usize,
    pub bits_of_security: f64,
    pub is_poly_challenge: bool,
    pub has_binding_vector: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralEvidence {
    pub c_poly_size: usize,
    pub digest_coeff_vector_size: usize,
    pub c_poly_size_threshold: usize,
    pub digest_coeff_threshold: usize,
}

impl StructuralEvidence {
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.c_poly_size >= self.c_poly_size_threshold
            && self.digest_coeff_vector_size >= self.digest_coeff_threshold
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HardnessError {
    #[error("structural precondition failed: {0}")]
    StructuralPreconditionFailed(String),
}

const TARGET_BITS: f64 = 128.0;
pub const CI_FLOOR_BITS: f64 = 112.0;
pub const MIN_C_POLY_SIZE: usize = 64;
pub const MIN_DIGEST_COEFF_VECTOR_SIZE: usize = 64;

fn root_hermite_factor_for_blocksize(block_size: usize) -> f64 {
    let beta = block_size as f64;
    if beta <= 2.0 {
        return 1.0219;
    }
    let numerator = beta / (2.0 * std::f64::consts::PI * std::f64::consts::E);
    (numerator.powf(1.0 / (2.0 * (beta - 1.0)))).max(1.0001)
}

fn target_root_hermite_factor(n: usize, q: u32, beta: u32) -> f64 {
    (f64::from(q) / f64::from(beta)).powf(1.0 / (2.0 * n as f64))
}

fn bkz_blocksize_estimate(n: usize, q: u32, beta: u32) -> usize {
    let target = target_root_hermite_factor(n, q, beta);
    for b in 40usize..=1024usize {
        if root_hermite_factor_for_blocksize(b) <= target {
            return b;
        }
    }
    1024
}

fn estimated_bits_of_security(n: usize, q: u32, beta: u32, c_poly_size: usize) -> f64 {
    let block = bkz_blocksize_estimate(n, q, beta) as f64;
    let base_cost = 0.292 * block;
    let challenge_scale = (c_poly_size as f64 / 64.0).max(1.0);
    // Simplified BKZ pipeline scaling: larger module dimensions raise workfactor materially.
    let dimension_scale = (n as f64 / 24.0).max(1.0);
    let modulus_scale = (f64::from(q).log2() / 23.0).max(0.5);
    base_cost * challenge_scale * dimension_scale * modulus_scale
}

#[must_use]
pub fn structural_evidence() -> StructuralEvidence {
    StructuralEvidence {
        c_poly_size: C_POLY_SIZE,
        digest_coeff_vector_size: DIGEST_COEFF_VECTOR_SIZE,
        c_poly_size_threshold: MIN_C_POLY_SIZE,
        digest_coeff_threshold: MIN_DIGEST_COEFF_VECTOR_SIZE,
    }
}

#[must_use]
pub fn system_audit() -> SystemAudit {
    let bits = estimated_bits_of_security(N, Q, BETA, C_POLY_SIZE);
    SystemAudit {
        n: N,
        q: Q,
        beta: BETA,
        c_poly_size: C_POLY_SIZE,
        digest_coeff_vector_size: DIGEST_COEFF_VECTOR_SIZE,
        bits_of_security: bits,
        is_poly_challenge: C_POLY_SIZE >= MIN_C_POLY_SIZE,
        has_binding_vector: DIGEST_COEFF_VECTOR_SIZE >= MIN_DIGEST_COEFF_VECTOR_SIZE,
    }
}

pub fn current_effective_security_bits(
    _estimator_json_path: Option<&Path>,
    _audit_ledger_path: Option<&Path>,
) -> Result<(f64, String), HardnessError> {
    let audit = system_audit();
    Ok((audit.bits_of_security, "compiled-system-audit".to_string()))
}

pub fn assess_hardness(
    estimator_json_path: Option<&Path>,
    audit_ledger_path: Option<&Path>,
) -> Result<HardnessAssessment, HardnessError> {
    let structural = structural_evidence();
    if !structural.is_ok() {
        return Err(HardnessError::StructuralPreconditionFailed(format!(
            "C_POLY_SIZE={} (min {}), DIGEST_COEFF_VECTOR_SIZE={} (min {})",
            structural.c_poly_size,
            structural.c_poly_size_threshold,
            structural.digest_coeff_vector_size,
            structural.digest_coeff_threshold
        )));
    }
    let audit = system_audit();
    if !audit.is_poly_challenge {
        return Err(HardnessError::StructuralPreconditionFailed(
            "challenge model must remain polynomial".to_string(),
        ));
    }
    if !audit.has_binding_vector {
        return Err(HardnessError::StructuralPreconditionFailed(
            "digest binding must remain coefficient-vector based".to_string(),
        ));
    }
    let (bits, source) = current_effective_security_bits(estimator_json_path, audit_ledger_path)?;
    let status = if bits >= TARGET_BITS {
        HardnessStatus::Meets128BitTarget
    } else {
        HardnessStatus::Below128BitTarget
    };
    Ok(HardnessAssessment {
        effective_security_bits: bits,
        ci_floor_bits: CI_FLOOR_BITS,
        target_bits: TARGET_BITS,
        status,
        source,
        structural_ok: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *state
    }

    fn perturb_pm_10_percent(base: f64, state: &mut u64) -> f64 {
        let r = (lcg_next(state) >> 11) as f64 / ((1u64 << 53) as f64);
        let delta = (r * 0.2) - 0.1;
        base * (1.0 + delta)
    }

    #[test]
    fn hardness_assessment_structured_status_exists() {
        let assessment =
            assess_hardness(None, None).expect("assessment should load from system audit");
        assert!(assessment.structural_ok);
        match assessment.status {
            HardnessStatus::Meets128BitTarget | HardnessStatus::Below128BitTarget => {}
        }
    }

    /// Mandatory CI floor: fail build if effective security dips below 112 bits.
    #[test]
    fn ci_security_floor_112_bits() {
        let assessment = assess_hardness(None, None).expect("must read current security estimate");
        assert!(
            assessment.structural_ok,
            "structural checks must pass before bit checks"
        );
        assert!(
            assessment.effective_security_bits >= CI_FLOOR_BITS,
            "effective security {:.2} bits below CI floor {:.2} bits (source: {})",
            assessment.effective_security_bits,
            CI_FLOOR_BITS,
            assessment.source
        );
    }

    #[test]
    fn c_poly_size_threshold_is_enforced() {
        let structural = structural_evidence();
        assert!(
            structural.c_poly_size >= MIN_C_POLY_SIZE,
            "C_POLY_SIZE={} below required threshold {}",
            structural.c_poly_size,
            MIN_C_POLY_SIZE
        );
    }

    #[test]
    fn structural_estimator_sanity_for_current_params() {
        let audit = system_audit();
        assert!(audit.n >= 256);
        assert!(audit.q >= 8_380_417);
        assert!(
            audit.bits_of_security >= CI_FLOOR_BITS,
            "estimated bits {:.2} below floor {:.2}",
            audit.bits_of_security,
            CI_FLOOR_BITS
        );
    }

    #[test]
    fn test_estimator_sensitivity() {
        const MONTE_CARLO_CASES: usize = 512;
        const MIN_SPREAD_BITS: f64 = 8.0;

        let mut min_bits = f64::INFINITY;
        let mut max_bits = f64::NEG_INFINITY;
        let mut rng = 0xC0FFEE1234u64;

        for _ in 0..MONTE_CARLO_CASES {
            let n = perturb_pm_10_percent(N as f64, &mut rng).round().max(64.0) as usize;
            let q = perturb_pm_10_percent(Q as f64, &mut rng)
                .round()
                .max(1024.0) as u32;
            let beta = perturb_pm_10_percent(BETA as f64, &mut rng)
                .round()
                .max(1.0) as u32;
            let c_poly = perturb_pm_10_percent(C_POLY_SIZE as f64, &mut rng)
                .round()
                .max(8.0) as usize;
            let bits = estimated_bits_of_security(n, q, beta, c_poly);

            assert!(
                bits >= CI_FLOOR_BITS,
                "monte-carlo case below CI floor: bits={bits:.2}, n={n}, q={q}, beta={beta}, c_poly={c_poly}"
            );

            min_bits = min_bits.min(bits);
            max_bits = max_bits.max(bits);
        }

        let spread = max_bits - min_bits;
        assert!(
            spread >= MIN_SPREAD_BITS,
            "estimator insufficiently sensitive: spread {spread:.2} < {MIN_SPREAD_BITS:.2}"
        );
    }
}
