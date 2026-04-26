use crate::lattice::rejection::RejectionSamplingClaim;
use qssm_le::{BETA, C_POLY_SIZE, C_POLY_SPAN, ETA, GAMMA, N};
use serde::{Deserialize, Serialize};

pub const LE_HVZK_VALIDATION_SCHEMA_VERSION: u32 = 1;
pub const LE_HVZK_FLOAT_ABS_TOLERANCE: f64 = 5.421_010_862_427_522e-20;
pub const LE_HVZK_QUERY_BUDGET_LOG2: f64 = 64.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeSetBValidationArtifact {
    pub schema_version: u32,
    pub n: usize,
    pub eta: u32,
    pub gamma: u32,
    pub beta: u32,
    pub c_poly_size: usize,
    pub c_poly_span: i32,
    pub security_param_epsilon_log2: f64,
    pub query_budget_log2: f64,
    pub worst_case_cr_inf_norm: u64,
    pub required_eta_for_hvzk: f64,
    pub minimum_gamma_for_support_containment: u64,
    pub challenge_space_log2: f64,
    pub fs_security_bits: f64,
    pub abort_probability_estimate: f64,
    pub meets_hvzk_requirement: bool,
    pub supports_containment: bool,
    pub float_abs_tolerance: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalLeSetBValidationReport {
    pub schema_version: u32,
    pub worst_case_cr_inf_norm: u64,
    pub required_eta_for_hvzk: f64,
    pub minimum_gamma_for_support_containment: u64,
    pub challenge_space_log2: f64,
    pub fs_security_bits: f64,
    pub abort_probability_estimate: f64,
}

#[must_use]
pub fn build_current_le_set_b_validation_artifact() -> LeSetBValidationArtifact {
    let claim = RejectionSamplingClaim::for_current_params();
    let challenge_space_log2 = C_POLY_SIZE as f64 * ((2 * C_POLY_SPAN + 1) as f64).log2();
    let fs_security_bits = challenge_space_log2 - LE_HVZK_QUERY_BUDGET_LOG2;
    let minimum_gamma_for_support_containment =
        u64::from(ETA) + claim.worst_case_cr_inf_norm;
    LeSetBValidationArtifact {
        schema_version: LE_HVZK_VALIDATION_SCHEMA_VERSION,
        n: N,
        eta: ETA,
        gamma: GAMMA,
        beta: BETA,
        c_poly_size: C_POLY_SIZE,
        c_poly_span: C_POLY_SPAN,
        security_param_epsilon_log2: -128.0,
        query_budget_log2: LE_HVZK_QUERY_BUDGET_LOG2,
        worst_case_cr_inf_norm: claim.worst_case_cr_inf_norm,
        required_eta_for_hvzk: claim.required_eta_for_hvzk,
        minimum_gamma_for_support_containment,
        challenge_space_log2,
        fs_security_bits,
        abort_probability_estimate: claim.abort_probability_estimate,
        meets_hvzk_requirement: claim.meets_hvzk_requirement(),
        supports_containment: u64::from(GAMMA) >= minimum_gamma_for_support_containment,
        float_abs_tolerance: LE_HVZK_FLOAT_ABS_TOLERANCE,
    }
}

#[must_use]
pub fn independent_recompute_le_set_b_validation(
    n: usize,
    eta: u32,
    gamma: u32,
    beta: u32,
    c_poly_size: usize,
    c_poly_span: i32,
    security_param_epsilon_log2: f64,
    query_budget_log2: f64,
) -> ExternalLeSetBValidationReport {
    let worst_case_cr_inf_norm =
        c_poly_size as u64 * c_poly_span.unsigned_abs() as u64 * u64::from(beta);
    let epsilon = 2f64.powf(security_param_epsilon_log2);
    let ln_arg = (2.0 * n as f64) / epsilon;
    let required_eta_for_hvzk =
        11.0 * worst_case_cr_inf_norm as f64 * (ln_arg.ln() / std::f64::consts::PI).sqrt();
    let minimum_gamma_for_support_containment = u64::from(eta) + worst_case_cr_inf_norm;
    let challenge_space_log2 = c_poly_size as f64 * ((2 * c_poly_span + 1) as f64).log2();
    let fs_security_bits = challenge_space_log2 - query_budget_log2;
    let s = worst_case_cr_inf_norm as f64;
    let eta_f = f64::from(eta);
    let gamma_f = f64::from(gamma);
    let abort_probability_estimate = if s > gamma_f {
        1.0
    } else if eta_f + s > gamma_f {
        let tail_mass = (eta_f + s - gamma_f) / (2.0 * eta_f + 1.0);
        let per_coord = (2.0 * tail_mass).min(1.0);
        1.0 - (1.0 - per_coord).powi(n as i32)
    } else {
        0.0
    };
    ExternalLeSetBValidationReport {
        schema_version: LE_HVZK_VALIDATION_SCHEMA_VERSION,
        worst_case_cr_inf_norm,
        required_eta_for_hvzk,
        minimum_gamma_for_support_containment,
        challenge_space_log2,
        fs_security_bits,
        abort_probability_estimate,
    }
}

pub fn validate_external_report_against_artifact(
    artifact: &LeSetBValidationArtifact,
    report: &ExternalLeSetBValidationReport,
) -> Result<(), String> {
    if artifact.schema_version != report.schema_version {
        return Err(format!(
            "schema_version mismatch: artifact={}, report={}",
            artifact.schema_version, report.schema_version
        ));
    }
    if artifact.worst_case_cr_inf_norm != report.worst_case_cr_inf_norm {
        return Err("worst_case_cr_inf_norm mismatch".to_string());
    }
    if artifact.minimum_gamma_for_support_containment
        != report.minimum_gamma_for_support_containment
    {
        return Err("minimum_gamma_for_support_containment mismatch".to_string());
    }
    let tol = artifact.float_abs_tolerance;
    let compare = |name: &str, lhs: f64, rhs: f64| -> Result<(), String> {
        if (lhs - rhs).abs() <= tol {
            Ok(())
        } else {
            Err(format!("{name} mismatch: lhs={lhs}, rhs={rhs}, tol={tol}"))
        }
    };
    compare(
        "required_eta_for_hvzk",
        artifact.required_eta_for_hvzk,
        report.required_eta_for_hvzk,
    )?;
    compare(
        "challenge_space_log2",
        artifact.challenge_space_log2,
        report.challenge_space_log2,
    )?;
    compare(
        "fs_security_bits",
        artifact.fs_security_bits,
        report.fs_security_bits,
    )?;
    compare(
        "abort_probability_estimate",
        artifact.abort_probability_estimate,
        report.abort_probability_estimate,
    )?;
    Ok(())
}
