#![forbid(unsafe_code)]

pub mod benchmarks;
pub mod lattice;
pub mod ms;
pub mod shared;
pub mod zk;

use qssm_gadget::DIGEST_COEFF_VECTOR_SIZE;
use qssm_le::{BETA, C_POLY_SIZE, N, Q};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------------------
// Cross-cutting: ClaimType taxonomy
// ---------------------------------------------------------------------------

/// Every `*Claim` / `*Theorem` struct carries this field, making explicit
/// whether the claim is a formal reduction, a bounded-leakage argument,
/// or a heuristic numeric estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimType {
    /// Formal reduction to a named hard problem (MSIS, collision resistance).
    Soundness,
    /// Formal reduction showing cross-engine forgery implies hash collision.
    Binding,
    /// Simulation-based transcript lemma or theorem scaffold for zero-knowledge.
    ZeroKnowledge,
    /// Bounded-leakage argument. Explicitly NOT full HVZK simulation.
    WitnessHiding,
    /// Numeric bound from a cited model; heuristic until backed by external estimator.
    Estimation,
}

// ---------------------------------------------------------------------------
// Cross-cutting: Estimate source taxonomy
// ---------------------------------------------------------------------------

/// Where a security-bit estimate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EstimateSource {
    /// Compiled-in APS15 / formal bound only.
    Formal,
    /// External estimator JSON only (not currently used alone).
    External,
    /// min(formal, external overlay).
    Combined,
}

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
    #[error("I/O error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
}

const TARGET_BITS: f64 = 128.0;
pub const CI_FLOOR_BITS: f64 = 112.0;
pub const MIN_C_POLY_SIZE: usize = 48;
pub const MIN_DIGEST_COEFF_VECTOR_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Phase 2.1 — Formal Security Estimator
// ---------------------------------------------------------------------------

/// Combined security estimate using formal MSIS + FS bounds.
///
/// Delegates to [`reduction_lattice::LeCommitmentSoundnessTheorem`] for the
/// formal classical/quantum bits.  For rank-1 ring-SIS with invertible CRS,
/// MSIS is perfectly binding (∞ bits), so the estimate is FS-dominated.
///
/// Ref: \[APS15\] §4.2 (MSIS), \[KLS18\] Theorem 1 (FS)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEstimate {
    pub claim_type: ClaimType,
    /// Effective classical security bits = min(MSIS classical, −FS advantage).
    pub formal_classical_bits: f64,
    /// Effective quantum security bits = min(MSIS quantum, −FS advantage).
    pub formal_quantum_bits: f64,
    /// External classical overlay (from JSON file, if present).
    pub overlay_classical_bits: Option<f64>,
    /// External quantum overlay (from JSON file, if present).
    pub overlay_quantum_bits: Option<f64>,
    /// Which source(s) drove this estimate.
    pub source: EstimateSource,
    /// Human-readable model description.
    pub model_description: &'static str,
}

impl SecurityEstimate {
    /// Compute from formal MSIS + FS bounds for (n, q, β).
    #[must_use]
    pub fn compute(n: usize, q: u32, beta: u32) -> Self {
        use crate::lattice::core::LeCommitmentSoundnessTheorem;
        let thm =
            LeCommitmentSoundnessTheorem::compute(n, q, beta, C_POLY_SIZE, qssm_le::C_POLY_SPAN);
        Self {
            claim_type: ClaimType::Estimation,
            formal_classical_bits: thm.security_bits(),
            formal_quantum_bits: thm.quantum_security_bits(),
            overlay_classical_bits: None,
            overlay_quantum_bits: None,
            source: EstimateSource::Formal,
            model_description: "min(MSIS-APS15, FS-KLS18): rank-1 ring-SIS + Fiat-Shamir ROM",
        }
    }

    /// Compute for the frozen qssm-le parameters.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(N, Q, BETA)
    }

    /// Effective classical bits = min(formal, overlay if present).
    #[must_use]
    pub fn effective_classical_bits(&self) -> f64 {
        match self.overlay_classical_bits {
            Some(ov) => self.formal_classical_bits.min(ov),
            None => self.formal_classical_bits,
        }
    }

    /// Effective quantum bits = min(formal, overlay if present).
    #[must_use]
    pub fn effective_quantum_bits(&self) -> f64 {
        match self.overlay_quantum_bits {
            Some(ov) => self.formal_quantum_bits.min(ov),
            None => self.formal_quantum_bits,
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 3.2 — Effective Security Bits (formal + overlay)
// ---------------------------------------------------------------------------

/// Combined security-bit result with formal and optional overlay sources.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectiveSecurityBits {
    pub formal_classical_bits: f64,
    pub formal_quantum_bits: f64,
    pub overlay_classical_bits: Option<f64>,
    pub overlay_quantum_bits: Option<f64>,
    /// min(formal_classical, overlay_classical.unwrap_or(formal_classical))
    pub effective_classical_bits: f64,
    /// min(formal_quantum, overlay_quantum.unwrap_or(formal_quantum))
    pub effective_quantum_bits: f64,
    pub source: EstimateSource,
}

/// JSON schema for external estimator overlay file.
#[derive(Debug, Deserialize)]
struct ExternalEstimate {
    classical_bits: f64,
    quantum_bits: f64,
    #[serde(rename = "source")]
    _source: Option<String>,
    #[serde(rename = "date")]
    _date: Option<String>,
}

/// Compute formal security bits for the given lattice parameters.
///
/// Uses the composed `LeCommitmentSoundnessTheorem` (min of MSIS + FS).
fn estimated_bits_of_security(n: usize, q: u32, beta: u32) -> f64 {
    SecurityEstimate::compute(n, q, beta).formal_classical_bits
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
    let bits = estimated_bits_of_security(N, Q, BETA);
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

/// Compute effective security bits, optionally overlaying an external
/// estimator JSON file.
///
/// JSON schema: `{ "classical_bits": f64, "quantum_bits": f64, "source": String, "date": String }`
///
/// Returns `EffectiveSecurityBits` with `effective_*` = min(formal, overlay).
/// Falls back to formal-only when path is `None` or file is missing/malformed.
pub fn compute_effective_security(
    estimator_json_path: Option<&Path>,
) -> Result<EffectiveSecurityBits, HardnessError> {
    let formal = SecurityEstimate::for_current_params();

    let overlay = estimator_json_path.and_then(|p| {
        let data = std::fs::read_to_string(p).ok()?;
        serde_json::from_str::<ExternalEstimate>(&data).ok()
    });

    let (ov_c, ov_q, source) = match &overlay {
        Some(ext) => (
            Some(ext.classical_bits),
            Some(ext.quantum_bits),
            EstimateSource::Combined,
        ),
        None => (None, None, EstimateSource::Formal),
    };

    let eff_c = formal
        .formal_classical_bits
        .min(ov_c.unwrap_or(f64::INFINITY));
    let eff_q = formal
        .formal_quantum_bits
        .min(ov_q.unwrap_or(f64::INFINITY));

    Ok(EffectiveSecurityBits {
        formal_classical_bits: formal.formal_classical_bits,
        formal_quantum_bits: formal.formal_quantum_bits,
        overlay_classical_bits: ov_c,
        overlay_quantum_bits: ov_q,
        effective_classical_bits: eff_c,
        effective_quantum_bits: eff_q,
        source,
    })
}

pub fn current_effective_security_bits(
    estimator_json_path: Option<&Path>,
    _audit_ledger_path: Option<&Path>,
) -> Result<(f64, String), HardnessError> {
    let eff = compute_effective_security(estimator_json_path)?;
    let source = match eff.source {
        EstimateSource::Formal => "formal-aps15".to_string(),
        EstimateSource::External => "external-estimator".to_string(),
        EstimateSource::Combined => "combined-formal+overlay".to_string(),
    };
    Ok((eff.effective_classical_bits, source))
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
        // Security is FS-dominated for rank-1 ring-SIS (perfectly binding).
        // Perturbing lattice parameters (n, q, β) should not drop below
        // CI_FLOOR_BITS because the FS bound is independent of them.
        const MONTE_CARLO_CASES: usize = 512;

        let mut min_bits = f64::INFINITY;
        let mut rng = 0xC0FFEE1234u64;

        for _ in 0..MONTE_CARLO_CASES {
            let n = perturb_pm_10_percent(N as f64, &mut rng).round().max(64.0) as usize;
            let q = perturb_pm_10_percent(Q as f64, &mut rng)
                .round()
                .max(1024.0) as u32;
            let beta = perturb_pm_10_percent(BETA as f64, &mut rng)
                .round()
                .max(1.0) as u32;
            let bits = estimated_bits_of_security(n, q, beta);

            min_bits = min_bits.min(bits);
            assert!(
                bits >= CI_FLOOR_BITS,
                "perturbed params (n={n}, q={q}, β={beta}) gave {bits:.1} bits < CI floor"
            );
        }

        assert!(
            min_bits >= CI_FLOOR_BITS,
            "minimum bits {min_bits:.2} across all perturbations < CI floor {CI_FLOOR_BITS:.2}"
        );
    }

    // --- Phase 2.1 tests ---

    #[test]
    fn security_estimate_for_current_params() {
        let est = SecurityEstimate::for_current_params();
        assert_eq!(est.claim_type, ClaimType::Estimation);
        assert_eq!(est.source, EstimateSource::Formal);
        assert!(
            est.formal_classical_bits >= 128.0,
            "formal classical bits {:.1} < 128",
            est.formal_classical_bits
        );
        assert!(
            est.formal_quantum_bits >= 100.0,
            "formal quantum bits {:.1} < 100",
            est.formal_quantum_bits
        );
        assert!(est.overlay_classical_bits.is_none());
        assert!(est.overlay_quantum_bits.is_none());
        assert!(
            (est.effective_classical_bits() - est.formal_classical_bits).abs() < 0.001,
            "effective should equal formal when no overlay"
        );
    }

    // --- Phase 3.2 tests ---

    #[test]
    fn effective_security_formal_only() {
        let eff = compute_effective_security(None).unwrap();
        assert_eq!(eff.source, EstimateSource::Formal);
        assert!(eff.overlay_classical_bits.is_none());
        assert!((eff.effective_classical_bits - eff.formal_classical_bits).abs() < 0.001);
    }

    #[test]
    fn effective_security_fallback_on_missing_file() {
        let eff = compute_effective_security(Some(Path::new("nonexistent.json"))).unwrap();
        assert_eq!(eff.source, EstimateSource::Formal);
        assert!(eff.overlay_classical_bits.is_none());
    }

    #[test]
    fn effective_security_with_overlay_file() {
        let dir = std::env::temp_dir().join("qssm_proofs_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("overlay.json");
        std::fs::write(
            &path,
            r#"{"classical_bits": 120.0, "quantum_bits": 110.0, "source": "test", "date": "2026-01-01"}"#,
        )
        .unwrap();

        let eff = compute_effective_security(Some(&path)).unwrap();
        assert_eq!(eff.source, EstimateSource::Combined);
        assert_eq!(eff.overlay_classical_bits, Some(120.0));
        assert_eq!(eff.overlay_quantum_bits, Some(110.0));
        // effective = min(formal, overlay)
        assert!(eff.effective_classical_bits <= 120.0);
        assert!(eff.effective_quantum_bits <= 110.0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn effective_security_min_of_logic() {
        // When overlay is higher than formal, formal wins
        let dir = std::env::temp_dir().join("qssm_proofs_test_min");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("high_overlay.json");
        std::fs::write(&path, r#"{"classical_bits": 999.0, "quantum_bits": 999.0}"#).unwrap();

        let eff = compute_effective_security(Some(&path)).unwrap();
        assert_eq!(eff.source, EstimateSource::Combined);
        // formal < 999, so effective = formal
        assert!((eff.effective_classical_bits - eff.formal_classical_bits).abs() < 0.001);

        let _ = std::fs::remove_file(&path);
    }
}


// ---------------------------------------------------------------------------
// Audit-mode feature gate: runs only when `cargo test --features audit-mode`
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "audit-mode"))]
mod audit_mode_tests {
    use crate::zk::core::{run_audit_validation, PROOF_STRUCTURE_VERSION};

    #[test]
    fn audit_mode_validates_simulator_independence_and_lemma_closure() {
        let checklist = run_audit_validation()
            .expect("audit validation must succeed");
        assert!(
            checklist.all_passed,
            "Audit-mode validation failed: not all checklist items passed"
        );
        assert_eq!(checklist.version, PROOF_STRUCTURE_VERSION);
        for item in &checklist.items {
            assert!(
                item.passed,
                "Audit-mode item {} failed: {}",
                item.id, item.detail
            );
        }
    }
}
