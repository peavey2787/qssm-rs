//! First-class parameter sync tests.
//!
//! These integration tests import constants from upstream crates and assert
//! that every formal claim struct uses the correct values.  This is the
//! single guardrail against silent parameter drift.

use qssm_le::{BETA, C_POLY_SIZE, C_POLY_SPAN, ETA, GAMMA, N, Q};

use qssm_proofs::lattice::core::{
    FsReductionBound, LeCommitmentSoundnessTheorem, LyubashevskyExtractionClaim, MsisBound,
};
use qssm_proofs::lattice::external_validation::{
    build_current_le_set_b_validation_artifact, independent_recompute_le_set_b_validation,
    validate_external_report_against_artifact, ExternalLeSetBValidationReport,
    LE_HVZK_VALIDATION_SCHEMA_VERSION,
};
use qssm_proofs::lattice::rejection::RejectionSamplingClaim;
use qssm_proofs::lattice::witness_hiding::WitnessHidingClaim;
use qssm_proofs::ms::blake3::Blake3BindingReduction;
use qssm_proofs::ms::soundness::MsSoundnessClaim;

#[test]
fn upstream_constants_match_expected() {
    assert_eq!(N, qssm_le::N, "N drifted");
    assert_eq!(Q, qssm_le::Q, "Q drifted");
    assert_eq!(BETA, qssm_le::BETA, "BETA drifted");
    assert_eq!(ETA, qssm_le::ETA, "ETA drifted");
    assert_eq!(GAMMA, qssm_le::GAMMA, "GAMMA drifted");
    assert_eq!(C_POLY_SIZE, qssm_le::C_POLY_SIZE, "C_POLY_SIZE drifted");
    assert_eq!(C_POLY_SPAN, qssm_le::C_POLY_SPAN, "C_POLY_SPAN drifted");
}

// ---------------------------------------------------------------------------
// MsisBound
// ---------------------------------------------------------------------------

#[test]
fn msis_bound_params_sync() {
    let msis = MsisBound::for_current_params();
    assert_eq!(msis.n, N);
    assert_eq!(msis.q, Q);
    assert_eq!(msis.beta, BETA);
}

// ---------------------------------------------------------------------------
// FsReductionBound
// ---------------------------------------------------------------------------

#[test]
fn fs_bound_params_sync() {
    let fs = FsReductionBound::for_current_params();
    let expected_challenge_space =
        C_POLY_SIZE as f64 * ((2 * C_POLY_SPAN + 1) as f64).log2();
    assert!(
        (fs.challenge_space_log2 - expected_challenge_space).abs() < 0.001,
        "FS challenge space drifted: got {}, expected {}",
        fs.challenge_space_log2,
        expected_challenge_space
    );
}

// ---------------------------------------------------------------------------
// LeCommitmentSoundnessTheorem
// ---------------------------------------------------------------------------

#[test]
fn le_theorem_params_sync() {
    let thm = LeCommitmentSoundnessTheorem::for_current_params();
    assert_eq!(thm.msis.n, N);
    assert_eq!(thm.msis.q, Q);
    assert_eq!(thm.msis.beta, BETA);
    assert!(
        thm.security_bits() >= 128.0,
        "LE soundness {:.1} < 128",
        thm.security_bits()
    );
}

// ---------------------------------------------------------------------------
// LyubashevskyExtractionClaim
// ---------------------------------------------------------------------------

#[test]
fn extraction_params_sync() {
    let ext = LyubashevskyExtractionClaim::for_current_params();
    let expected_challenge_space =
        C_POLY_SIZE as f64 * ((2 * C_POLY_SPAN + 1) as f64).log2();
    assert!(
        (ext.challenge_space_log2 - expected_challenge_space).abs() < 0.001,
        "extraction challenge space drifted"
    );
}

// ---------------------------------------------------------------------------
// WitnessHidingClaim
// ---------------------------------------------------------------------------

#[test]
fn witness_hiding_params_sync() {
    let wh = WitnessHidingClaim::for_current_params();
    assert_eq!(wh.gamma, GAMMA);
    assert_eq!(wh.beta, BETA);
    assert_eq!(wh.gap_ratio, f64::from(GAMMA) / f64::from(BETA));
}

// ---------------------------------------------------------------------------
// RejectionSamplingClaim
// ---------------------------------------------------------------------------

#[test]
fn rejection_params_sync() {
    let rs = RejectionSamplingClaim::for_current_params();
    assert_eq!(rs.eta, ETA);
    assert_eq!(rs.gamma, GAMMA);
    assert_eq!(rs.beta, BETA);
    assert_eq!(rs.c_poly_span, C_POLY_SPAN);
    assert_eq!(rs.c_poly_size, C_POLY_SIZE);
    assert_eq!(
        rs.worst_case_cr_inf_norm,
        C_POLY_SIZE as u64 * C_POLY_SPAN.unsigned_abs() as u64 * u64::from(BETA)
    );
}

// ---------------------------------------------------------------------------
// Blake3BindingReduction
// ---------------------------------------------------------------------------

#[test]
fn blake3_binding_params_sync() {
    let b3 = Blake3BindingReduction::for_current_params();
    assert_eq!(b3.hash_output_bits, 256);
    assert!(
        b3.advantage_log2 <= -128.0,
        "BLAKE3 advantage {:.1} > -128",
        b3.advantage_log2
    );
}

// ---------------------------------------------------------------------------
// MsSoundnessClaim
// ---------------------------------------------------------------------------

#[test]
fn ms_soundness_params_sync() {
    let ms = MsSoundnessClaim::for_current_params();
    assert_eq!(ms.nonce_count, 256);
    assert_eq!(ms.tree_depth, 7);
    assert_eq!(ms.leaf_count, 128);
    assert!(
        ms.cheat_probability_log2 <= -112.0,
        "MS cheat probability {:.1} > -112",
        ms.cheat_probability_log2
    );
}

// ---------------------------------------------------------------------------
// SecurityEstimate
// ---------------------------------------------------------------------------

#[test]
fn security_estimate_params_sync() {
    let est = qssm_proofs::SecurityEstimate::for_current_params();
    assert!(
        est.formal_classical_bits >= 128.0,
        "formal classical bits {:.1} < 128",
        est.formal_classical_bits
    );
    assert!(
        est.formal_quantum_bits >= 128.0,
        "formal quantum bits {:.1} < 128",
        est.formal_quantum_bits
    );
}

#[test]
fn external_le_set_b_validation_contract_is_consistent() {
    let artifact = build_current_le_set_b_validation_artifact();
    assert_eq!(artifact.schema_version, LE_HVZK_VALIDATION_SCHEMA_VERSION);
    let report = independent_recompute_le_set_b_validation(
        artifact.n,
        artifact.eta,
        artifact.gamma,
        artifact.beta,
        artifact.c_poly_size,
        artifact.c_poly_span,
        artifact.security_param_epsilon_log2,
        artifact.query_budget_log2,
    );
    validate_external_report_against_artifact(&artifact, &report)
        .expect("independent report must validate against artifact");
}

// ---------------------------------------------------------------------------
// Serialization round-trip for all claim structs
// ---------------------------------------------------------------------------

#[test]
fn all_claims_serialize_roundtrip() {
    // MsisBound
    let msis = MsisBound::for_current_params();
    let json = serde_json::to_string(&msis).expect("MsisBound serialize");
    let _: MsisBound = serde_json::from_str(&json).expect("MsisBound deserialize");

    // FsReductionBound
    let fs = FsReductionBound::for_current_params();
    let json = serde_json::to_string(&fs).expect("FsReductionBound serialize");
    let _: FsReductionBound = serde_json::from_str(&json).expect("FsReductionBound deserialize");

    // LeCommitmentSoundnessTheorem
    let thm = LeCommitmentSoundnessTheorem::for_current_params();
    let json = serde_json::to_string(&thm).expect("LeCommitmentSoundnessTheorem serialize");
    let _: LeCommitmentSoundnessTheorem =
        serde_json::from_str(&json).expect("LeCommitmentSoundnessTheorem deserialize");

    // LyubashevskyExtractionClaim
    let ext = LyubashevskyExtractionClaim::for_current_params();
    let json = serde_json::to_string(&ext).expect("LyubashevskyExtractionClaim serialize");
    let _: LyubashevskyExtractionClaim =
        serde_json::from_str(&json).expect("LyubashevskyExtractionClaim deserialize");

    // Blake3BindingReduction
    let b3 = Blake3BindingReduction::for_current_params();
    let json = serde_json::to_string(&b3).expect("Blake3BindingReduction serialize");
    let _: Blake3BindingReduction =
        serde_json::from_str(&json).expect("Blake3BindingReduction deserialize");

    // MsSoundnessClaim
    let ms = MsSoundnessClaim::for_current_params();
    let json = serde_json::to_string(&ms).expect("MsSoundnessClaim serialize");
    let _: MsSoundnessClaim = serde_json::from_str(&json).expect("MsSoundnessClaim deserialize");

    // RejectionSamplingClaim
    let rs = RejectionSamplingClaim::for_current_params();
    let json = serde_json::to_string(&rs).expect("RejectionSamplingClaim serialize");
    let _: RejectionSamplingClaim =
        serde_json::from_str(&json).expect("RejectionSamplingClaim deserialize");

    // WitnessHidingClaim
    let wh = WitnessHidingClaim::for_current_params();
    let json = serde_json::to_string(&wh).expect("WitnessHidingClaim serialize");
    let _: WitnessHidingClaim =
        serde_json::from_str(&json).expect("WitnessHidingClaim deserialize");

    // External LE validation structures
    let artifact = build_current_le_set_b_validation_artifact();
    let json = serde_json::to_string(&artifact).expect("LeSetBValidationArtifact serialize");
    let _: qssm_proofs::lattice::external_validation::LeSetBValidationArtifact =
        serde_json::from_str(&json).expect("LeSetBValidationArtifact deserialize");

    let report = ExternalLeSetBValidationReport {
        schema_version: LE_HVZK_VALIDATION_SCHEMA_VERSION,
        worst_case_cr_inf_norm: artifact.worst_case_cr_inf_norm,
        required_eta_for_hvzk: artifact.required_eta_for_hvzk,
        minimum_gamma_for_support_containment: artifact.minimum_gamma_for_support_containment,
        challenge_space_log2: artifact.challenge_space_log2,
        fs_security_bits: artifact.fs_security_bits,
        abort_probability_estimate: artifact.abort_probability_estimate,
    };
    let json = serde_json::to_string(&report).expect("ExternalLeSetBValidationReport serialize");
    let _: ExternalLeSetBValidationReport =
        serde_json::from_str(&json).expect("ExternalLeSetBValidationReport deserialize");
}
