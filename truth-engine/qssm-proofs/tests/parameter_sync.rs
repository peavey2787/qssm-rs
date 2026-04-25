//! First-class parameter sync tests.
//!
//! These integration tests import constants from upstream crates and assert
//! that every formal claim struct uses the correct values.  This is the
//! single guardrail against silent parameter drift.

use qssm_le::{BETA, C_POLY_SIZE, C_POLY_SPAN, ETA, GAMMA, N, Q};

use qssm_proofs::reduction_blake3::Blake3BindingReduction;
use qssm_proofs::reduction_lattice::{
    FsReductionBound, LeCommitmentSoundnessTheorem, LyubashevskyExtractionClaim, MsisBound,
};
use qssm_proofs::reduction_ms::MsSoundnessClaim;
use qssm_proofs::reduction_rejection::RejectionSamplingClaim;
use qssm_proofs::reduction_witness_hiding::WitnessHidingClaim;

// ---------------------------------------------------------------------------
// Canonical LE Set B constants (must match qssm-le exactly)
// ---------------------------------------------------------------------------

const EXPECTED_N: usize = 256;
const EXPECTED_Q: u32 = 8_380_417;
const EXPECTED_BETA: u32 = 8;
const EXPECTED_ETA: u32 = 196_608;
const EXPECTED_GAMMA: u32 = 199_680;
const EXPECTED_C_POLY_SIZE: usize = 48;
const EXPECTED_C_POLY_SPAN: i32 = 8;

#[test]
fn upstream_constants_match_expected() {
    assert_eq!(N, EXPECTED_N, "N drifted");
    assert_eq!(Q, EXPECTED_Q, "Q drifted");
    assert_eq!(BETA, EXPECTED_BETA, "BETA drifted");
    assert_eq!(ETA, EXPECTED_ETA, "ETA drifted");
    assert_eq!(GAMMA, EXPECTED_GAMMA, "GAMMA drifted");
    assert_eq!(C_POLY_SIZE, EXPECTED_C_POLY_SIZE, "C_POLY_SIZE drifted");
    assert_eq!(C_POLY_SPAN, EXPECTED_C_POLY_SPAN, "C_POLY_SPAN drifted");
}

// ---------------------------------------------------------------------------
// MsisBound
// ---------------------------------------------------------------------------

#[test]
fn msis_bound_params_sync() {
    let msis = MsisBound::for_current_params();
    assert_eq!(msis.n, EXPECTED_N);
    assert_eq!(msis.q, EXPECTED_Q);
    assert_eq!(msis.beta, EXPECTED_BETA);
}

// ---------------------------------------------------------------------------
// FsReductionBound
// ---------------------------------------------------------------------------

#[test]
fn fs_bound_params_sync() {
    let fs = FsReductionBound::for_current_params();
    let expected_challenge_space =
        EXPECTED_C_POLY_SIZE as f64 * ((2 * EXPECTED_C_POLY_SPAN + 1) as f64).log2();
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
    assert_eq!(thm.msis.n, EXPECTED_N);
    assert_eq!(thm.msis.q, EXPECTED_Q);
    assert_eq!(thm.msis.beta, EXPECTED_BETA);
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
        EXPECTED_C_POLY_SIZE as f64 * ((2 * EXPECTED_C_POLY_SPAN + 1) as f64).log2();
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
    assert_eq!(wh.gamma, EXPECTED_GAMMA);
    assert_eq!(wh.beta, EXPECTED_BETA);
    assert_eq!(
        wh.gap_ratio,
        f64::from(EXPECTED_GAMMA) / f64::from(EXPECTED_BETA)
    );
}

// ---------------------------------------------------------------------------
// RejectionSamplingClaim
// ---------------------------------------------------------------------------

#[test]
fn rejection_params_sync() {
    let rs = RejectionSamplingClaim::for_current_params();
    assert_eq!(rs.eta, EXPECTED_ETA);
    assert_eq!(rs.gamma, EXPECTED_GAMMA);
    assert_eq!(rs.beta, EXPECTED_BETA);
    assert_eq!(rs.c_poly_span, EXPECTED_C_POLY_SPAN);
    assert_eq!(rs.c_poly_size, EXPECTED_C_POLY_SIZE);
    assert_eq!(
        rs.worst_case_cr_inf_norm,
        EXPECTED_C_POLY_SIZE as u64
            * EXPECTED_C_POLY_SPAN.unsigned_abs() as u64
            * u64::from(EXPECTED_BETA)
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
}
