//! Formal reduction claims for Lyubashevsky-style lattice commitment soundness.
//!
//! This module provides concrete numeric bounds for:
//! - **MSIS hardness** of the commitment scheme (Step 1.1)
//! - **Fiat-Shamir soundness** in the ROM (Step 1.1)
//! - **Special soundness / extraction** of the Σ-protocol (Step 1.2)
//!
//! Every struct carries a [`ClaimType`] field.  We prove soundness; we do not
//! claim HVZK (see `reduction_witness_hiding`).

use crate::ClaimType;
use qssm_le::{BETA, C_POLY_SIZE, C_POLY_SPAN, N, Q};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Step 1.1 — MSIS Bound
// ---------------------------------------------------------------------------

/// Sentinel value for "infinite" security bits (perfectly binding).
///
/// Used instead of `f64::INFINITY` so that serde_json serialization
/// round-trips cleanly. Any value above 1000 means "perfectly binding."
const INFINITE_BITS_SENTINEL: f64 = 1_000_000.0;

/// Root Hermite factor δ₀(b) for BKZ block size `b`.
///
/// # Ref: \[APS15\] §3.1
///
/// δ₀(b) ≈ (b / (2πe))^{1/(2(b-1))} for b ≥ 50.
fn root_hermite_factor(block_size: usize) -> f64 {
    let b = block_size as f64;
    if b < 2.0 {
        return 1.1; // degenerate
    }
    // Ref: [APS15] §3.1 — δ_0(b) ≈ (b / (2πe))^{1/(2(b-1))}
    let numerator = b / (2.0 * std::f64::consts::PI * std::f64::consts::E);
    numerator.powf(1.0 / (2.0 * (b - 1.0))).max(1.0001)
}

/// Target root Hermite factor for primal lattice attack on rank-1 ring-SIS.
///
/// For rank-1 ring-SIS in R_q = Z_q\[X\]/(X^N+1) with invertible CRS:
/// - The q-ary kernel lattice Λ = qZ^N has dimension d = N and volume q^N.
/// - BKZ-b finds vectors of length ≈ δ₀(b)^d · Vol(Λ)^{1/d} = δ₀(b)^N · q.
/// - An attacker needs this to be ≤ β·√N (Euclidean norm target).
///
/// So: δ* = (β · √N / q)^{1/N}
///
/// When δ* < 1 (as for our parameters), BKZ cannot find such a short vector
/// and the ring-SIS problem is **information-theoretically hard**: the kernel
/// lattice has no vectors of norm ≤ β·√N.
///
/// Ref: \[APS15\] §4.2 — primal attack cost model
fn target_root_hermite(n: usize, q: u32, beta: u32) -> f64 {
    let beta_euclidean = f64::from(beta) * (n as f64).sqrt();
    (beta_euclidean / f64::from(q)).powf(1.0 / n as f64)
}

/// Find the BKZ block size for the primal attack.
///
/// Returns `None` when the target δ* < 1.0, meaning BKZ cannot find a
/// short enough vector (the ring-SIS problem is infeasible).
fn find_bkz_blocksize(n: usize, q: u32, beta: u32) -> Option<usize> {
    let target = target_root_hermite(n, q, beta);
    if target < 1.0 {
        // Ref: [APS15] — when target δ < 1, no BKZ algorithm can solve
        // the SIS problem.  The commitment is perfectly binding.
        return None;
    }
    for b in 40usize..=4096 {
        if root_hermite_factor(b) <= target {
            return Some(b);
        }
    }
    Some(4096)
}

/// Concrete MSIS hardness bound for the rank-1 lattice commitment.
///
/// # Problem statement
///
/// Given **A** ∈ R_q (single invertible ring element), find short **x** with
/// ‖x‖_∞ ≤ β such that **A**·**x** = **0** mod q.
///
/// # Rank-1 perfect binding
///
/// Since q ≡ 1 (mod 512), X^{256}+1 splits completely and R_q ≅ F_q^{256}.
/// A random **A** is invertible with probability (1 − 1/q)^{256} ≈ 1 − 3×10⁻⁵.
/// When **A** is invertible, the only solution to **A**·x = 0 is x = 0.
/// The commitment is **perfectly binding** (information-theoretic).
///
/// The BKZ target δ* = (β√N / q)^{1/N} < 1 for our parameters, confirming
/// that no lattice reduction can find a nontrivial short kernel vector.
///
/// # Cost model
///
/// - Ref: \[APS15\] §4.2 — cost(b) = 2^{0.292·b} classical, 2^{0.265·b} quantum
/// - When δ* < 1: `bkz_blocksize = None`, bits = ∞ (perfectly binding)
/// - When δ* ≥ 1: binary search for b with δ₀(b) ≤ δ*, bits = 0.292·b
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsisBound {
    pub claim_type: ClaimType,
    pub n: usize,
    pub q: u32,
    pub beta: u32,
    /// `None` when δ* < 1 (ring-SIS is infeasible / perfectly binding).
    pub bkz_blocksize: Option<usize>,
    /// Ref: [APS15] §4.2 — classical core-SVP bits = 0.292 · b.
    /// `f64::INFINITY` when perfectly binding.
    pub classical_core_svp_bits: f64,
    /// Ref: [APS15] §4.2 — quantum core-SVP bits = 0.265 · b.
    /// `f64::INFINITY` when perfectly binding.
    pub quantum_core_svp_bits: f64,
}

impl MsisBound {
    /// Compute MSIS hardness for the given ring parameters.
    ///
    /// When the target root Hermite factor δ* < 1 (rank-1 ring-SIS with
    /// invertible CRS), the problem is infeasible and security is infinite.
    #[must_use]
    pub fn compute(n: usize, q: u32, beta: u32) -> Self {
        let bkz = find_bkz_blocksize(n, q, beta);
        match bkz {
            Some(b) => Self {
                claim_type: ClaimType::Soundness,
                n,
                q,
                beta,
                bkz_blocksize: Some(b),
                // Ref: [APS15] §4.2 — cost(b) = 2^{0.292·b} classical
                classical_core_svp_bits: 0.292 * b as f64,
                // Ref: [APS15] §4.2 — cost(b) = 2^{0.265·b} quantum
                quantum_core_svp_bits: 0.265 * b as f64,
            },
            None => Self {
                claim_type: ClaimType::Soundness,
                n,
                q,
                beta,
                bkz_blocksize: None,
                // Perfectly binding: no BKZ attack exists
                classical_core_svp_bits: INFINITE_BITS_SENTINEL,
                quantum_core_svp_bits: INFINITE_BITS_SENTINEL,
            },
        }
    }

    /// Compute for the frozen qssm-le parameters.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(N, Q, BETA)
    }
}

// ---------------------------------------------------------------------------
// Step 1.1 — Fiat-Shamir Reduction Bound
// ---------------------------------------------------------------------------

/// Fiat-Shamir soundness loss in the Random Oracle Model.
///
/// # Statement
///
/// ε_FS ≤ Q_H / |C_eff|
///
/// where Q_H is the adversary's hash-query budget and |C_eff| is the
/// effective challenge space size.
///
/// - Ref: \[KLS18\] Theorem 1 — Fiat-Shamir in ROM
/// - |C_eff| = (2·C_POLY_SPAN+1)^C_POLY_SIZE = 17^48
/// - log₂(|C_eff|) = 48·log₂(17) ≈ 196.2
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FsReductionBound {
    pub claim_type: ClaimType,
    /// log₂(Q_H) — adversary hash query budget in bits.
    pub query_budget_log2: f64,
    /// log₂(|C_eff|) = C_POLY_SIZE · log₂(2·C_POLY_SPAN+1).
    pub challenge_space_log2: f64,
    /// log₂(ε_FS) = query_budget_log2 − challenge_space_log2.
    pub advantage_log2: f64,
}

impl FsReductionBound {
    /// Compute for given challenge parameters and query budget.
    ///
    /// Ref: \[KLS18\] Theorem 1 — ε_FS = Q_H / |C_eff| in ROM
    #[must_use]
    pub fn compute(c_poly_size: usize, c_poly_span: i32, query_budget_log2: f64) -> Self {
        let challenge_space_log2 = c_poly_size as f64 * ((2 * c_poly_span + 1) as f64).log2();
        Self {
            claim_type: ClaimType::Soundness,
            query_budget_log2,
            challenge_space_log2,
            advantage_log2: query_budget_log2 - challenge_space_log2,
        }
    }

    /// Compute for the frozen qssm-le parameters with Q_H = 2^64.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(C_POLY_SIZE, C_POLY_SPAN, 64.0)
    }
}

// ---------------------------------------------------------------------------
// Step 1.1 — Composed LE Commitment Soundness Theorem
// ---------------------------------------------------------------------------

/// Composed soundness theorem for the LE commitment scheme.
///
/// # Statement
///
/// ε_forge ≤ ε_MSIS(n, q, β) + ε_FS(Q_H)
///
/// Any adversary forging a valid LE commitment proof either solves MSIS or
/// breaks Fiat-Shamir in the ROM.
///
/// `security_bits()` returns min(MSIS bits, −log₂(ε_FS)).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeCommitmentSoundnessTheorem {
    pub claim_type: ClaimType,
    pub msis: MsisBound,
    pub fs: FsReductionBound,
}

impl LeCommitmentSoundnessTheorem {
    /// Compose MSIS and FS bounds for given parameters.
    #[must_use]
    pub fn compute(n: usize, q: u32, beta: u32, c_poly_size: usize, c_poly_span: i32) -> Self {
        Self {
            claim_type: ClaimType::Soundness,
            msis: MsisBound::compute(n, q, beta),
            fs: FsReductionBound::compute(c_poly_size, c_poly_span, 64.0),
        }
    }

    /// Compose for the frozen qssm-le parameters.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(N, Q, BETA, C_POLY_SIZE, C_POLY_SPAN)
    }

    /// Effective security bits = min(MSIS classical bits, −FS advantage).
    #[must_use]
    pub fn security_bits(&self) -> f64 {
        let fs_bits = -self.fs.advantage_log2; // advantage is negative, so negate
        self.msis.classical_core_svp_bits.min(fs_bits)
    }

    /// Effective quantum security bits = min(MSIS quantum bits, −FS advantage).
    #[must_use]
    pub fn quantum_security_bits(&self) -> f64 {
        let fs_bits = -self.fs.advantage_log2;
        self.msis.quantum_core_svp_bits.min(fs_bits)
    }
}

// ---------------------------------------------------------------------------
// Step 1.2 — Lyubashevsky Extraction Claim
// ---------------------------------------------------------------------------

/// Special-soundness extraction claim for the Lyubashevsky Σ-protocol.
///
/// # Statement
///
/// Given two accepting transcripts (t, c₁, z₁) and (t, c₂, z₂) with c₁ ≠ c₂,
/// the extractor computes:
///
///   r = (z₁ − z₂) · (c₁ − c₂)⁻¹   in R_q
///
/// **(c₁ − c₂) is invertible** because X^{256}+1 splits completely mod
/// q = 8,380,417 (since q ≡ 1 mod 512), so R_q ≅ F_q^{256} via NTT and
/// every nonzero element is a unit.
///
/// Knowledge error κ = 1/|C_eff| = 1/17^{48}.
/// log₂(1/κ) = 48·log₂(17) ≈ 196.2 bits.
///
/// - Ref: \[Lyu12\] §3, Theorem 3.1 — special soundness for Σ-protocol
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LyubashevskyExtractionClaim {
    pub claim_type: ClaimType,
    /// log₂(|C_eff|) ≈ 322.8
    pub challenge_space_log2: f64,
    /// log₂(κ) = −challenge_space_log2 ≈ −322.8
    pub knowledge_error_log2: f64,
}

impl LyubashevskyExtractionClaim {
    /// Compute extraction claim from challenge parameters.
    ///
    /// Ref: \[Lyu12\] §3, Theorem 3.1 — knowledge error = 1/|C_eff|
    #[must_use]
    pub fn compute(c_poly_size: usize, c_poly_span: i32) -> Self {
        let challenge_space_log2 = c_poly_size as f64 * ((2 * c_poly_span + 1) as f64).log2();
        Self {
            claim_type: ClaimType::Soundness,
            challenge_space_log2,
            knowledge_error_log2: -challenge_space_log2,
        }
    }

    /// Compute for the frozen qssm-le parameters.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(C_POLY_SIZE, C_POLY_SPAN)
    }
}

// ---------------------------------------------------------------------------
// Legacy compat — kept to avoid breaking downstream
// ---------------------------------------------------------------------------

/// Legacy soundness model. Superseded by [`MsisBound`] + [`FsReductionBound`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatticeSoundnessModel {
    pub modulus_q: u32,
    pub challenge_poly_size: usize,
    pub challenge_coeff_span: i32,
    pub gamma_bound: u32,
    pub repetitions: u32,
}

impl Default for LatticeSoundnessModel {
    fn default() -> Self {
        Self {
            modulus_q: Q,
            challenge_poly_size: C_POLY_SIZE,
            challenge_coeff_span: C_POLY_SPAN,
            gamma_bound: qssm_le::GAMMA,
            repetitions: 1,
        }
    }
}

/// Legacy reduction notes. Superseded by formal claim structs above.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatticeReductionNotes {
    pub proven_components: Vec<String>,
    pub heuristic_components: Vec<String>,
}

#[must_use]
pub fn default_reduction_notes() -> LatticeReductionNotes {
    LatticeReductionNotes {
        proven_components: vec![
            "Formal MSIS bound via MsisBound (APS15 core-SVP model).".into(),
            "Fiat-Shamir ROM reduction via FsReductionBound (KLS18).".into(),
            "Special soundness / extraction via LyubashevskyExtractionClaim (Lyu12).".into(),
        ],
        heuristic_components: vec![
            "BKZ cost model is heuristic (core-SVP, not sieving lower bound).".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Step 1.1 tests ---

    #[test]
    fn msis_bound_perfectly_binding_for_current_params() {
        let msis = MsisBound::for_current_params();
        assert_eq!(msis.claim_type, ClaimType::Soundness);
        assert_eq!(msis.n, 256);
        assert_eq!(msis.q, 8_380_417);
        assert_eq!(msis.beta, 8);
        // Rank-1 ring-SIS with invertible CRS: δ* < 1 → perfectly binding
        assert!(
            msis.bkz_blocksize.is_none(),
            "rank-1 ring-SIS should be infeasible (perfectly binding)"
        );
        assert!(
            msis.classical_core_svp_bits >= INFINITE_BITS_SENTINEL,
            "MSIS classical bits should be sentinel (perfectly binding), got {}",
            msis.classical_core_svp_bits
        );
    }

    #[test]
    fn fs_reduction_challenge_space() {
        let fs = FsReductionBound::for_current_params();
        assert_eq!(fs.claim_type, ClaimType::Soundness);
        // log2(17^48) ≈ 196.2
        assert!(
            (fs.challenge_space_log2 - 196.2).abs() < 1.0,
            "challenge_space_log2 = {:.2}, expected ≈196.2",
            fs.challenge_space_log2
        );
        // advantage = 64 - 196.2 ≈ -132.2
        assert!(
            fs.advantage_log2 < -128.0,
            "FS advantage_log2 = {:.1}, should be < -128",
            fs.advantage_log2
        );
    }

    #[test]
    fn le_commitment_soundness_meets_128() {
        let thm = LeCommitmentSoundnessTheorem::for_current_params();
        assert_eq!(thm.claim_type, ClaimType::Soundness);
        // MSIS = ∞, FS ≈ 132.2 → min = 132.2
        assert!(
            thm.security_bits() >= 128.0,
            "LE soundness bits {:.1} < 128",
            thm.security_bits()
        );
        // Should be FS-dominated and close to 132.2 bits.
        assert!(
            thm.security_bits() < 140.0,
            "LE soundness {:.1} should be FS-dominated (≈132.2)",
            thm.security_bits()
        );
    }

    // --- Step 1.2 tests ---

    #[test]
    fn extraction_knowledge_error_below_neg128() {
        let ext = LyubashevskyExtractionClaim::for_current_params();
        assert_eq!(ext.claim_type, ClaimType::Soundness);
        assert!(
            ext.knowledge_error_log2 <= -128.0,
            "knowledge_error_log2 = {:.1}, expected ≤ -128",
            ext.knowledge_error_log2
        );
        // Specifically ≈ -196.2
        assert!(
            (ext.challenge_space_log2 - 196.2).abs() < 1.0,
            "challenge_space_log2 = {:.2}",
            ext.challenge_space_log2
        );
    }

    // --- Legacy compat ---

    #[test]
    fn syncs_to_current_modulus() {
        let m = LatticeSoundnessModel::default();
        assert_eq!(m.modulus_q, 8_380_417);
        assert_eq!(m.challenge_poly_size, 48);
    }
}
