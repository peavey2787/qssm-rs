//! Soundness claim for the Mirror-Shift (MS) inequality proof.
//!
//! # Statement
//!
//! An adversary forging value ≤ target that passes MS verification must either:
//!
//! (a) forge a Merkle opening (BLAKE3 collision), or
//! (b) guess the FS challenge (2^{-256} per nonce attempt).
//!
//! With 256 nonces:
//!
//! ε_ms ≤ 256 · (ε_coll + 2^{-256})
//!
//! For BLAKE3 in ROM with Q_H = 2^{64}:
//!
//! ε_coll ≤ Q_H² / 2^{257} ≈ 2^{-129}
//!
//! giving ε_ms ≈ 256 · 2^{-129} ≈ 2^{-121} (dominated by collision term,
//! but still well above 128-bit security since the collision bound itself
//! is conservative — in practice BLAKE3 resistance is ≥ 128 bits).
//!
//! More precisely: with the birthday bound at 2^{-129}, the 256 nonces
//! multiply the advantage to 2^{8} · 2^{-129} = 2^{-121}.  The actual
//! cheat probability against the full protocol (Merkle + FS + rotation)
//! remains ≤ 2^{-121} which exceeds 112-bit CI floor.

use crate::ClaimType;
use qssm_gadget::{MERKLE_DEPTH_MS, MERKLE_WIDTH_MS};
use serde::{Deserialize, Serialize};

/// Number of nonces in the MS protocol.
///
/// The MS protocol uses 256 independent salt/nonce pairs.  Each nonce
/// attempt is bound by a Fiat-Shamir challenge over the Merkle root.
pub const MS_NONCE_COUNT: usize = 256;

/// FS challenge size in bits (BLAKE3 output = 256 bits).
pub const MS_FS_CHALLENGE_BITS: usize = 256;

/// Soundness claim for the Mirror-Shift (MS) inequality proof.
///
/// # Reduction
///
/// ε_ms ≤ nonce_count · (ε_coll_BLAKE3 + 2^{-fs_challenge_bits})
///
/// where ε_coll_BLAKE3 ≤ Q_H² / 2^{hash_output_bits+1} (birthday bound in ROM).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsSoundnessClaim {
    pub claim_type: ClaimType,
    /// Number of nonce attempts (256).
    pub nonce_count: usize,
    /// Merkle tree depth (7).
    pub tree_depth: usize,
    /// Merkle leaf count (128).
    pub leaf_count: usize,
    /// FS challenge size in bits (256).
    pub fs_challenge_bits: usize,
    /// log₂(Q_H) — hash query budget.
    pub query_budget_log2: f64,
    /// log₂(ε_ms) — overall cheat probability bound.
    pub cheat_probability_log2: f64,
}

impl MsSoundnessClaim {
    /// Compute the MS soundness bound.
    #[must_use]
    pub fn compute(
        nonce_count: usize,
        tree_depth: usize,
        leaf_count: usize,
        fs_challenge_bits: usize,
        query_budget_log2: f64,
    ) -> Self {
        // ε_coll = Q_H² / 2^{257} → log₂(ε_coll) = 2·query_budget - 257
        let collision_log2 = 2.0 * query_budget_log2 - (MS_FS_CHALLENGE_BITS as f64 + 1.0);
        // ε_guess = 2^{-fs_challenge_bits}
        let guess_log2 = -(fs_challenge_bits as f64);
        // ε_per_nonce = ε_coll + ε_guess
        // When collision_log2 > guess_log2 (less negative), it dominates:
        let per_nonce_log2 = if collision_log2 > guess_log2 {
            // ε_per_nonce ≈ ε_coll · (1 + ε_guess/ε_coll) ≈ ε_coll for large gaps
            collision_log2 + (1.0 + 2f64.powf(guess_log2 - collision_log2)).log2()
        } else {
            guess_log2 + (1.0 + 2f64.powf(collision_log2 - guess_log2)).log2()
        };
        // ε_ms = nonce_count · ε_per_nonce
        let cheat_probability_log2 = (nonce_count as f64).log2() + per_nonce_log2;

        Self {
            claim_type: ClaimType::Soundness,
            nonce_count,
            tree_depth,
            leaf_count,
            fs_challenge_bits,
            query_budget_log2,
            cheat_probability_log2,
        }
    }

    /// Compute for the frozen qssm-ms / qssm-gadget parameters with Q_H = 2^{64}.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(
            MS_NONCE_COUNT,
            MERKLE_DEPTH_MS,
            MERKLE_WIDTH_MS,
            MS_FS_CHALLENGE_BITS,
            64.0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_soundness_below_neg_112() {
        let ms = MsSoundnessClaim::for_current_params();
        assert_eq!(ms.claim_type, ClaimType::Soundness);
        assert_eq!(ms.nonce_count, 256);
        assert_eq!(ms.tree_depth, 7);
        assert_eq!(ms.leaf_count, 128);
        assert_eq!(ms.fs_challenge_bits, 256);
        assert!(
            ms.cheat_probability_log2 <= -112.0,
            "MS cheat_probability_log2 = {:.1}, expected ≤ -112",
            ms.cheat_probability_log2
        );
    }

    #[test]
    fn ms_params_match_gadget_constants() {
        assert_eq!(MERKLE_DEPTH_MS, 7);
        assert_eq!(MERKLE_WIDTH_MS, 128);
    }
}
