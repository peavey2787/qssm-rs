//! Formal BLAKE3 binding reduction for cross-engine proof integrity.
//!
//! # Statement
//!
//! Any adversary producing a mismatched LE/MS pair that passes cross-engine
//! verification implies a BLAKE3 collision under domain separation.
//!
//! Engine A transcript domain tags:
//! - `DOMAIN_LE_FS` = "QSSM-LE-FS-LYU-v1.0"
//! - `DST_LE_COMMIT` = "QSSM-LE-V1-COMMIT..............."
//! - `DST_MS_VERIFY` = "QSSM-MS-V1-VERIFY..............."
//! - `CROSS_PROTOCOL_BINDING_LABEL` = "cross_protocol_digest_v1"
//!
//! Engine B FS domain tags:
//! - `DOMAIN_MS` = "QSSM-MS-v1.0"
//! - sub-label "fs_v2"
//! - Merkle root + binding_context
//!
//! ε_bind ≤ Q_H² / 2^{257}  (birthday bound on 256-bit BLAKE3 in ROM)
//!
//! - Ref: birthday bound on 256-bit hash
//! - Ref: BLAKE3 spec §2.5 — domain separation

use crate::ClaimType;
use serde::{Deserialize, Serialize};

/// Legacy adversary goal enum — kept for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Blake3AdversaryGoal {
    CollisionOnMerkleParentDomain,
    CollisionOnCrossProtocolDigest,
    ReplayEngineBTranscriptIntoEngineAContext,
}

/// Legacy adversary model — kept for backward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3AdversaryModel {
    pub goal: Blake3AdversaryGoal,
    pub query_budget: u64,
    pub adaptive_context_queries: bool,
    pub cross_engine_replay_capability: bool,
}

/// Legacy scaffold claim — kept for backward compatibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Blake3ReductionClaim {
    pub statement: String,
    pub advantage_upper_bound: f64,
    pub notes: String,
}

#[must_use]
pub fn default_collision_claim() -> Blake3ReductionClaim {
    Blake3ReductionClaim {
        statement: "Any forged Merkle/cross-protocol digest implies a BLAKE3 collision under domain-separated inputs.".into(),
        advantage_upper_bound: 2f64.powi(-128),
        notes: "Superseded by Blake3BindingReduction formal claim.".into(),
    }
}

// ---------------------------------------------------------------------------
// Formal binding reduction (Step 2.2)
// ---------------------------------------------------------------------------

/// Formal BLAKE3 cross-engine binding reduction.
///
/// # Reduction
///
/// Any adversary producing a mismatched LE/MS pair that passes cross-engine
/// verification must find a BLAKE3 collision across domain-separated inputs.
///
/// `advantage_log2()` = 2 · query_budget_log2 − (hash_output_bits + 1)
///
/// This is the birthday bound in the Random Oracle Model.
///
/// - Ref: birthday bound on 256-bit hash; domain separation per BLAKE3 spec §2.5
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Blake3BindingReduction {
    pub claim_type: ClaimType,
    /// Domain tags used by Engine A (LE) in its FS transcript.
    pub engine_a_domain_tags: Vec<String>,
    /// Domain tags used by Engine B (MS) in its FS transcript.
    pub engine_b_domain_tags: Vec<String>,
    /// BLAKE3 output size in bits (256).
    pub hash_output_bits: usize,
    /// log₂(ε_bind) = 2·query_budget_log2 − (hash_output_bits + 1).
    pub advantage_log2: f64,
    /// log₂(Q_H) — adversary hash query budget.
    pub query_budget_log2: f64,
}

impl Blake3BindingReduction {
    /// Compute the binding reduction for given parameters.
    #[must_use]
    pub fn compute(hash_output_bits: usize, query_budget_log2: f64) -> Self {
        // Ref: birthday bound — ε ≤ Q_H² / 2^{hash_bits+1}
        let advantage_log2 = 2.0 * query_budget_log2 - (hash_output_bits as f64 + 1.0);
        Self {
            claim_type: ClaimType::Binding,
            engine_a_domain_tags: vec![
                "QSSM-LE-FS-LYU-v1.0".to_string(),
                "QSSM-LE-V1-COMMIT...............".to_string(),
                "QSSM-MS-V1-VERIFY...............".to_string(),
                "cross_protocol_digest_v1".to_string(),
            ],
            engine_b_domain_tags: vec!["QSSM-MS-v1.0".to_string(), "fs_v2".to_string()],
            hash_output_bits,
            advantage_log2,
            query_budget_log2,
        }
    }

    /// Compute for 256-bit BLAKE3 with Q_H = 2^{64}.
    #[must_use]
    pub fn for_current_params() -> Self {
        Self::compute(256, 64.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_advantage_below_neg128() {
        let b = Blake3BindingReduction::for_current_params();
        assert_eq!(b.claim_type, ClaimType::Binding);
        assert_eq!(b.hash_output_bits, 256);
        // 2·64 − 257 = −129
        assert!(
            b.advantage_log2 <= -128.0,
            "advantage_log2 = {:.1}, expected ≤ -128",
            b.advantage_log2
        );
    }

    #[test]
    fn domain_tags_are_non_empty() {
        let b = Blake3BindingReduction::for_current_params();
        assert!(!b.engine_a_domain_tags.is_empty());
        assert!(!b.engine_b_domain_tags.is_empty());
        assert!(b
            .engine_a_domain_tags
            .contains(&"QSSM-LE-FS-LYU-v1.0".to_string()));
        assert!(b.engine_b_domain_tags.contains(&"QSSM-MS-v1.0".to_string()));
    }

    // Legacy compat
    #[test]
    fn legacy_default_collision_claim() {
        let c = default_collision_claim();
        assert!(c.advantage_upper_bound < 1e-30);
    }
}
