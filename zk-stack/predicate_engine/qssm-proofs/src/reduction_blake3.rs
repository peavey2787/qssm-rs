//! Reduction scaffolding for BLAKE3-related assumptions in cross-engine binding.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Blake3AdversaryGoal {
    CollisionOnMerkleParentDomain,
    CollisionOnCrossProtocolDigest,
    ReplayEngineBTranscriptIntoEngineAContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3AdversaryModel {
    pub goal: Blake3AdversaryGoal,
    /// Maximum number of random-oracle style queries.
    pub query_budget: u64,
    /// Whether the adversary can adaptively choose transcript context.
    pub adaptive_context_queries: bool,
    /// Whether the adversary controls one engine transcript and attempts replay into the other.
    pub cross_engine_replay_capability: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Blake3ReductionClaim {
    pub statement: String,
    /// Placeholder advantage upper bound (heuristic) for tracking.
    pub advantage_upper_bound: f64,
    pub notes: String,
}

#[must_use]
pub fn default_collision_claim() -> Blake3ReductionClaim {
    Blake3ReductionClaim {
        statement: "Any forged Merkle/cross-protocol digest implies a BLAKE3 collision/preimage-style break under domain-separated inputs.".into(),
        advantage_upper_bound: 2f64.powi(-128),
        notes: "Scaffold value only; replace with audited bound tied to concrete model.".into(),
    }
}
