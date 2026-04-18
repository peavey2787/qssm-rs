//! # QSSM ZK API
//!
//! Stable SDK for zero-knowledge predicate proofs.
//! This crate is a **pure façade** — all logic lives in dedicated modules.
//!
//! ## Quick start
//!
//! ```no_run
//! use zk_api::{ProofContext, prove, verify};
//! use template_lib::QssmTemplate;
//! use serde_json::json;
//!
//! let ctx = ProofContext::new([0u8; 32]);
//! let template = QssmTemplate::proof_of_age("age-21");
//! let claim = json!({ "claim": { "age_years": 25 } });
//! let binding_ctx = [0u8; 32];
//! let entropy_seed = [1u8; 32]; // from device sensor / harvester
//!
//! let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx, entropy_seed).unwrap();
//! assert!(verify(&ctx, &template, &claim, &proof, binding_ctx).unwrap());
//! ```

mod context;
pub mod error;
mod entropy;
mod prove;
mod verify;
pub mod wire;

// ── Core types ───────────────────────────────────────────────────────
pub use context::{Proof, ProofContext};
pub use error::ZkError;
pub use wire::{ProofBundle, SovereignProofBundle, WireFormatError, PROTOCOL_VERSION};

// ── SDK entry points ─────────────────────────────────────────────────
pub use prove::prove;
pub use verify::verify;

// ── Entropy harvest ──────────────────────────────────────────────────
pub use entropy::{
    harvest, harvest_entropy_seed, harvest_entropy_seed_with_config,
    HarvestConfig, Heartbeat, HeError, SensorEntropy,
};

// ── Template re-export ───────────────────────────────────────────────
pub use template_lib;

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_utils::hashing::blake3_hash;
    use serde_json::json;

    fn test_seed() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-SEED")
    }

    fn test_entropy() -> [u8; 32] {
        blake3_hash(b"QSSM-SDK-TEST-ENTROPY")
    }

    #[test]
    fn prove_and_verify_round_trip() {
        let ctx = ProofContext::new(test_seed());
        let template = template_lib::QssmTemplate::proof_of_age("test-age");
        let claim = json!({ "claim": { "age_years": 25 } });
        let binding_ctx = blake3_hash(b"test-binding-context");

        let proof = prove(&ctx, &template, &claim, 100, 50, binding_ctx, test_entropy())
            .expect("prove should succeed");
        let ok = verify(&ctx, &template, &claim, &proof, binding_ctx)
            .expect("verify should succeed");
        assert!(ok);
    }
}
