#![forbid(unsafe_code)]
//! # QSSM ZK API
//!
//! Stable SDK for zero-knowledge predicate proof **verification**.
//! This crate defines the shared types ([`Proof`], [`ProofContext`], [`ZkError`]),
//! the versioned wire format ([`ProofBundle`]), and the [`verify`] entry point.
//!
//! For **proving**, see the companion crate `qssm-local-prover`.
//!
//! ## Quick start
//!
//! ```no_run
//! use qssm_api::{ProofContext, verify};
//! use qssm_templates::QssmTemplate;
//! use serde_json::json;
//!
//! let ctx = ProofContext::new([0u8; 32]);
//! let template = QssmTemplate::proof_of_age("age-21");
//! let claim = json!({ "claim": { "age_years": 25 } });
//! let binding_ctx = [0u8; 32];
//!
//! // `proof` obtained from qssm_local_prover::prove or deserialized from wire format.
//! // assert!(verify(&ctx, &template, &claim, &proof, binding_ctx).unwrap());
//! ```

mod context;
pub mod error;
mod verify;
pub mod wire;

// ── Shared constants ─────────────────────────────────────────────────
/// MS context tag shared between prove and verify pipelines.
pub const MS_CONTEXT_TAG: &[u8] = b"qssm-sdk-v1";

// ── Core types ───────────────────────────────────────────────────────
pub use context::{Proof, ProofContext};
pub use error::ZkError;
pub use wire::{ProofBundle, WireFormatError, PROTOCOL_VERSION};

// ── SDK entry points ─────────────────────────────────────────────────
pub use verify::verify;

// ── Template re-export ───────────────────────────────────────────────
pub use qssm_templates;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_context_vk_accessor() {
        let seed = qssm_utils::hashing::blake3_hash(b"QSSM-SDK-TEST-SEED");
        let ctx = ProofContext::new(seed);
        let vk_ref = ctx.vk();
        let expected = qssm_le::VerifyingKey::from_seed(seed);
        assert_eq!(vk_ref.crs_seed, expected.crs_seed, "vk accessor must return the correct key");
    }
}