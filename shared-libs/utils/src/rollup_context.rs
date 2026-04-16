//! Rollup-wide context: binds proofs and leader attestations to finalized L1 + QRNG.
#![forbid(unsafe_code)]

use crate::hashing::{hash_domain, DOMAIN_MSSQ_ROLLUP_CONTEXT};

/// Inputs hashed into every LE/MS challenge and ML-DSA leader message (finalized L1, not volatile tip).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollupContext {
    /// Kaspa finalized block hash (or agreed rollup anchor limb).
    pub finalized_block_hash: [u8; 32],
    pub finalized_blue_score: u64,
    pub qrng_epoch: u64,
    pub qrng_value: [u8; 32],
}

impl RollupContext {
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        rollup_context_digest(self)
    }
}

/// `BLAKE3(DOMAIN ‖ finalized_block_hash ‖ finalized_blue_score ‖ qrng_epoch ‖ qrng_value)`.
#[must_use]
pub fn rollup_context_digest(ctx: &RollupContext) -> [u8; 32] {
    hash_domain(
        DOMAIN_MSSQ_ROLLUP_CONTEXT,
        &[
            ctx.finalized_block_hash.as_slice(),
            &ctx.finalized_blue_score.to_le_bytes(),
            &ctx.qrng_epoch.to_le_bytes(),
            ctx.qrng_value.as_slice(),
        ],
    )
}
