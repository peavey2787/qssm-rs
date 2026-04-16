//! L1 read path (finality-aware) vs batch posting sink (gRPC / mock).
#![forbid(unsafe_code)]

use crate::{Batch, Error};

/// Kaspa (or mock) view used for `Seed_k`, `RollupContext`, and proof binding. **Settles on finalized data**, not volatile tip-only fields.
pub trait L1Anchor: Send + Sync {
    fn get_current_slot(&self) -> u64;
    fn get_ledger_entropy(&self) -> [u8; 32];
    /// Previous finalized block hash for the current rollup slot (MSSQ seed limb).
    fn parent_block_hash_prev(&self) -> [u8; 32];
    fn latest_qrng_value(&self) -> [u8; 32];
    fn qrng_epoch(&self) -> u64;
    /// Kaspa blue score (or mock analogue) at the finalized boundary included in `RollupContext`.
    fn finalized_blue_score(&self) -> u64;
    /// Whether `block_hash` is accepted as finalized by this node (finality bit / policy).
    fn is_block_finalized(&self, block_hash: &[u8; 32]) -> bool;
}

/// Mutable sink for posting L2 batches to L1 (mock vector or future DA path).
pub trait L1BatchSink {
    fn post_batch(&mut self, batch: &Batch) -> Result<(), Error>;
}

/// Rollup-facing anchor: reads + optional posting (implemented by anchor adapters such as `qssm_kaspa::MockKaspaAdapter`).
pub trait SovereignAnchor: L1Anchor + L1BatchSink {}

impl<T: L1Anchor + L1BatchSink> SovereignAnchor for T {}
