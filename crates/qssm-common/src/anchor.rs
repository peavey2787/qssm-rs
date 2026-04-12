use crate::{Batch, Error};

/// L1 anchor: slot clock, ledger entropy, Kaspa block hash limb, QRNG limb, and batch posting.
pub trait SovereignAnchor {
    fn get_current_slot(&self) -> u64;
    fn get_ledger_entropy(&self) -> [u8; 32];
    /// `Kaspa_Block_Hash_{k-1}` for the current slot `k` (genesis-backed when `k == 0`).
    fn parent_block_hash_prev(&self) -> [u8; 32];
    /// Latest QRNG value (32-byte); rotates on slower cadence than block hash.
    fn latest_qrng_value(&self) -> [u8; 32];
    /// Monotonic QRNG epoch (e.g. ~60 s updates in production; mocked in tests).
    fn qrng_epoch(&self) -> u64;
    fn post_batch(&mut self, batch: &Batch) -> Result<(), Error>;
}
