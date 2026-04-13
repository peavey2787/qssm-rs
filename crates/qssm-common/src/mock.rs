use qssm_utils::hashing::{
    hash_domain, DOMAIN_MOCK_KASPA_BLOCK, DOMAIN_MOCK_KASPA_ENTROPY, DOMAIN_MOCK_QRNG,
};

use crate::l1_anchor::{L1Anchor, L1BatchSink};
use crate::{Batch, Error};

/// Deterministic mock BlockDAG: volatile `fast_tick` vs **`finalized_tick`** (rollup anchor).
#[derive(Debug, Clone)]
pub struct MockKaspaAdapter {
    slot: u64,
    genesis: [u8; 32],
    posted: Vec<Batch>,
    /// Volatile tip simulation (~100 ms narrative).
    fast_tick: u64,
    /// Tick depth included in finalized / rollup-safe parent hash.
    finalized_tick: u64,
    /// When true, every [`Self::tick_fast`] also advances `finalized_tick`.
    auto_finalize: bool,
    qrng_epoch: u64,
    qrng_value: [u8; 32],
}

impl MockKaspaAdapter {
    pub fn new(genesis: [u8; 32]) -> Self {
        let mut s = Self {
            slot: 0,
            genesis,
            posted: Vec::new(),
            fast_tick: 0,
            finalized_tick: 0,
            auto_finalize: true,
            qrng_epoch: 0,
            qrng_value: [0u8; 32],
        };
        s.refresh_qrng_digest();
        s
    }

    pub fn set_slot(&mut self, slot: u64) {
        self.slot = slot;
    }

    pub fn advance_slot(&mut self) {
        self.slot = self.slot.saturating_add(1);
    }

    pub fn tick_fast(&mut self) {
        self.fast_tick = self.fast_tick.saturating_add(1);
        if self.auto_finalize {
            self.finalized_tick = self.fast_tick;
        }
    }

    pub fn fast_tick_count(&self) -> u64 {
        self.fast_tick
    }

    pub fn finalized_tick_count(&self) -> u64 {
        self.finalized_tick
    }

    /// Promote volatile chain depth into the finalized view (reorg resistance tests).
    pub fn finalize_volatile(&mut self) {
        self.finalized_tick = self.fast_tick;
    }

    pub fn set_auto_finalize(&mut self, on: bool) {
        self.auto_finalize = on;
    }

    pub fn advance_qrng_epoch(&mut self) {
        self.qrng_epoch = self.qrng_epoch.saturating_add(1);
        self.refresh_qrng_digest();
    }

    pub fn set_qrng_epoch(&mut self, epoch: u64) {
        self.qrng_epoch = epoch;
        self.refresh_qrng_digest();
    }

    fn refresh_qrng_digest(&mut self) {
        self.qrng_value = hash_domain(
            DOMAIN_MOCK_QRNG,
            &[
                self.qrng_epoch.to_le_bytes().as_slice(),
                self.genesis.as_slice(),
            ],
        );
    }

    pub fn posted_batches(&self) -> &[Batch] {
        &self.posted
    }

    fn genesis_block_hash(&self) -> [u8; 32] {
        hash_domain(
            DOMAIN_MOCK_KASPA_BLOCK,
            &[b"genesis", self.genesis.as_slice()],
        )
    }

    /// Parent / prior block hash for `slot` using tick `t` (finalized or volatile).
    fn parent_hash_with_tick(&self, tick: u64) -> [u8; 32] {
        if self.slot == 0 {
            self.genesis_block_hash()
        } else {
            let prev = self.slot - 1;
            hash_domain(
                DOMAIN_MOCK_KASPA_BLOCK,
                &[
                    prev.to_le_bytes().as_slice(),
                    self.genesis.as_slice(),
                    tick.to_le_bytes().as_slice(),
                ],
            )
        }
    }
}

impl L1Anchor for MockKaspaAdapter {
    fn get_current_slot(&self) -> u64 {
        self.slot
    }

    fn get_ledger_entropy(&self) -> [u8; 32] {
        let le = self.slot.to_le_bytes();
        hash_domain(DOMAIN_MOCK_KASPA_ENTROPY, &[le.as_slice(), &self.genesis])
    }

    fn parent_block_hash_prev(&self) -> [u8; 32] {
        self.parent_hash_with_tick(self.finalized_tick)
    }

    fn latest_qrng_value(&self) -> [u8; 32] {
        self.qrng_value
    }

    fn qrng_epoch(&self) -> u64 {
        self.qrng_epoch
    }

    fn finalized_blue_score(&self) -> u64 {
        self.finalized_tick
    }

    fn is_block_finalized(&self, block_hash: &[u8; 32]) -> bool {
        let g = self.genesis_block_hash();
        *block_hash == g || *block_hash == self.parent_block_hash_prev()
    }
}

impl L1BatchSink for MockKaspaAdapter {
    fn post_batch(&mut self, batch: &Batch) -> Result<(), Error> {
        self.posted.push(batch.clone());
        Ok(())
    }
}
