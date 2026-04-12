use qssm_utils::hashing::{
    hash_domain, DOMAIN_MOCK_KASPA_BLOCK, DOMAIN_MOCK_KASPA_ENTROPY, DOMAIN_MOCK_QRNG,
};

use crate::anchor::SovereignAnchor;
use crate::{Batch, Error};

/// Deterministic mock BlockDAG anchor: manual slot, **fast tick** (~100 ms block-hash narrative), **QRNG epoch** (~60 s).
#[derive(Debug, Clone)]
pub struct MockKaspaAdapter {
    slot: u64,
    genesis: [u8; 32],
    posted: Vec<Batch>,
    /// Simulated high-velocity block counter (advance with [`Self::tick_fast`]).
    fast_tick: u64,
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

    /// Simulate ~100 ms Kaspa block hash churn (deterministic).
    pub fn tick_fast(&mut self) {
        self.fast_tick = self.fast_tick.saturating_add(1);
    }

    pub fn fast_tick_count(&self) -> u64 {
        self.fast_tick
    }

    /// Advance QRNG epoch (~60 s narrative) and refresh `latest_qrng_value`.
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
}

impl SovereignAnchor for MockKaspaAdapter {
    fn get_current_slot(&self) -> u64 {
        self.slot
    }

    fn get_ledger_entropy(&self) -> [u8; 32] {
        let le = self.slot.to_le_bytes();
        hash_domain(
            DOMAIN_MOCK_KASPA_ENTROPY,
            &[le.as_slice(), &self.genesis],
        )
    }

    fn parent_block_hash_prev(&self) -> [u8; 32] {
        if self.slot == 0 {
            hash_domain(DOMAIN_MOCK_KASPA_BLOCK, &[b"genesis", self.genesis.as_slice()])
        } else {
            let prev = self.slot - 1;
            hash_domain(
                DOMAIN_MOCK_KASPA_BLOCK,
                &[
                    prev.to_le_bytes().as_slice(),
                    self.genesis.as_slice(),
                    self.fast_tick.to_le_bytes().as_slice(),
                ],
            )
        }
    }

    fn latest_qrng_value(&self) -> [u8; 32] {
        self.qrng_value
    }

    fn qrng_epoch(&self) -> u64 {
        self.qrng_epoch
    }

    fn post_batch(&mut self, batch: &Batch) -> Result<(), Error> {
        self.posted.push(batch.clone());
        Ok(())
    }
}
