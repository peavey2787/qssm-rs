//! Rollup state + `RollupContext` construction from an [`L1Anchor`](crate::L1Anchor).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::VecDeque;

use qssm_utils::{RollupContext, StateMirrorTree};

use crate::L1Anchor;
use crate::StorageLease;

/// Account / storage tree + cached Merkle root semantics via [`StateMirrorTree`].
#[derive(Debug, Clone, Default)]
pub struct RollupState {
    pub smt: StateMirrorTree,
    pub leases: BTreeMap<[u8; 32], StorageLease>,
    pub pulse_height: u64,
    pub recent_roots: VecDeque<[u8; 32]>,
}

impl RollupState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            smt: StateMirrorTree::new(),
            leases: BTreeMap::new(),
            pulse_height: 0,
            recent_roots: VecDeque::new(),
        }
    }

    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.smt.root()
    }
}

#[must_use]
pub fn rollup_context_from_l1<A: L1Anchor>(anchor: &A) -> RollupContext {
    RollupContext {
        finalized_block_hash: anchor.parent_block_hash_prev(),
        finalized_blue_score: anchor.finalized_blue_score(),
        qrng_epoch: anchor.qrng_epoch(),
        qrng_value: anchor.latest_qrng_value(),
    }
}
