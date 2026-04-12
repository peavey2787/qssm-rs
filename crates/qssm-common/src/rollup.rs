//! Rollup state + `RollupContext` construction from an [`L1Anchor`](crate::L1Anchor).
#![forbid(unsafe_code)]

use qssm_utils::{RollupContext, StateMirrorTree};

use crate::L1Anchor;

/// Account / storage tree + cached Merkle root semantics via [`StateMirrorTree`].
#[derive(Debug, Clone, Default)]
pub struct RollupState {
    pub smt: StateMirrorTree,
}

impl RollupState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            smt: StateMirrorTree::new(),
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
