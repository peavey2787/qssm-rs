//! Kaspa BlockDAG anchor for rollup `L1Anchor` (production: gRPC; default: typed stub).
//!
//! Enable `kaspa-grpc` and wire real RPCs to finalized headers / blue score. The default
//! [`GrpcKaspaAnchor`] returns conservative placeholders until connected.
#![forbid(unsafe_code)]

use qssm_common::{Batch, Error, L1Anchor, L1BatchSink};

/// Placeholder gRPC-backed anchor (replace internals with real Kaspa RPC mapping).
#[derive(Debug, Default, Clone)]
pub struct GrpcKaspaAnchor {
    /// When wired: cache from `GetSinkBlueScore` / virtual chain finality RPCs.
    pub stub_slot: u64,
    pub stub_finalized_blue_score: u64,
    pub stub_parent_hash: [u8; 32],
    pub stub_qrng_epoch: u64,
    pub stub_qrng_value: [u8; 32],
    pub stub_entropy: [u8; 32],
}

impl GrpcKaspaAnchor {
    #[must_use]
    pub fn new_stub() -> Self {
        Self::default()
    }
}

impl L1Anchor for GrpcKaspaAnchor {
    fn get_current_slot(&self) -> u64 {
        self.stub_slot
    }

    fn get_ledger_entropy(&self) -> [u8; 32] {
        self.stub_entropy
    }

    fn parent_block_hash_prev(&self) -> [u8; 32] {
        self.stub_parent_hash
    }

    fn latest_qrng_value(&self) -> [u8; 32] {
        self.stub_qrng_value
    }

    fn qrng_epoch(&self) -> u64 {
        self.stub_qrng_epoch
    }

    fn finalized_blue_score(&self) -> u64 {
        self.stub_finalized_blue_score
    }

    fn is_block_finalized(&self, block_hash: &[u8; 32]) -> bool {
        *block_hash == self.stub_parent_hash
    }
}

/// Until DA path exists, posting is a no-op success (wire to `SubmitTransaction` etc.).
#[derive(Default)]
pub struct GrpcBatchSink {
    _priv: (),
}

impl L1BatchSink for GrpcBatchSink {
    fn post_batch(&mut self, _batch: &Batch) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(feature = "kaspa-grpc")]
pub mod grpc {
    //! Reserved: `tonic` client types and proto includes live here when wired.
    pub use tonic;
}
