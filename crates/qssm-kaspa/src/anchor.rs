//! Production L1 anchor surface (gRPC-backed in real deployments; stubbed in workspace by default).

use qssm_common::L1Anchor;

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
