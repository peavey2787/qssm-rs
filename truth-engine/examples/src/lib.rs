//! Shared setup helpers for zk-stack examples.
//!
//! Eliminates repeated boilerplate across example binaries.

use zk_api::ProofContext;

/// Common SDK context: a seeded [`ProofContext`] and its binding context.
pub struct SdkSetup {
    pub ctx: ProofContext,
    pub binding_ctx: [u8; 32],
}

impl SdkSetup {
    /// Harvest hardware entropy, derive a [`ProofContext`] and a binding context
    /// from `binding_label` (BLAKE3 of the label bytes).
    pub fn from_label(binding_label: &[u8]) -> Self {
        let seed = zk_api::harvest_entropy_seed()
            .expect("hardware entropy unavailable — cannot produce sovereign proofs");
        Self {
            ctx: ProofContext::new(seed),
            binding_ctx: qssm_utils::hashing::blake3_hash(binding_label),
        }
    }

    /// Harvest a fresh 32-byte entropy seed for a single prove call.
    pub fn fresh_entropy(&self) -> [u8; 32] {
        zk_api::harvest_entropy_seed()
            .expect("hardware entropy unavailable — cannot produce sovereign proofs")
    }
}

/// Format a 32-byte hash as `<first8>...<last8>`.
pub fn hex_short(bytes: &[u8]) -> String {
    let h = hex::encode(bytes);
    if h.len() >= 16 {
        format!("{}...{}", &h[..8], &h[h.len() - 8..])
    } else {
        h
    }
}
