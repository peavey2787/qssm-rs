//! §5 Sovereign Digest → 30‑bit limb for `qssm-le` `PublicInstance.message`.
//!
//! **Never** embed raw `root` or `root % 2^30` — always hash `Root ‖ RollupContext ‖ ProofMetadata` first.

use qssm_utils::hashing::hash_domain;

/// Domain tag for `H(domain ‖ root ‖ rollup ‖ metadata…)`.
pub const DOMAIN_SOVEREIGN_LIMB_V1: &str = "QSSM-SOVEREIGN-LIMB-v1.0";

/// `SovereignDigest = hash_domain(DOMAIN, chunks…)` then low **30** bits (LE) as `u64` message limb.
#[must_use]
pub fn sovereign_message_limb_v1(
    root: &[u8; 32],
    rollup_context_digest: &[u8; 32],
    proof_metadata: &[u8],
) -> u64 {
    let digest = hash_domain(
        DOMAIN_SOVEREIGN_LIMB_V1,
        &[root.as_slice(), rollup_context_digest, proof_metadata],
    );
    let w = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    u64::from(w & ((1u32 << 30) - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_is_below_2_pow_30() {
        let r = [7u8; 32];
        let ctx = [9u8; 32];
        let m = sovereign_message_limb_v1(&r, &ctx, b"meta");
        assert!(m < (1u64 << 30));
    }
}
