//! Pure arithmetic helpers used by prove/verify crossing checks.

use qssm_utils::hashing::{hash_domain, DOMAIN_MS};

pub(crate) fn ledger_rotation(ledger_entropy: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&ledger_entropy[..8]);
    u64::from_le_bytes(b)
}

/// Ledger-anchored per-nonce rotation: `n ∈ [0,255]` yields 256 full-width `u64` tweaks
/// (plain `r ⊕ zext(n)` only flips low bits and often cannot straddle `2^63` for small values).
pub(crate) fn rot_for_nonce(r: u64, n: u8) -> u64 {
    let h = hash_domain(DOMAIN_MS, &[b"rot_nonce", &r.to_le_bytes(), &[n]]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h[..8]);
    u64::from_le_bytes(b)
}

pub(crate) fn highest_differing_bit(a: u64, b: u64) -> Option<u8> {
    let mut k: u8 = 63;
    loop {
        let ba = (a >> k) & 1;
        let bb = (b >> k) & 1;
        if ba != bb {
            return Some(k);
        }
        if k == 0 {
            return None;
        }
        k -= 1;
    }
}
