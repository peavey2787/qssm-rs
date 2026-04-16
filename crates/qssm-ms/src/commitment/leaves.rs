//! Leaf construction and deterministic salt materialization for commitments.

use qssm_utils::hashing::{hash_domain, DOMAIN_MS};

/// Per-leaf salts: index `2 * i + b` binds bit `b ∈ {0,1}` at position `i` (0..64).
pub type Salts = [[u8; 32]; 128];

pub(crate) fn ms_leaf(i: u8, bit: u8, salt: &[u8; 32], ledger: &[u8; 32]) -> [u8; 32] {
    hash_domain(DOMAIN_MS, &[b"leaf", &[i], &[bit], salt.as_slice(), ledger])
}

pub(crate) fn build_leaves(salts: &Salts, ledger: &[u8; 32]) -> Vec<[u8; 32]> {
    let mut leaves = Vec::with_capacity(128);
    for i in 0u8..64 {
        for b in 0u8..=1u8 {
            let idx = 2 * (i as usize) + (b as usize);
            leaves.push(ms_leaf(i, b, &salts[idx], ledger));
        }
    }
    leaves
}

/// Deterministic salts from `seed` (reproducible CI / demos).
pub(crate) fn derive_salts(seed: [u8; 32]) -> Salts {
    let mut salts = [[0u8; 32]; 128];
    for i in 0u32..64 {
        for b in 0u8..=1u8 {
            let idx = (2 * i + b as u32) as usize;
            salts[idx] = hash_domain(
                DOMAIN_MS,
                &[b"salt", seed.as_slice(), &i.to_le_bytes(), &[b]],
            );
        }
    }
    salts
}
