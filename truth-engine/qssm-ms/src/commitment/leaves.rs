//! Leaf construction and deterministic salt materialization for commitments.

use qssm_utils::hashing::{hash_domain, DOMAIN_MS};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Per-leaf salts: index `2 * i + b` binds bit `b ∈ {0,1}` at position `i` (0..64).
///
/// Wraps 128 × 32-byte secret salt material.  Derives [`Zeroize`] + [`ZeroizeOnDrop`]
/// so the 4 KiB buffer is scrubbed when the value goes out of scope.
/// `Clone` and `Copy` are intentionally absent to prevent unmanaged copies.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Salts(pub(crate) [[u8; 32]; 128]);

impl std::fmt::Debug for Salts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Salts([REDACTED; 128])")
    }
}

impl Salts {
    /// Read-only access to the salt at `index` (0..128).
    #[inline]
    pub fn get(&self, index: usize) -> Option<&[u8; 32]> {
        self.0.get(index)
    }

    /// Internal: borrow the full array.
    #[inline]
    pub(crate) fn inner(&self) -> &[[u8; 32]; 128] {
        &self.0
    }
}

impl std::ops::Index<usize> for Salts {
    type Output = [u8; 32];
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

pub(crate) fn ms_leaf(i: u8, bit: u8, salt: &[u8; 32], binding_ent: &[u8; 32]) -> [u8; 32] {
    hash_domain(DOMAIN_MS, &[b"leaf", &[i], &[bit], salt.as_slice(), binding_ent])
}

pub(crate) fn build_leaves(salts: &Salts, binding_ent: &[u8; 32]) -> Vec<[u8; 32]> {
    let mut leaves = Vec::with_capacity(128);
    for i in 0u8..64 {
        for b in 0u8..=1u8 {
            let idx = 2 * (i as usize) + (b as usize);
            leaves.push(ms_leaf(i, b, &salts.0[idx], binding_ent));
        }
    }
    leaves
}

/// Deterministic salts from `seed` (reproducible CI / demos).
pub(crate) fn derive_salts(seed: [u8; 32]) -> Salts {
    let mut salts = Salts([[0u8; 32]; 128]);
    for i in 0u32..64 {
        for b in 0u8..=1u8 {
            let idx = (2 * i + b as u32) as usize;
            salts.0[idx] = hash_domain(
                DOMAIN_MS,
                &[b"salt", seed.as_slice(), &i.to_le_bytes(), &[b]],
            );
        }
    }
    salts
}
