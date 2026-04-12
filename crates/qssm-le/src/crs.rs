//! Transparent CRS: ring element \(A\) from `BLAKE3(DOMAIN_LE ‖ crs_seed)`.
#![forbid(unsafe_code)]

use qssm_utils::hashing::{hash_domain, DOMAIN_LE};

use crate::params::{N, Q};
use crate::ring::RqPoly;

/// Verifying / proving key material (nothing-up-my-sleeve seed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey {
    pub crs_seed: [u8; 32],
}

impl VerifyingKey {
    pub fn from_seed(crs_seed: [u8; 32]) -> Self {
        Self { crs_seed }
    }

    /// Expand into a pseudorandom ring element \(A \in R_q\).
    pub fn matrix_a_poly(&self) -> RqPoly {
        let mut coeffs = [0u32; N];
        for (i, c) in coeffs.iter_mut().enumerate() {
            let ib = (i as u32).to_le_bytes();
            let buf = hash_domain(DOMAIN_LE, &[b"A_row", self.crs_seed.as_slice(), ib.as_slice()]);
            let mut w = [0u8; 4];
            w.copy_from_slice(&buf[..4]);
            *c = u32::from_le_bytes(w) % Q;
        }
        RqPoly(coeffs)
    }
}
