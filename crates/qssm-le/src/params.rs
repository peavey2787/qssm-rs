//! Beta parameters: modulus, dimension, shortness, message range.
#![forbid(unsafe_code)]

/// Polynomial degree \(n = 64\) for \(R_q = \mathbb{Z}_q[X]/(X^n+1)\).
pub const N: usize = 64;
/// Prime modulus with \(128 \mid (q-1)\) for length-128 NTT.
pub const Q: u32 = 7_340_033;
/// \(\ell_\infty\) bound on witness coefficients (rejection sampling threshold).
pub const BETA: u32 = 8;
/// Public message must embed below Goldilocks lift range (doc: \(v < 2^{30}\)).
pub const MAX_MESSAGE: u64 = 1 << 30;
