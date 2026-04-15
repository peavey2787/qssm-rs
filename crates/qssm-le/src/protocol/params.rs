//! Beta parameters: modulus, dimension, shortness, message range.
#![forbid(unsafe_code)]

/// Polynomial degree \(n = 256\) for \(R_q = \mathbb{Z}_q[X]/(X^n+1)\).
pub const N: usize = 256;
/// Prime modulus with \(512 \mid (q-1)\) for length-512 NTT.
pub const Q: u32 = 8_380_417;
/// \(\ell_\infty\) bound on witness coefficients (rejection sampling threshold).
pub const BETA: u32 = 8;
/// Public message must embed below Goldilocks lift range (doc: \(v < 2^{30}\)).
pub const MAX_MESSAGE: u64 = 1 << 30;

/// Masking vector \(\ell_\infty\) bound (Lyubashevsky-style; rejection if exceeded).
pub const ETA: u32 = 2_048;
/// Verifier accepts responses with \(\|z\|_\infty \le \gamma\) (centered mod \(q\)).
pub const GAMMA: u32 = 4_096;
/// Fiat–Shamir scalar challenge range \([-C\_SPAN, C\_SPAN]\) (soundness vs proof size trade-off).
pub const C_SPAN: i32 = 16;
/// Prover resampling attempts before giving up.
pub const MAX_PROVER_ATTEMPTS: u32 = 65_536;
