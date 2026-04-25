//! Beta parameters: modulus, dimension, shortness, public binding, and challenge model.
#![forbid(unsafe_code)]

/// Polynomial degree \(n = 256\) for \(R_q = \mathbb{Z}_q[X]/(X^n+1)\).
pub const N: usize = 256;
/// Prime modulus with \(512 \mid (q-1)\) for length-512 NTT.
pub const Q: u32 = 8_380_417;
/// \(\ell_\infty\) bound on witness coefficients (rejection sampling threshold).
pub const BETA: u32 = 8;
/// Number of digest coefficients bound into Engine A public input.
pub const PUBLIC_DIGEST_COEFFS: usize = 64;
/// Maximum per-coefficient value for digest-to-coefficient embedding (4-bit lanes).
pub const PUBLIC_DIGEST_COEFF_MAX: u32 = 0x0f;

/// Masking vector \(\ell_\infty\) bound (proof-safe Set B for the formal HVZK route).
pub const ETA: u32 = 196_608;
/// Verifier accepts responses with \(\|z\|_\infty \le \gamma\) (centered mod \(q\)).
pub const GAMMA: u32 = 199_680;
/// Polynomial challenge coefficient count.
pub const C_POLY_SIZE: usize = 48;
/// Polynomial challenge coefficient span per lane \([-C\_POLY\_SPAN, C\_POLY\_SPAN]\).
pub const C_POLY_SPAN: i32 = 8;
/// Prover resampling attempts before giving up.
pub const MAX_PROVER_ATTEMPTS: u32 = 65_536;
