//! Module-LWE commitment \(C = A r + \mu\) with Lyubashevsky-style Fiat–Shamir + rejection (no witness in proof).
#![forbid(unsafe_code)]

use crate::DeterministicRng;
use core::hint::black_box;
use qssm_utils::hashing::DOMAIN_MS;
use qssm_utils::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION;
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::algebra::ring::{
    encode_rq_coeffs_le, short_vec_to_rq, short_vec_to_rq_bound, RqPoly, ScrubbedPoly,
};
use crate::crs::VerifyingKey;
use crate::protocol::params::{
    BETA, C_POLY_SIZE, C_POLY_SPAN, ETA, GAMMA, MAX_PROVER_ATTEMPTS, N, PUBLIC_DIGEST_COEFFS,
    PUBLIC_DIGEST_COEFF_MAX, Q,
};
use crate::LeError;

const DOMAIN_LE_FS: &str = "QSSM-LE-FS-LYU-v1.0";
const DOMAIN_LE_CHALLENGE_POLY: &str = "QSSM-LE-CHALLENGE-POLY-v1.0";
const CROSS_PROTOCOL_BINDING_LABEL: &[u8] = b"cross_protocol_digest_v1";
const DST_LE_COMMIT: [u8; 32] = *b"QSSM-LE-V1-COMMIT...............";
const DST_MS_VERIFY: [u8; 32] = *b"QSSM-MS-V1-VERIFY...............";

/// Public inputs visible to all verifiers (no secret witness).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicBinding {
    /// Bind digest-derived coefficient vector (4-bit lanes, each ≤ 15).
    DigestCoeffVector { coeffs: [u32; PUBLIC_DIGEST_COEFFS] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInstance {
    binding: PublicBinding,
}

impl PublicInstance {
    #[must_use]
    pub fn binding(&self) -> &PublicBinding {
        &self.binding
    }

    /// Construct from digest coefficients. Validates all ≤ `PUBLIC_DIGEST_COEFF_MAX`.
    pub fn digest_coeffs(coeffs: [u32; PUBLIC_DIGEST_COEFFS]) -> Result<Self, LeError> {
        for &c in &coeffs {
            if c > PUBLIC_DIGEST_COEFF_MAX {
                return Err(LeError::OversizedInput);
            }
        }
        Ok(Self {
            binding: PublicBinding::DigestCoeffVector { coeffs },
        })
    }

    /// Encode a `u64` scalar as 4-bit nibble coefficients (16 nibbles, rest zero).
    /// Standard migration path from the removed legacy single-limb message mode.
    #[must_use]
    pub fn from_u64_nibbles(value: u64) -> Self {
        let mut coeffs = [0u32; PUBLIC_DIGEST_COEFFS];
        for i in 0..16 {
            coeffs[i] = ((value >> (i * 4)) & 0x0f) as u32;
        }
        Self {
            binding: PublicBinding::DigestCoeffVector { coeffs },
        }
    }

    pub fn validate(&self) -> Result<(), LeError> {
        let PublicBinding::DigestCoeffVector { coeffs } = &self.binding;
        for &c in coeffs {
            if c > PUBLIC_DIGEST_COEFF_MAX {
                return Err(LeError::OversizedInput);
            }
        }
        Ok(())
    }
}

/// Secret witness (prover-only).
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Witness {
    r: [i32; N],
}

impl core::fmt::Debug for Witness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Witness").field("r", &"[REDACTED]").finish()
    }
}

impl Witness {
    /// Construct a new witness from short coefficients.
    #[must_use]
    pub fn new(r: [i32; N]) -> Self {
        Self { r }
    }

    /// Read-only access to witness coefficients.
    #[must_use]
    pub fn coeffs(&self) -> &[i32; N] {
        &self.r
    }

    pub fn validate(&self) -> Result<(), LeError> {
        for &v in &self.r {
            if v.unsigned_abs() > BETA {
                return Err(LeError::RejectedSample);
            }
        }
        Ok(())
    }
}

/// Secret witness key material (alias wrapper for forward-compatible APIs).
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[allow(dead_code)]
pub(crate) struct SecretKey {
    pub(crate) r: [i32; N],
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretKey")
            .field("r", &"[REDACTED]")
            .finish()
    }
}

/// Prover masking randomness sampled per-attempt.
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct CommitmentRandomness {
    y: [i32; N],
}

impl CommitmentRandomness {
    /// Construct a new commitment randomness from nonce coefficients.
    #[must_use]
    pub fn new(y: [i32; N]) -> Self {
        Self { y }
    }

    /// Read-only access to nonce coefficients.
    #[must_use]
    pub fn coeffs(&self) -> &[i32; N] {
        &self.y
    }
}

impl core::fmt::Debug for CommitmentRandomness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommitmentRandomness")
            .field("y", &"[REDACTED]")
            .finish()
    }
}

/// Commitment as a full ring element (canonical coeffs mod \(q\)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment(pub RqPoly);

/// Witness-hiding proof: masking commitment \(t = Ay\) and response \(z = y + c r\) with FS challenge \(c\).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatticeProof {
    pub t: RqPoly,
    pub z: RqPoly,
    /// Fiat–Shamir seed bytes (recomputed by verifier).
    pub challenge_seed: [u8; 32],
}

/// Serializes [`PublicBinding`] for Fiat–Shamir. **Sync:** any change to this byte layout or to
/// [`fs_challenge_bytes`] hash-input order must bump [`qssm_utils::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`]
/// and the gadget `TranscriptMap` / `TRANSCRIPT_MAP_LAYOUT_VERSION` in `qssm-gadget`.
fn public_binding_fs_bytes(public: &PublicInstance) -> Vec<u8> {
    let _ = LE_FS_PUBLIC_BINDING_LAYOUT_VERSION;
    let PublicBinding::DigestCoeffVector { coeffs } = &public.binding;
    let mut out = Vec::with_capacity(1 + coeffs.len() * 4);
    out.push(1);
    for &c in coeffs {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

fn fs_challenge_bytes(
    binding_context: &[u8; 32],
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    t: &RqPoly,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_LE_FS.as_bytes());
    h.update(&DST_LE_COMMIT);
    h.update(&DST_MS_VERIFY);
    // Explicit cross-protocol binding context to prevent Engine-A/Engine-B replay confusion.
    h.update(CROSS_PROTOCOL_BINDING_LABEL);
    h.update(DOMAIN_MS.as_bytes());
    h.update(b"fs_v2");
    h.update(binding_context);
    h.update(vk.crs_seed.as_slice());
    h.update(&public_binding_fs_bytes(public));
    h.update(&encode_rq_coeffs_le(&commitment.0));
    h.update(&encode_rq_coeffs_le(t));
    *h.finalize().as_bytes()
}

#[inline(never)]
fn gamma_bound_scan(poly: &RqPoly) -> Choice {
    #[inline(always)]
    fn check_coeff(coeff: u32) -> Choice {
        let q_half = Q / 2;
        let x = coeff;
        let gt_half_mask = ((q_half.wrapping_sub(x)) >> 31).wrapping_neg();
        let centered = i64::from(x) - (i64::from(Q) & i64::from(gt_half_mask));
        let sign_mask = centered >> 63;
        let abs_centered = ((centered ^ sign_mask) - sign_mask) as u64;
        (abs_centered as u32).ct_lt(&(GAMMA + 1))
    }
    let mut ok = Choice::from(1u8);
    macro_rules! check4 {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {{
            ok &= check_coeff(poly.0[$a]);
            ok &= check_coeff(poly.0[$b]);
            ok &= check_coeff(poly.0[$c]);
            ok &= check_coeff(poly.0[$d]);
        }};
    }
    check4!(0, 1, 2, 3);
    check4!(4, 5, 6, 7);
    check4!(8, 9, 10, 11);
    check4!(12, 13, 14, 15);
    check4!(16, 17, 18, 19);
    check4!(20, 21, 22, 23);
    check4!(24, 25, 26, 27);
    check4!(28, 29, 30, 31);
    check4!(32, 33, 34, 35);
    check4!(36, 37, 38, 39);
    check4!(40, 41, 42, 43);
    check4!(44, 45, 46, 47);
    check4!(48, 49, 50, 51);
    check4!(52, 53, 54, 55);
    check4!(56, 57, 58, 59);
    check4!(60, 61, 62, 63);
    check4!(64, 65, 66, 67);
    check4!(68, 69, 70, 71);
    check4!(72, 73, 74, 75);
    check4!(76, 77, 78, 79);
    check4!(80, 81, 82, 83);
    check4!(84, 85, 86, 87);
    check4!(88, 89, 90, 91);
    check4!(92, 93, 94, 95);
    check4!(96, 97, 98, 99);
    check4!(100, 101, 102, 103);
    check4!(104, 105, 106, 107);
    check4!(108, 109, 110, 111);
    check4!(112, 113, 114, 115);
    check4!(116, 117, 118, 119);
    check4!(120, 121, 122, 123);
    check4!(124, 125, 126, 127);
    check4!(128, 129, 130, 131);
    check4!(132, 133, 134, 135);
    check4!(136, 137, 138, 139);
    check4!(140, 141, 142, 143);
    check4!(144, 145, 146, 147);
    check4!(148, 149, 150, 151);
    check4!(152, 153, 154, 155);
    check4!(156, 157, 158, 159);
    check4!(160, 161, 162, 163);
    check4!(164, 165, 166, 167);
    check4!(168, 169, 170, 171);
    check4!(172, 173, 174, 175);
    check4!(176, 177, 178, 179);
    check4!(180, 181, 182, 183);
    check4!(184, 185, 186, 187);
    check4!(188, 189, 190, 191);
    check4!(192, 193, 194, 195);
    check4!(196, 197, 198, 199);
    check4!(200, 201, 202, 203);
    check4!(204, 205, 206, 207);
    check4!(208, 209, 210, 211);
    check4!(212, 213, 214, 215);
    check4!(216, 217, 218, 219);
    check4!(220, 221, 222, 223);
    check4!(224, 225, 226, 227);
    check4!(228, 229, 230, 231);
    check4!(232, 233, 234, 235);
    check4!(236, 237, 238, 239);
    check4!(240, 241, 242, 243);
    check4!(244, 245, 246, 247);
    check4!(248, 249, 250, 251);
    check4!(252, 253, 254, 255);
    ok
}

#[inline(never)]
fn ct_reject_if_above_gamma(poly: &RqPoly) -> Choice {
    #[inline(never)]
    fn invoke(f: &dyn Fn(&RqPoly) -> Choice, p: &RqPoly) -> Choice {
        f(p)
    }
    let dispatch: &dyn Fn(&RqPoly) -> Choice = &gamma_bound_scan;
    black_box(invoke(dispatch, poly))
}

fn challenge_poly(seed: &[u8; 32]) -> [i32; C_POLY_SIZE] {
    let mut coeffs = [0i32; C_POLY_SIZE];
    let span = C_POLY_SPAN as u32;
    let mut filled = 0usize;
    let mut ctr = 0u32;
    while filled < C_POLY_SIZE {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_LE_CHALLENGE_POLY.as_bytes());
        h.update(seed);
        h.update(&ctr.to_le_bytes());
        let block = h.finalize();
        for chunk in block.as_bytes().chunks_exact(4) {
            if filled >= C_POLY_SIZE {
                break;
            }
            let u = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            coeffs[filled] = (u % (2 * span + 1)) as i32 - C_POLY_SPAN;
            filled += 1;
        }
        ctr = ctr.wrapping_add(1);
    }
    coeffs
}

fn challenge_poly_to_rq(poly: &[i32; C_POLY_SIZE]) -> RqPoly {
    let mut out = [0u32; N];
    for i in 0..C_POLY_SIZE {
        let c = poly[i];
        out[i] = if c >= 0 {
            (c as u32) % Q
        } else {
            Q - ((-c) as u32 % Q)
        };
    }
    RqPoly(out)
}

fn is_canonical_poly(poly: &RqPoly) -> bool {
    poly.0.iter().all(|&c| c < Q)
}

fn mu_from_public(public: &PublicInstance) -> RqPoly {
    let PublicBinding::DigestCoeffVector { coeffs } = &public.binding;
    let mut out = [0u32; N];
    out[..PUBLIC_DIGEST_COEFFS].copy_from_slice(coeffs);
    RqPoly(out)
}

/// \(C = A r + \mu(public)\).
pub fn commit_mlwe(
    vk: &VerifyingKey,
    public: &PublicInstance,
    witness: &Witness,
) -> Result<Commitment, LeError> {
    public.validate()?;
    witness.validate()?;
    let a = vk.matrix_a_poly();
    let r = ScrubbedPoly::from_public(&short_vec_to_rq(&witness.r)?);
    let ar = r.mul_public(&a)?;
    let mu = mu_from_public(public);
    Ok(Commitment(ar.as_public().add(&mu)))
}

pub fn prove_with_witness(
    vk: &VerifyingKey,
    public: &PublicInstance,
    witness: &Witness,
    commitment: &Commitment,
    binding_context: &[u8; 32],
    rng: &mut impl DeterministicRng,
) -> Result<LatticeProof, LeError> {
    public.validate()?;
    witness.validate()?;
    let a = vk.matrix_a_poly();
    let r_poly = ScrubbedPoly::from_public(&short_vec_to_rq(&witness.r)?);
    let mu = mu_from_public(public);
    let u = ScrubbedPoly::from_public(&commitment.0.sub(&mu));

    for _ in 0..MAX_PROVER_ATTEMPTS {
        let mut y_arr = [0i32; N];
        for coeff in &mut y_arr {
            *coeff = (rng.next_u32() % (2 * ETA + 1)) as i32 - ETA as i32;
        }
        let y_poly = ScrubbedPoly::from_public(&short_vec_to_rq_bound(&y_arr, ETA)?);
        y_arr.zeroize();
        let t = y_poly.mul_public(&a)?.as_public();
        let challenge_seed = fs_challenge_bytes(binding_context, vk, public, commitment, &t);
        let c_poly = challenge_poly(&challenge_seed);
        let c_rq = challenge_poly_to_rq(&c_poly);
        let c_rq_secret = ScrubbedPoly::from_public(&c_rq);
        let cr = r_poly.mul_public(&c_rq)?;
        let z = y_poly.add(&cr);
        if ct_reject_if_above_gamma(&z.as_public()).unwrap_u8() == 0 {
            continue;
        }
        let lhs = z.mul_public(&a)?.as_public();
        let rhs = t.add(&c_rq_secret.mul_scrubbed(&u)?.as_public());
        if lhs == rhs {
            return Ok(LatticeProof {
                t,
                z: z.into_public(),
                challenge_seed,
            });
        }
    }
    Err(LeError::ProverAborted)
}

/// Algebraic verification: \(\|z\|_\infty \le \gamma\), recompute \(c\), check \(Az = t + c(C-\mu)\). **No `Witness`.**
pub fn verify_lattice_algebraic(
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    proof: &LatticeProof,
    binding_context: &[u8; 32],
) -> Result<bool, LeError> {
    public.validate()?;
    if !is_canonical_poly(&commitment.0)
        || !is_canonical_poly(&proof.t)
        || !is_canonical_poly(&proof.z)
    {
        return Err(LeError::OversizedInput);
    }
    if ct_reject_if_above_gamma(&proof.z).unwrap_u8() == 0 {
        return Err(LeError::InvalidNorm);
    }
    let a = vk.matrix_a_poly();
    let mu = mu_from_public(public);
    let u = commitment.0.sub(&mu);
    let challenge_seed = fs_challenge_bytes(binding_context, vk, public, commitment, &proof.t);
    if challenge_seed.ct_eq(&proof.challenge_seed).unwrap_u8() == 0 {
        return Err(LeError::DomainMismatch);
    }
    let c_poly = challenge_poly(&challenge_seed);
    let c_rq = challenge_poly_to_rq(&c_poly);
    let lhs = a.mul(&proof.z)?;
    let rhs = proof.t.add(&c_rq.mul(&u)?);
    if lhs == rhs {
        Ok(true)
    } else {
        Err(LeError::DomainMismatch)
    }
}
