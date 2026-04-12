//! Module-LWE commitment \(C = A r + \mu\) with Lyubashevsky-style Fiat–Shamir + rejection (no witness in proof).
#![forbid(unsafe_code)]

use rand::RngCore;

use crate::crs::VerifyingKey;
use crate::params::{C_SPAN, GAMMA, MAX_MESSAGE, MAX_PROVER_ATTEMPTS, N, BETA, ETA};
use crate::ring::{encode_rq_coeffs_le, short_vec_to_rq, short_vec_to_rq_bound, RqPoly};
use crate::LeError;

const DOMAIN_LE_FS: &str = "QSSM-LE-FS-LYU-v1.0";

/// Public inputs visible to all verifiers (no secret witness).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInstance {
    pub message: u64,
}

impl PublicInstance {
    pub fn validate(&self) -> Result<(), LeError> {
        if self.message >= MAX_MESSAGE {
            return Err(LeError::MessageOutOfRange);
        }
        Ok(())
    }
}

/// Secret witness (prover-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub r: [i32; N],
}

impl Witness {
    pub fn validate(&self) -> Result<(), LeError> {
        for &v in &self.r {
            if v.unsigned_abs() > BETA {
                return Err(LeError::RejectedSample);
            }
        }
        Ok(())
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
    /// Fiat–Shamir challenge bytes (recomputed by verifier).
    pub challenge: [u8; 32],
}

fn fs_challenge_bytes(
    rollup_context_digest: &[u8; 32],
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    t: &RqPoly,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_LE_FS.as_bytes());
    h.update(rollup_context_digest);
    h.update(vk.crs_seed.as_slice());
    h.update(&public.message.to_le_bytes());
    h.update(&encode_rq_coeffs_le(&commitment.0));
    h.update(&encode_rq_coeffs_le(t));
    *h.finalize().as_bytes()
}

/// Map FS bytes to a small scalar challenge in \([-C\_SPAN, C\_SPAN]\).
fn challenge_scalar(ch: &[u8; 32]) -> i32 {
    let u = u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]);
    let span = C_SPAN as u32;
    (u % (2 * span + 1)) as i32 - C_SPAN
}

/// \(C = A r + \mu(m)\).
pub fn commit_mlwe(
    vk: &VerifyingKey,
    public: &PublicInstance,
    witness: &Witness,
) -> Result<Commitment, LeError> {
    public.validate()?;
    witness.validate()?;
    let a = vk.matrix_a_poly();
    let r = short_vec_to_rq(&witness.r)?;
    let ar = a.mul(&r)?;
    let mu = RqPoly::embed_constant(public.message);
    Ok(Commitment(ar.add(&mu)))
}

pub fn prove_with_witness(
    vk: &VerifyingKey,
    public: &PublicInstance,
    witness: &Witness,
    commitment: &Commitment,
    rollup_context_digest: &[u8; 32],
    rng: &mut impl RngCore,
) -> Result<LatticeProof, LeError> {
    public.validate()?;
    witness.validate()?;
    let a = vk.matrix_a_poly();
    let r_poly = short_vec_to_rq(&witness.r)?;
    let mu = RqPoly::embed_constant(public.message);
    let u = commitment.0.sub(&mu);

    for _ in 0..MAX_PROVER_ATTEMPTS {
        let mut y = [0i32; N];
        for coeff in &mut y {
            *coeff = (rng.next_u32() % (2 * ETA + 1)) as i32 - ETA as i32;
        }
        let y_poly = short_vec_to_rq_bound(&y, ETA)?;
        let t = a.mul(&y_poly)?;
        let ch = fs_challenge_bytes(rollup_context_digest, vk, public, commitment, &t);
        let c = challenge_scalar(&ch);
        let cr = r_poly.scalar_mul_signed(c);
        let z = y_poly.add(&cr);
        if z.inf_norm_centered() > GAMMA {
            continue;
        }
        let lhs = a.mul(&z)?;
        let rhs = t.add(&u.scalar_mul_signed(c));
        if lhs == rhs {
            return Ok(LatticeProof { t, z, challenge: ch });
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
    rollup_context_digest: &[u8; 32],
) -> Result<bool, LeError> {
    public.validate()?;
    if proof.z.inf_norm_centered() > GAMMA {
        return Ok(false);
    }
    let a = vk.matrix_a_poly();
    let mu = RqPoly::embed_constant(public.message);
    let u = commitment.0.sub(&mu);
    let ch = fs_challenge_bytes(rollup_context_digest, vk, public, commitment, &proof.t);
    if ch != proof.challenge {
        return Ok(false);
    }
    let c = challenge_scalar(&ch);
    let lhs = a.mul(&proof.z)?;
    let rhs = proof.t.add(&u.scalar_mul_signed(c));
    Ok(lhs == rhs)
}
