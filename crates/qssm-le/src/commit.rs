//! Module-LWE style commitment \(C = A \cdot r + \mu\) over \(R_q\) (Beta single-relation).
#![forbid(unsafe_code)]

use crate::crs::VerifyingKey;
use crate::params::{BETA, MAX_MESSAGE};
use crate::ring::{short_vec_to_rq, RqPoly};
use crate::LeError;

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

/// Secret witness (prover-only; **must not** be an argument to `verify_lattice`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// Short polynomial \(r\) coefficients, \(\|r\|_\infty \le \beta\).
    pub r: [i32; crate::params::N],
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

/// NIZK-style proof bundle: shortness opening + Fiat–Shamir binding transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatticeProof {
    /// Coefficients of \(r\) (verifier enforces \(\ell_\infty\) bound).
    pub r_opening: [i32; crate::params::N],
    pub transcript: [u8; 32],
}

fn fs_transcript(
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    r_digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(qssm_utils::hashing::DOMAIN_LE.as_bytes());
    h.update(DOMAIN_LE_REF_PROOF.as_bytes());
    h.update(vk.crs_seed.as_slice());
    h.update(&public.message.to_le_bytes());
    for c in commitment.0.0.iter() {
        h.update(&c.to_le_bytes());
    }
    h.update(r_digest.as_slice());
    *h.finalize().as_bytes()
}

const DOMAIN_LE_REF_PROOF: &str = "QSSM-LE-BETA-PROOF-v2.0";

fn digest_r(r: &[i32; crate::params::N]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(qssm_utils::hashing::DOMAIN_LE.as_bytes());
    h.update(b"r_opening");
    for v in r {
        h.update(&v.to_le_bytes());
    }
    *h.finalize().as_bytes()
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
) -> Result<LatticeProof, LeError> {
    public.validate()?;
    witness.validate()?;
    let rd = digest_r(&witness.r);
    let tr = fs_transcript(vk, public, commitment, &rd);
    Ok(LatticeProof {
        r_opening: witness.r,
        transcript: tr,
    })
}

/// Algebraic verification: recompute \(C' = A r' + \mu\) and check FS transcript. **No `Witness` parameter.**
pub fn verify_lattice_algebraic(
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    proof: &LatticeProof,
) -> Result<bool, LeError> {
    public.validate()?;
    for &v in &proof.r_opening {
        if v.unsigned_abs() > BETA {
            return Err(LeError::RejectedSample);
        }
    }
    let a = vk.matrix_a_poly();
    let r = short_vec_to_rq(&proof.r_opening)?;
    let ar = a.mul(&r)?;
    let mu = RqPoly::embed_constant(public.message);
    let expected = Commitment(ar.add(&mu));
    if expected != *commitment {
        return Ok(false);
    }
    let rd = digest_r(&proof.r_opening);
    let tr = fs_transcript(vk, public, commitment, &rd);
    Ok(tr == proof.transcript)
}
