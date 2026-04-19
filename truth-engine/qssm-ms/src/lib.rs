//! QSSM-MS: Ghost-Mirror commitments and succinct inequality proofs (reference implementation).
//!
//! **Reference notes (vs. whitepaper):** per-nonce rotation uses `BLAKE3(DOMAIN_MS ‖ "rot_nonce" ‖ r ‖ n)`
//! so each `n ∈ [0,255]` perturbs the full `u64` (a bare `r ⊕ zext(n)` only toggles low bits and is
//! too narrow for demos). The crossing step uses `a′ > b′` plus the highest bit where `a′` and `b′`
//! differ (avoids an astronomically rare fixed `2^63` hemisphere straddle under 256 trials).
#![forbid(unsafe_code)]

mod commitment;
mod core;
mod error;
mod transcript;

pub use commitment::leaves::Salts;
pub use error::MsError;

use commitment::leaves::{build_leaves, derive_salts, ms_leaf};
use commitment::tree::verify_path_to_root;
use core::{binding_rotation, highest_differing_bit, rot_for_nonce};
use qssm_utils::PositionAwareTree;
use subtle::ConstantTimeEq;
use transcript::fs_challenge;

/// Expected Merkle path length for the 128-leaf tree.
const MERKLE_PATH_LEN: usize = 7;

/// Merkle root over 128 position-aware leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root([u8; 32]);

impl Root {
    /// Construct a `Root` from raw bytes.
    #[inline]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Read-only access to the underlying hash.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A succinct Ghost-Mirror inequality proof.
///
/// All fields are private.  Use the accessor methods to read individual
/// components, or [`GhostMirrorProof::new`] to reconstruct from wire data.
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Clone)]
pub struct GhostMirrorProof {
    pub(crate) n: u8,
    pub(crate) k: u8,
    pub(crate) bit_at_k: u8,
    pub(crate) opened_salt: [u8; 32],
    pub(crate) path: Vec<[u8; 32]>,
    pub(crate) challenge: [u8; 32],
}

impl GhostMirrorProof {
    /// Construct a proof from deserialized components, with validation.
    ///
    /// Returns `Err(MsError::InvalidProofField)` if any field is out of range:
    /// - `bit_at_k` must be 0 or 1
    /// - `k` must be ≤ 63
    /// - `path` must contain exactly 7 sibling hashes
    pub fn new(
        n: u8,
        k: u8,
        bit_at_k: u8,
        opened_salt: [u8; 32],
        path: Vec<[u8; 32]>,
        challenge: [u8; 32],
    ) -> Result<Self, MsError> {
        if bit_at_k > 1 {
            return Err(MsError::InvalidProofField("bit_at_k must be 0 or 1"));
        }
        if k > 63 {
            return Err(MsError::InvalidProofField("k must be <= 63"));
        }
        if path.len() != MERKLE_PATH_LEN {
            return Err(MsError::InvalidProofField(
                "path must contain exactly 7 sibling hashes",
            ));
        }
        Ok(Self {
            n,
            k,
            bit_at_k,
            opened_salt,
            path,
            challenge,
        })
    }

    /// Nonce used for this proof.
    #[inline]
    pub fn n(&self) -> u8 {
        self.n
    }
    /// Bit position of the crossing.
    #[inline]
    pub fn k(&self) -> u8 {
        self.k
    }
    /// The bit of the *original* value at position `k`.
    #[inline]
    pub fn bit_at_k(&self) -> u8 {
        self.bit_at_k
    }
    /// The opened salt for the leaf at `(k, bit_at_k)`.
    #[inline]
    pub fn opened_salt(&self) -> &[u8; 32] {
        &self.opened_salt
    }
    /// Merkle siblings (length 7).
    #[inline]
    pub fn path(&self) -> &[[u8; 32]] {
        &self.path
    }
    /// Fiat-Shamir challenge digest.
    #[inline]
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
}

impl std::fmt::Debug for GhostMirrorProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GhostMirrorProof")
            .field("n", &self.n)
            .field("k", &self.k)
            .field("bit_at_k", &self.bit_at_k)
            .field("opened_salt", &"[REDACTED]")
            .field("path", &format_args!("[{} siblings]", self.path.len()))
            .field("challenge", &"[REDACTED]")
            .finish()
    }
}

/// Deterministic salts from `seed` (reproducible CI / demos).
pub fn commit(seed: [u8; 32], binding_entropy: [u8; 32]) -> Result<(Root, Salts), MsError> {
    let salts = derive_salts(seed);
    let leaves = build_leaves(&salts, &binding_entropy);
    let tree = PositionAwareTree::new(leaves)?;
    Ok((Root::new(tree.get_root()), salts))
}

/// Prove `value > target` under binding entropy; tries all nonces `n ∈ [0,255]`.
pub fn prove(
    value: u64,
    target: u64,
    salts: &Salts,
    binding_entropy: [u8; 32],
    context: &[u8],
    binding_context: &[u8; 32],
) -> Result<GhostMirrorProof, MsError> {
    if value <= target {
        return Err(MsError::NoValidRotation);
    }
    let leaves = build_leaves(salts, &binding_entropy);
    let tree = PositionAwareTree::new(leaves)?;
    let root = tree.get_root();
    let r = binding_rotation(&binding_entropy);

    for n in 0u8..=255 {
        let rot = rot_for_nonce(r, n);
        let a_p = value.wrapping_add(rot);
        let b_p = target.wrapping_add(rot);
        if a_p <= b_p {
            continue;
        }
        let Some(k) = highest_differing_bit(a_p, b_p) else {
            continue;
        };
        let bit_at_k = ((value >> k) & 1) as u8;
        let leaf_idx = 2 * (k as usize) + (bit_at_k as usize);
        let opened_salt = salts[leaf_idx];
        let path = tree.get_proof(leaf_idx)?;
        let challenge = fs_challenge(
            &root,
            n,
            k,
            &binding_entropy,
            value,
            target,
            context,
            binding_context,
        );
        return Ok(GhostMirrorProof {
            n,
            k,
            bit_at_k,
            opened_salt,
            path,
            challenge,
        });
    }
    Err(MsError::NoValidRotation)
}

/// Verify opening + Merkle path + Fiat–Shamir binding + crossing predicate.
///
/// # Security
///
/// This is a **succinct predicate proof**, not a zero-knowledge proof.
/// Both `value` and `target` must be known to the verifier — the protocol
/// proves `value > target` without revealing magnitude information beyond
/// the binary predicate result.  Do **not** use this function in contexts
/// where the values themselves must remain hidden from the verifier.
pub fn verify(
    root: Root,
    proof: &GhostMirrorProof,
    binding_entropy: [u8; 32],
    value: u64,
    target: u64,
    context: &[u8],
    binding_context: &[u8; 32],
) -> bool {
    if proof.bit_at_k > 1 {
        return false;
    }
    if proof.k > 63 {
        return false;
    }
    if ((value >> proof.k) & 1) as u8 != proof.bit_at_k {
        return false;
    }
    let leaf = ms_leaf(
        proof.k,
        proof.bit_at_k,
        &proof.opened_salt,
        &binding_entropy,
    );
    let leaf_idx = 2 * (proof.k as usize) + (proof.bit_at_k as usize);
    if !verify_path_to_root(root.as_bytes(), &leaf, leaf_idx, 128, &proof.path) {
        return false;
    }
    let expect_c = fs_challenge(
        root.as_bytes(),
        proof.n,
        proof.k,
        &binding_entropy,
        value,
        target,
        context,
        binding_context,
    );
    if expect_c.ct_eq(&proof.challenge).unwrap_u8() == 0 {
        return false;
    }
    let r = binding_rotation(&binding_entropy);
    let rot = rot_for_nonce(r, proof.n);
    let a_p = value.wrapping_add(rot);
    let b_p = target.wrapping_add(rot);
    if a_p <= b_p {
        return false;
    }
    highest_differing_bit(a_p, b_p) == Some(proof.k)
}
