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
use core::{highest_differing_bit, binding_rotation, rot_for_nonce};
use qssm_utils::PositionAwareTree;
use transcript::fs_challenge;

/// Merkle root over 128 position-aware leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostMirrorProof {
    pub n: u8,
    pub k: u8,
    pub bit_at_k: u8,
    pub opened_salt: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub challenge: [u8; 32],
}

/// Deterministic salts from `seed` (reproducible CI / demos).
pub fn commit(
    _value: u64,
    seed: [u8; 32],
    binding_entropy: [u8; 32],
) -> Result<(Root, Salts), MsError> {
    let salts = derive_salts(seed);
    let leaves = build_leaves(&salts, &binding_entropy);
    let tree = PositionAwareTree::new(leaves)?;
    Ok((Root(tree.get_root()), salts))
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
    let leaf = ms_leaf(proof.k, proof.bit_at_k, &proof.opened_salt, &binding_entropy);
    let leaf_idx = 2 * (proof.k as usize) + (proof.bit_at_k as usize);
    if !verify_path_to_root(&root.0, &leaf, leaf_idx, 128, &proof.path) {
        return false;
    }
    let expect_c = fs_challenge(
        &root.0,
        proof.n,
        proof.k,
        &binding_entropy,
        value,
        target,
        context,
        binding_context,
    );
    if expect_c != proof.challenge {
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
