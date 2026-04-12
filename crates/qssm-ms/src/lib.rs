//! QSSM-MS: Ghost-Mirror commitments and succinct inequality proofs (reference implementation).
//!
//! **Reference notes (vs. whitepaper):** per-nonce rotation uses `BLAKE3(DOMAIN_MS ‖ "rot_nonce" ‖ r ‖ n)`
//! so each `n ∈ [0,255]` perturbs the full `u64` (a bare `r ⊕ zext(n)` only toggles low bits and is
//! too narrow for demos). The crossing step uses `a′ > b′` plus the highest bit where `a′` and `b′`
//! differ (avoids an astronomically rare fixed `2^63` hemisphere straddle under 256 trials).
#![forbid(unsafe_code)]

mod error;

pub use error::MsError;

use qssm_utils::hashing::{hash_domain, DOMAIN_MS};
use qssm_utils::{merkle_parent, PositionAwareTree};

/// Merkle root over 128 position-aware leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root(pub [u8; 32]);

/// Per-leaf salts: index `2 * i + b` binds bit `b ∈ {0,1}` at position `i` (0..64).
pub type Salts = [[u8; 32]; 128];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostMirrorProof {
    pub n: u8,
    pub k: u8,
    pub bit_at_k: u8,
    pub opened_salt: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub challenge: [u8; 32],
}

fn ledger_rotation(ledger_entropy: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&ledger_entropy[..8]);
    u64::from_le_bytes(b)
}

/// Ledger-anchored per-nonce rotation: `n ∈ [0,255]` yields 256 full-width `u64` tweaks
/// (plain `r ⊕ zext(n)` only flips low bits and often cannot straddle `2^63` for small values).
fn rot_for_nonce(r: u64, n: u8) -> u64 {
    let h = hash_domain(DOMAIN_MS, &[b"rot_nonce", &r.to_le_bytes(), &[n]]);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h[..8]);
    u64::from_le_bytes(b)
}

fn ms_leaf(i: u8, bit: u8, salt: &[u8; 32], ledger: &[u8; 32]) -> [u8; 32] {
    hash_domain(DOMAIN_MS, &[b"leaf", &[i], &[bit], salt.as_slice(), ledger])
}

fn build_leaves(salts: &Salts, ledger: &[u8; 32]) -> Vec<[u8; 32]> {
    let mut leaves = Vec::with_capacity(128);
    for i in 0u8..64 {
        for b in 0u8..=1u8 {
            let idx = 2 * (i as usize) + (b as usize);
            leaves.push(ms_leaf(i, b, &salts[idx], ledger));
        }
    }
    leaves
}

fn highest_differing_bit(a: u64, b: u64) -> Option<u8> {
    let mut k: u8 = 63;
    loop {
        let ba = (a >> k) & 1;
        let bb = (b >> k) & 1;
        if ba != bb {
            return Some(k);
        }
        if k == 0 {
            return None;
        }
        k -= 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn fs_challenge(
    root: &[u8; 32],
    n: u8,
    k: u8,
    entropy: &[u8; 32],
    value: u64,
    target: u64,
    context: &[u8],
    rollup_context_digest: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[
            b"fs_v2",
            root.as_slice(),
            &[n],
            &[k],
            entropy.as_slice(),
            &value.to_le_bytes(),
            &target.to_le_bytes(),
            context,
            rollup_context_digest.as_slice(),
        ],
    )
}

fn verify_path_to_root(
    root: &[u8; 32],
    leaf: &[u8; 32],
    index: usize,
    width: usize,
    proof: &[[u8; 32]],
) -> bool {
    if !width.is_power_of_two() {
        return false;
    }
    let mut acc = *leaf;
    let mut idx: usize = index;
    for sib in proof {
        let (left, right) = if idx.is_multiple_of(2) {
            (&acc, sib)
        } else {
            (sib, &acc)
        };
        acc = merkle_parent(left, right);
        idx /= 2;
    }
    idx == 0 && acc == *root && proof.len() == width.ilog2() as usize
}

/// Deterministic salts from `seed` (reproducible CI / demos).
pub fn commit(
    _value: u64,
    seed: [u8; 32],
    ledger_entropy: [u8; 32],
) -> Result<(Root, Salts), MsError> {
    let mut salts = [[0u8; 32]; 128];
    for i in 0u32..64 {
        for b in 0u8..=1u8 {
            let idx = (2 * i + b as u32) as usize;
            salts[idx] = hash_domain(
                DOMAIN_MS,
                &[b"salt", seed.as_slice(), &i.to_le_bytes(), &[b]],
            );
        }
    }
    let leaves = build_leaves(&salts, &ledger_entropy);
    let tree = PositionAwareTree::new(leaves)?;
    Ok((Root(tree.get_root()), salts))
}

/// Prove `value > target` under ledger entropy; tries all nonces `n ∈ [0,255]`.
pub fn prove(
    value: u64,
    target: u64,
    salts: &Salts,
    ledger_entropy: [u8; 32],
    context: &[u8],
    rollup_context_digest: &[u8; 32],
) -> Result<GhostMirrorProof, MsError> {
    if value <= target {
        return Err(MsError::NoValidRotation);
    }
    let leaves = build_leaves(salts, &ledger_entropy);
    let tree = PositionAwareTree::new(leaves)?;
    let root = tree.get_root();
    let r = ledger_rotation(&ledger_entropy);

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
            &ledger_entropy,
            value,
            target,
            context,
            rollup_context_digest,
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
    ledger_entropy: [u8; 32],
    value: u64,
    target: u64,
    context: &[u8],
    rollup_context_digest: &[u8; 32],
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
    let leaf = ms_leaf(proof.k, proof.bit_at_k, &proof.opened_salt, &ledger_entropy);
    let leaf_idx = 2 * (proof.k as usize) + (proof.bit_at_k as usize);
    if !verify_path_to_root(&root.0, &leaf, leaf_idx, 128, &proof.path) {
        return false;
    }
    let expect_c = fs_challenge(
        &root.0,
        proof.n,
        proof.k,
        &ledger_entropy,
        value,
        target,
        context,
        rollup_context_digest,
    );
    if expect_c != proof.challenge {
        return false;
    }
    let r = ledger_rotation(&ledger_entropy);
    let rot = rot_for_nonce(r, proof.n);
    let a_p = value.wrapping_add(rot);
    let b_p = target.wrapping_add(rot);
    if a_p <= b_p {
        return false;
    }
    highest_differing_bit(a_p, b_p) == Some(proof.k)
}
