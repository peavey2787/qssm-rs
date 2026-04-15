//! Merkle-specific commitment verification helpers.

use qssm_utils::merkle_parent;

pub(crate) fn verify_path_to_root(
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
        let (left, right) = if idx.is_multiple_of(2) { (&acc, sib) } else { (sib, &acc) };
        acc = merkle_parent(left, right);
        idx /= 2;
    }
    idx == 0 && acc == *root && proof.len() == width.ilog2() as usize
}
