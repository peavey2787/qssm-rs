//! Merkle-specific commitment verification helpers.

use qssm_utils::merkle_parent;
use subtle::ConstantTimeEq;

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
        #[allow(clippy::manual_is_multiple_of)]
        let (left, right) = if idx % 2 == 0 {
            (&acc, sib)
        } else {
            (sib, &acc)
        };
        acc = merkle_parent(left, right);
        idx /= 2;
    }
    idx == 0 && acc.ct_eq(root).unwrap_u8() == 1 && proof.len() == width.ilog2() as usize
}
