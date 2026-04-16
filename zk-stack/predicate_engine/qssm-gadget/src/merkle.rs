//! Phase 0: `leaf_index` LE bit path must match physical left/right placement before hashing.

use qssm_utils::merkle_parent;

use crate::error::GadgetError;
use crate::primitives::bits::to_le_bits;

/// Engine B Ghost‑Mirror tree: 128 leaves, depth 7 (`qssm-ms` / `PositionAwareTree`).
pub const MERKLE_WIDTH_MS: usize = 128;
pub const MERKLE_DEPTH_MS: usize = 7;

/// Witness for a Merkle opening (fixed depth‑7 path for MS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePathWitness {
    pub leaf: [u8; 32],
    pub siblings: [[u8; 32]; MERKLE_DEPTH_MS],
    pub leaf_index: u8,
}

impl MerklePathWitness {
    /// Phase 0 + upward hash to root (same sibling order as `qssm-ms` `verify_path_to_root`).
    pub fn recompute_root(&self) -> Result<[u8; 32], GadgetError> {
        if self.leaf_index as usize >= MERKLE_WIDTH_MS {
            return Err(GadgetError::LeafIndexOutOfRange {
                index: self.leaf_index as usize,
                width: MERKLE_WIDTH_MS,
            });
        }

        let parity_from_le: [bool; 32] = to_le_bits(self.leaf_index as u32);
        let mut idx = self.leaf_index as usize;
        let mut acc = self.leaf;

        for level in 0..MERKLE_DEPTH_MS {
            let expected_acc_on_right = parity_from_le[level];
            let acc_on_right = (idx & 1) == 1;
            if expected_acc_on_right != acc_on_right {
                return Err(GadgetError::IndexMismatch);
            }

            let sib = &self.siblings[level];
            acc = if idx.is_multiple_of(2) {
                merkle_parent(&acc, sib)
            } else {
                merkle_parent(sib, &acc)
            };
            idx /= 2;
        }

        debug_assert_eq!(idx, 0);
        Ok(acc)
    }
}

/// Engine B: opened leaf index is `2*k + bit_at_k` (`qssm-ms`).
pub fn assert_ms_leaf_index_matches_opening(
    k: u8,
    bit_at_k: u8,
    leaf_index: u8,
) -> Result<(), GadgetError> {
    let expected = 2usize * (k as usize) + (bit_at_k as usize);
    if leaf_index as usize != expected {
        return Err(GadgetError::MsOpeningMismatch {
            leaf_index: leaf_index as usize,
            k,
            bit_at_k,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::bits::to_le_bits;

    #[test]
    fn phase0_parities_align_with_index_walk() {
        let leaf_index = 37u8;
        let mut idx = leaf_index as usize;
        let p = to_le_bits(leaf_index as u32);
        for level in 0..MERKLE_DEPTH_MS {
            assert_eq!((idx & 1) == 1, p[level], "level {level}");
            idx /= 2;
        }
    }

    #[test]
    fn wrong_claimed_index_triggers_opening_mismatch() {
        let err = assert_ms_leaf_index_matches_opening(3, 1, 10).unwrap_err();
        assert!(matches!(err, GadgetError::MsOpeningMismatch { .. }));
    }
}
