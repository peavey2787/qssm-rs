use crate::hashing::{hash_domain, DOMAIN_MERKLE_PARENT};

/// Binary Merkle tree over power-of-two leaves. **Proof order**: siblings from leaf level
/// toward the root (deepest first): index `0` is the leaf’s immediate sibling, then the
/// next level, up to the sibling below the root.
#[derive(Debug, Clone)]
pub struct PositionAwareTree {
    root: [u8; 32],
    leaves: Vec<[u8; 32]>,
    levels: Vec<Vec<[u8; 32]>>,
}

/// Binary Merkle parent (neutral domain — not MS-specific).
pub fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    hash_domain(DOMAIN_MERKLE_PARENT, &[&buf])
}

impl PositionAwareTree {
    /// Pads `leaves` with deterministic padding digests until length is a power of two (min 1).
    pub fn new(mut leaves: Vec<[u8; 32]>) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyLeaves);
        }
        let target = leaves.len().next_power_of_two();
        let pad = hash_domain(DOMAIN_MERKLE_PARENT, &[b"pad"]);
        while leaves.len() < target {
            leaves.push(pad);
        }
        let mut levels = vec![leaves.clone()];
        let mut cur = leaves;
        while cur.len() > 1 {
            let mut next = Vec::with_capacity(cur.len() / 2);
            for pair in cur.chunks_exact(2) {
                next.push(merkle_parent(&pair[0], &pair[1]));
            }
            levels.push(next.clone());
            cur = next;
        }
        let root = cur.first().copied().ok_or(MerkleError::EmptyLeaves)?;
        let leaves = levels.first().cloned().ok_or(MerkleError::EmptyLeaves)?;
        Ok(Self {
            root,
            leaves,
            levels,
        })
    }

    pub fn get_root(&self) -> [u8; 32] {
        self.root
    }

    /// `index` is into the **padded** leaf vector (same order as `new` input + padding).
    pub fn get_proof(&self, index: usize) -> Result<Vec<[u8; 32]>, MerkleError> {
        let width = self.leaves.len();
        if index >= width {
            return Err(MerkleError::IndexOutOfBounds);
        }
        let mut proof = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = idx ^ 1;
            let sib = level
                .get(sibling)
                .copied()
                .ok_or(MerkleError::IndexOutOfBounds)?;
            proof.push(sib);
            idx /= 2;
        }
        Ok(proof)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum MerkleError {
    #[error("merkle tree requires at least one leaf")]
    EmptyLeaves,
    #[error("leaf index out of bounds")]
    IndexOutOfBounds,
}

#[cfg(test)]
#[allow(clippy::needless_range_loop, clippy::manual_is_multiple_of)]
mod tests {
    use super::*;
    use crate::hashing::blake3_hash;

    fn leaf(n: u8) -> [u8; 32] {
        blake3_hash(&[n])
    }

    /// Helper: manually verify a proof by walking siblings up to the root.
    fn verify_proof(
        root: &[u8; 32],
        leaf: &[u8; 32],
        mut index: usize,
        proof: &[[u8; 32]],
    ) -> bool {
        let mut cur = *leaf;
        for sib in proof {
            cur = if index % 2 == 0 {
                merkle_parent(&cur, sib)
            } else {
                merkle_parent(sib, &cur)
            };
            index /= 2;
        }
        cur == *root
    }

    #[test]
    fn single_leaf_root_is_leaf() {
        let l = leaf(42);
        let tree = PositionAwareTree::new(vec![l]).unwrap();
        assert_eq!(tree.get_root(), l);
        let proof = tree.get_proof(0).unwrap();
        assert!(proof.is_empty());
    }

    #[test]
    fn two_leaf_roundtrip() {
        let leaves = vec![leaf(0), leaf(1)];
        let tree = PositionAwareTree::new(leaves.clone()).unwrap();
        let expected_root = merkle_parent(&leaves[0], &leaves[1]);
        assert_eq!(tree.get_root(), expected_root);
        for i in 0..2 {
            let proof = tree.get_proof(i).unwrap();
            assert!(verify_proof(&tree.get_root(), &leaves[i], i, &proof));
        }
    }

    #[test]
    fn three_leaf_pads_to_four() {
        let leaves = vec![leaf(0), leaf(1), leaf(2)];
        let tree = PositionAwareTree::new(leaves.clone()).unwrap();
        // Should pad to 4 leaves; proof length = log2(4) = 2
        let proof = tree.get_proof(0).unwrap();
        assert_eq!(proof.len(), 2);
        for i in 0..3 {
            let proof = tree.get_proof(i).unwrap();
            assert!(verify_proof(&tree.get_root(), &leaves[i], i, &proof));
        }
    }

    #[test]
    fn five_leaf_pads_to_eight() {
        let leaves: Vec<[u8; 32]> = (0u8..5).map(leaf).collect();
        let tree = PositionAwareTree::new(leaves.clone()).unwrap();
        // Should pad to 8 leaves; proof length = log2(8) = 3
        let proof = tree.get_proof(0).unwrap();
        assert_eq!(proof.len(), 3);
        for i in 0..5 {
            let proof = tree.get_proof(i).unwrap();
            assert!(verify_proof(&tree.get_root(), &leaves[i], i, &proof));
        }
    }

    #[test]
    fn determinism() {
        let leaves: Vec<[u8; 32]> = (0u8..7).map(leaf).collect();
        let t1 = PositionAwareTree::new(leaves.clone()).unwrap();
        let t2 = PositionAwareTree::new(leaves).unwrap();
        assert_eq!(t1.get_root(), t2.get_root());
    }

    #[test]
    fn empty_leaves_error() {
        let err = PositionAwareTree::new(vec![]).unwrap_err();
        assert!(matches!(err, MerkleError::EmptyLeaves));
    }

    #[test]
    fn index_out_of_bounds_error() {
        let tree = PositionAwareTree::new(vec![leaf(0), leaf(1)]).unwrap();
        let err = tree.get_proof(2).unwrap_err();
        assert!(matches!(err, MerkleError::IndexOutOfBounds));
    }

    #[test]
    fn parent_non_commutativity() {
        let a = leaf(0);
        let b = leaf(1);
        assert_ne!(merkle_parent(&a, &b), merkle_parent(&b, &a));
    }

    #[test]
    fn power_of_two_no_padding() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(leaf).collect();
        let tree = PositionAwareTree::new(leaves.clone()).unwrap();
        // proof length = log2(4) = 2
        let proof = tree.get_proof(3).unwrap();
        assert_eq!(proof.len(), 2);
        assert!(verify_proof(&tree.get_root(), &leaves[3], 3, &proof));
    }

    #[test]
    fn large_tree_128_leaves() {
        let leaves: Vec<[u8; 32]> = (0u8..128).map(leaf).collect();
        let tree = PositionAwareTree::new(leaves.clone()).unwrap();
        // proof length = log2(128) = 7
        let proof = tree.get_proof(0).unwrap();
        assert_eq!(proof.len(), 7);
        // spot-check a few indices
        for &i in &[0, 1, 63, 64, 127] {
            let proof = tree.get_proof(i).unwrap();
            assert!(verify_proof(&tree.get_root(), &leaves[i], i, &proof));
        }
    }
}
