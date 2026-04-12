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

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum MerkleError {
    #[error("merkle tree requires at least one leaf")]
    EmptyLeaves,
    #[error("leaf index out of bounds")]
    IndexOutOfBounds,
}
