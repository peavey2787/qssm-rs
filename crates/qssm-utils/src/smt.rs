//! Canonical 256-bit sparse Merkle tree over `hash(domain, key, value)`.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::hashing::{hash_domain, DOMAIN_MERKLE_PARENT, DOMAIN_MSSQ_STATE};

/// 32-byte account / storage key.
pub type StateKey = [u8; 32];

/// In-memory key–value store with deterministic Merkle root (rebuilt on each update).
#[derive(Debug, Clone)]
pub struct StateMirrorTree {
    entries: BTreeMap<StateKey, [u8; 32]>,
}

impl Default for StateMirrorTree {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMirrorTree {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Leaf digest: `BLAKE3(DOMAIN ‖ "smt_leaf" ‖ key ‖ value_32)`.
    fn leaf_digest(key: &StateKey, value: &[u8; 32]) -> [u8; 32] {
        hash_domain(
            DOMAIN_MSSQ_STATE,
            &[b"smt_leaf", key.as_slice(), value.as_slice()],
        )
    }

    fn default_leaf() -> [u8; 32] {
        hash_domain(DOMAIN_MSSQ_STATE, &[b"smt_leaf_default"])
    }

    fn default_hashes() -> [[u8; 32]; 257] {
        let mut d = [[0u8; 32]; 257];
        d[256] = Self::default_leaf();
        for depth in (0..256).rev() {
            d[depth] = merkle_parent(&d[depth + 1], &d[depth + 1]);
        }
        d
    }

    fn node_prefix(key: &StateKey, depth: usize) -> StateKey {
        if depth == 256 {
            return *key;
        }
        let mut out = *key;
        let bytes = depth / 8;
        let rem = depth % 8;
        if bytes < 32 {
            if rem == 0 {
                for b in &mut out[bytes..] {
                    *b = 0;
                }
            } else {
                let mask = 0xFF << (8 - rem);
                out[bytes] &= mask;
                for b in &mut out[bytes + 1..] {
                    *b = 0;
                }
            }
        }
        out
    }

    fn bit_at(key: &StateKey, depth: usize) -> u8 {
        let byte = depth / 8;
        let bit = 7 - (depth % 8);
        (key[byte] >> bit) & 1
    }

    fn with_bit(prefix: &StateKey, depth: usize, bit: u8) -> StateKey {
        let mut out = Self::node_prefix(prefix, depth + 1);
        let byte = depth / 8;
        let pos = 7 - (depth % 8);
        if bit == 1 {
            out[byte] |= 1 << pos;
        } else {
            out[byte] &= !(1 << pos);
        }
        out
    }

    fn build_node_hashes(&self) -> (HashMap<NodeKey, [u8; 32]>, [[u8; 32]; 257]) {
        let defaults = Self::default_hashes();
        let mut nodes: HashMap<NodeKey, [u8; 32]> = HashMap::new();
        for (k, v) in &self.entries {
            nodes.insert(
                NodeKey {
                    depth: 256,
                    prefix: *k,
                },
                Self::leaf_digest(k, v),
            );
        }
        for depth in (0..256).rev() {
            let child_depth = depth + 1;
            let child_keys = nodes
                .keys()
                .filter(|k| k.depth == child_depth)
                .map(|k| Self::node_prefix(&k.prefix, depth))
                .collect::<BTreeSet<_>>();
            for parent_prefix in child_keys {
                let left_prefix = Self::with_bit(&parent_prefix, depth, 0);
                let right_prefix = Self::with_bit(&parent_prefix, depth, 1);
                let left = nodes
                    .get(&NodeKey {
                        depth: child_depth,
                        prefix: left_prefix,
                    })
                    .copied()
                    .unwrap_or(defaults[child_depth]);
                let right = nodes
                    .get(&NodeKey {
                        depth: child_depth,
                        prefix: right_prefix,
                    })
                    .copied()
                    .unwrap_or(defaults[child_depth]);
                if left == defaults[child_depth] && right == defaults[child_depth] {
                    continue;
                }
                nodes.insert(
                    NodeKey {
                        depth,
                        prefix: parent_prefix,
                    },
                    merkle_parent(&left, &right),
                );
            }
        }
        (nodes, defaults)
    }

    /// Recompute root from canonical sparse tree (empty map -> default root).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let (nodes, defaults) = self.build_node_hashes();
        nodes.get(&NodeKey::root()).copied().unwrap_or(defaults[0])
    }

    /// Empty tree uses `hash(domain, "smt_empty")` as root sentinel.
    #[must_use]
    pub fn empty_root() -> [u8; 32] {
        Self::default_hashes()[0]
    }

    pub fn get(&self, key: &StateKey) -> Option<&[u8; 32]> {
        self.entries.get(key)
    }

    pub fn insert(&mut self, key: StateKey, value: [u8; 32]) {
        self.entries.insert(key, value);
    }

    #[must_use]
    pub fn prove(&self, key: &StateKey) -> SparseMerkleProof {
        let (nodes, defaults) = self.build_node_hashes();
        let mut siblings = Vec::with_capacity(256);
        for depth in 0..256 {
            let parent = Self::node_prefix(key, depth);
            let sibling_bit = if Self::bit_at(key, depth) == 0 { 1 } else { 0 };
            let sibling_prefix = Self::with_bit(&parent, depth, sibling_bit);
            let s = nodes
                .get(&NodeKey {
                    depth: depth + 1,
                    prefix: sibling_prefix,
                })
                .copied()
                .unwrap_or(defaults[depth + 1]);
            siblings.push(s);
        }
        SparseMerkleProof {
            key: *key,
            value: self.entries.get(key).copied(),
            siblings,
        }
    }

    #[must_use]
    pub fn verify_proof(root: [u8; 32], proof: &SparseMerkleProof) -> bool {
        if proof.siblings.len() != 256 {
            return false;
        }
        let default_leaf = Self::default_leaf();
        let mut cur = match proof.value {
            Some(v) => Self::leaf_digest(&proof.key, &v),
            None => default_leaf,
        };
        for depth in (0..256).rev() {
            let sib = proof.siblings[depth];
            let bit = Self::bit_at(&proof.key, depth);
            cur = if bit == 0 {
                merkle_parent(&cur, &sib)
            } else {
                merkle_parent(&sib, &cur)
            };
        }
        cur == root
    }
}

fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    hash_domain(DOMAIN_MERKLE_PARENT, &[&buf])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NodeKey {
    depth: usize,
    prefix: StateKey,
}

impl NodeKey {
    fn root() -> Self {
        Self {
            depth: 0,
            prefix: [0u8; 32],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMerkleProof {
    pub key: StateKey,
    pub value: Option<[u8; 32]>,
    pub siblings: Vec<[u8; 32]>,
}

impl SparseMerkleProof {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 32 + 2 + (256 * 32));
        out.push(if self.value.is_some() { 1 } else { 0 });
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.value.unwrap_or([0u8; 32]));
        out.extend_from_slice(&(self.siblings.len() as u16).to_le_bytes());
        for s in &self.siblings {
            out.extend_from_slice(s);
        }
        out
    }

    pub fn decode(input: &[u8]) -> Option<Self> {
        if input.len() < 67 {
            return None;
        }
        let has_value = input[0] == 1;
        let mut key = [0u8; 32];
        key.copy_from_slice(&input[1..33]);
        let mut v = [0u8; 32];
        v.copy_from_slice(&input[33..65]);
        let depth = u16::from_le_bytes(input[65..67].try_into().ok()?) as usize;
        if input.len() != 67 + depth * 32 {
            return None;
        }
        let mut siblings = Vec::with_capacity(depth);
        let mut off = 67;
        for _ in 0..depth {
            let mut s = [0u8; 32];
            s.copy_from_slice(&input[off..off + 32]);
            siblings.push(s);
            off += 32;
        }
        Some(Self {
            key,
            value: if has_value { Some(v) } else { None },
            siblings,
        })
    }
}
