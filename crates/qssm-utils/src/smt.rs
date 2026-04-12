//! State Mirror Tree v1: sorted-account Merkle root over `hash(domain, key, value_bytes)`.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

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

    fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        debug_assert!(!leaves.is_empty());
        let mut cur: Vec<[u8; 32]> = leaves.to_vec();
        let pad = hash_domain(DOMAIN_MERKLE_PARENT, &[b"smt_pad"]);
        let target = cur.len().next_power_of_two();
        while cur.len() < target {
            cur.push(pad);
        }
        while cur.len() > 1 {
            let mut next = Vec::with_capacity(cur.len() / 2);
            for pair in cur.chunks_exact(2) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                next.push(hash_domain(DOMAIN_MERKLE_PARENT, &[&buf]));
            }
            cur = next;
        }
        cur[0]
    }

    /// Recompute root from sorted leaves (empty map → [`Self::empty_root()`]).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self
            .entries
            .iter()
            .map(|(k, v)| Self::leaf_digest(k, v))
            .collect();
        if leaves.is_empty() {
            return Self::empty_root();
        }
        Self::merkle_root(&leaves)
    }

    /// Empty tree uses `hash(domain, "smt_empty")` as root sentinel.
    #[must_use]
    pub fn empty_root() -> [u8; 32] {
        hash_domain(DOMAIN_MSSQ_STATE, &[b"smt_empty"])
    }

    pub fn get(&self, key: &StateKey) -> Option<&[u8; 32]> {
        self.entries.get(key)
    }

    pub fn insert(&mut self, key: StateKey, value: [u8; 32]) {
        self.entries.insert(key, value);
    }
}
