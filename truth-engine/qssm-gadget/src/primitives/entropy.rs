//! Entropy anchor types and **floor** computation (pure, no network I/O).
//!
//! The first **32** bytes of the floor preimage are an **entropy anchor** (external anchor hash,
//! a static root, or a hashed timestamp). Anchors are one [`EntropyAnchor`] variant, not a
//! hard‑coded primitive.
//!
//! External entropy boosters (NIST beacon, etc.) are injected by the caller — the truth engine
//! never performs network I/O.

use qssm_utils::hashing::blake3_hash;

/// **32‑byte leg** mixed with local entropy for [`entropy_floor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyAnchor {
    /// External **32‑byte** anchor hash (e.g. finalized block id, DAG parent) used as the floor limb.
    AnchorHash([u8; 32]),
    /// Fixed **32‑byte** root (no external chain): e.g. org‑published commitment or app session root.
    StaticRoot([u8; 32]),
    /// Wall‑clock (or agreed) **Unix seconds**; canonicalized to **32** bytes via domain‑separated BLAKE3.
    TimestampUnixSecs { unix_secs: u64 },
}

impl EntropyAnchor {
    /// **32** bytes fed into **`BLAKE3(leg ‖ local)`** (the entropy floor preimage's first half).
    #[must_use]
    pub fn entropy_leg(&self) -> [u8; 32] {
        match self {
            Self::AnchorHash(h) | Self::StaticRoot(h) => *h,
            Self::TimestampUnixSecs { unix_secs } => {
                let mut buf = [0u8; 8 + 32];
                buf[..32].copy_from_slice(b"QSSM-ENTROPY-ANCHOR-TIMESTAMP-v1");
                buf[32..].copy_from_slice(&unix_secs.to_le_bytes());
                blake3_hash(&buf)
            }
        }
    }
}

/// **`BLAKE3(anchor_leg ‖ Local_Bytes)`** — entropy **floor**. **`anchor_leg`** is [`EntropyAnchor::entropy_leg`].
#[must_use]
pub fn entropy_floor(anchor_leg: [u8; 32], local_bytes: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&anchor_leg);
    preimage[32..].copy_from_slice(&local_bytes);
    blake3_hash(&preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(entropy_floor(a, b), entropy_floor(a, b));
        assert_ne!(entropy_floor(a, b), entropy_floor(b, a));
    }

    #[test]
    fn timestamp_anchor_leg_deterministic() {
        let a = EntropyAnchor::TimestampUnixSecs {
            unix_secs: 1_700_000_000,
        };
        assert_eq!(a.entropy_leg(), a.entropy_leg());
        let b = EntropyAnchor::TimestampUnixSecs {
            unix_secs: 1_700_000_001,
        };
        assert_ne!(a.entropy_leg(), b.entropy_leg());
    }

    #[test]
    fn static_root_matches_raw_leg() {
        let h = [9u8; 32];
        assert_eq!(
            EntropyAnchor::StaticRoot(h).entropy_leg(),
            EntropyAnchor::AnchorHash(h).entropy_leg()
        );
    }
}
