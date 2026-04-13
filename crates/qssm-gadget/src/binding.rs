//! Phase 3 / **8** — Sovereign Digest → **30‑bit** limb for **`qssm-le`** `PublicInstance::message`.
//!
//! Preimage order (normative, **v2.0**): **`hash_domain(DOMAIN_SOVEREIGN_LIMB_V2, &[root32, rollup32, metadata])`**  
//! where **`metadata`** = **`encode_proof_metadata_v2`** = v1 fields **`‖ sovereign_entropy[32] ‖ nist_flag`**.  
//! Limb: first **30** bits of the digest in **LE** order via [`crate::bits::to_le_bits`] / [`crate::bits::from_le_bits`] only — **no** `& ((1<<30)-1)` or **`% 2^30`** on the public witness path.

use qssm_utils::hashing::hash_domain;

use crate::bits::{from_le_bits, to_le_bits};

/// Historical domain (**v1.0**); **v2.0** is normative for [`SovereignWitness`].
pub const DOMAIN_SOVEREIGN_LIMB_V1: &str = "QSSM-SOVEREIGN-LIMB-v1.0";

/// **Normative** sovereign limb domain (**includes Phase 8 entropy in metadata blob**).
pub const DOMAIN_SOVEREIGN_LIMB_V2: &str = "QSSM-SOVEREIGN-LIMB-v2.0";

/// 32‑byte output of [`sovereign_digest`].
pub type SovereignDigest = [u8; 32];

/// Engine B v1 metadata prefix: **`n ‖ k ‖ bit_at_k ‖ challenge[32]`** (fixed order).
#[must_use]
pub fn encode_proof_metadata_v1(n: u8, k: u8, bit_at_k: u8, challenge: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(35);
    v.push(n);
    v.push(k);
    v.push(bit_at_k);
    v.extend_from_slice(challenge);
    v
}

/// **Phase 8** — extends v1 with **`sovereign_entropy[32]`** and **`nist_included`** flag byte (**0** / **1**).
#[must_use]
pub fn encode_proof_metadata_v2(
    n: u8,
    k: u8,
    bit_at_k: u8,
    challenge: &[u8; 32],
    sovereign_entropy: &[u8; 32],
    nist_included: bool,
) -> Vec<u8> {
    let mut v = encode_proof_metadata_v1(n, k, bit_at_k, challenge);
    v.extend_from_slice(sovereign_entropy);
    v.push(u8::from(nist_included));
    v
}

/// **`SovereignDigest = hash_domain(DOMAIN_SOVEREIGN_LIMB_V2, &[root, rollup, metadata])`**.
#[must_use]
pub fn sovereign_digest(
    root: &[u8; 32],
    rollup_context_digest: &[u8; 32],
    proof_metadata: &[u8],
) -> SovereignDigest {
    hash_domain(
        DOMAIN_SOVEREIGN_LIMB_V2,
        &[
            root.as_slice(),
            rollup_context_digest.as_slice(),
            proof_metadata,
        ],
    )
}

/// First **30** LE bits of **`digest`** (low **32** bits of the **256‑bit LE** integer = LE **`u32`** from first **4** bytes), then pad to **`[bool;32]`** and [`from_le_bits`].
///
/// Returns **(padded limb witness bits, message_limb)** with **`message_limb < 2^30`**.
#[must_use]
pub fn message_limb_from_sovereign_digest_normative(digest: &SovereignDigest) -> ([bool; 32], u64) {
    let w = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let lane = to_le_bits(w);
    let mut padded = [false; 32];
    for i in 0..30 {
        padded[i] = lane[i];
    }
    padded[30] = false;
    padded[31] = false;
    let m = from_le_bits(&padded);
    (padded, u64::from(m))
}

/// Full binding witness: inputs, digest, LE limb bits, **`message_limb`**, and Phase 8 entropy metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SovereignWitness {
    pub root: [u8; 32],
    pub rollup_context_digest: [u8; 32],
    pub n: u8,
    pub k: u8,
    pub bit_at_k: u8,
    pub challenge: [u8; 32],
    /// Final **32** bytes fed into sovereign metadata (**floor ⊕ NIST** when booster applies).
    pub sovereign_entropy: [u8; 32],
    /// **`true`** iff NIST beacon pulse was applied (**200 OK** within timeout).
    pub nist_included: bool,
    pub proof_metadata: Vec<u8>,
    pub domain_tag: &'static str,
    pub digest: SovereignDigest,
    /// Padded witness: indices **0..30** are the normative limb bits; **30..32** are **false**.
    pub limb_bits: [bool; 32],
    pub message_limb: u64,
}

impl SovereignWitness {
    /// Build from hashed inputs (computes **`digest`** and **normative** limb).
    #[must_use]
    pub fn bind(
        root: [u8; 32],
        rollup_context_digest: [u8; 32],
        n: u8,
        k: u8,
        bit_at_k: u8,
        challenge: [u8; 32],
        sovereign_entropy: [u8; 32],
        nist_included: bool,
    ) -> Self {
        let proof_metadata = encode_proof_metadata_v2(
            n,
            k,
            bit_at_k,
            &challenge,
            &sovereign_entropy,
            nist_included,
        );
        let digest = sovereign_digest(&root, &rollup_context_digest, &proof_metadata);
        let (limb_bits, message_limb) = message_limb_from_sovereign_digest_normative(&digest);
        Self {
            root,
            rollup_context_digest,
            n,
            k,
            bit_at_k,
            challenge,
            sovereign_entropy,
            nist_included,
            proof_metadata,
            domain_tag: DOMAIN_SOVEREIGN_LIMB_V2,
            digest,
            limb_bits,
            message_limb,
        }
    }

    /// Recompute **`hash_domain`** and normative limb; check **`digest`**, **`message_limb`**, **`limb_bits`**, metadata encoding.
    pub fn validate(&self) -> bool {
        if self.domain_tag != DOMAIN_SOVEREIGN_LIMB_V2 {
            return false;
        }
        let expect_meta = encode_proof_metadata_v2(
            self.n,
            self.k,
            self.bit_at_k,
            &self.challenge,
            &self.sovereign_entropy,
            self.nist_included,
        );
        if expect_meta != self.proof_metadata {
            return false;
        }
        let recomputed = sovereign_digest(
            &self.root,
            &self.rollup_context_digest,
            &self.proof_metadata,
        );
        if recomputed != self.digest {
            return false;
        }
        let (lb, m) = message_limb_from_sovereign_digest_normative(&self.digest);
        lb == self.limb_bits && m == self.message_limb
    }

    /// Phase 6: flat index-based JSON — **public** `root`, `digest`, **`message_limb_u30`**, **`nist_included`**, plus **private** limb bit-wires and preimage aux hex.
    #[must_use]
    pub fn to_prover_json(&self) -> String {
        serde_json::to_string_pretty(&crate::prover_json::sovereign_witness_value(self))
            .expect("sovereign witness JSON")
    }
}

/// Derive **`message_limb`** from a **full v2** metadata blob (see **`encode_proof_metadata_v2`**).
#[must_use]
pub fn sovereign_message_limb_v1(
    root: &[u8; 32],
    rollup_context_digest: &[u8; 32],
    proof_metadata: &[u8],
) -> u64 {
    let digest = sovereign_digest(root, rollup_context_digest, proof_metadata);
    message_limb_from_sovereign_digest_normative(&digest).1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_is_below_2_pow_30() {
        let r = [7u8; 32];
        let ctx = [9u8; 32];
        let ch = [3u8; 32];
        let ent = [0u8; 32];
        let w = SovereignWitness::bind(r, ctx, 1, 2, 0, ch, ent, false);
        assert!(w.message_limb < (1u64 << 30));
    }

    #[test]
    fn sovereign_witness_round_trip_validate() {
        let root = [0xabu8; 32];
        let ctx = [0xcd; 32];
        let ch = [0xee; 32];
        let ent = [0x11; 32];
        let w = SovereignWitness::bind(root, ctx, 0, 5, 1, ch, ent, true);
        assert!(w.validate());
    }

    #[test]
    fn sovereign_to_prover_json_roundtrip() {
        let root = [0x01u8; 32];
        let ctx = [0x02; 32];
        let ch = [0x03; 32];
        let ent = [0x04; 32];
        let w = SovereignWitness::bind(root, ctx, 1, 0, 0, ch, ent, false);
        let v: serde_json::Value = serde_json::from_str(&w.to_prover_json()).expect("parse");
        assert_eq!(v["kind"], "SovereignWitnessV1");
        assert_eq!(
            v["public"]["message_limb_u30"],
            serde_json::json!(w.message_limb)
        );
        assert_eq!(v["public"]["nist_included"], serde_json::json!(false));
    }
}
