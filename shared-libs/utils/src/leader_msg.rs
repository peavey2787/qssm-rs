//! Canonical byte layout for ML-DSA–signed leader attestations.
#![forbid(unsafe_code)]

const PREFIX: &[u8] = b"MSSQ-LDR-ATTEST-v1\0";

/// Bytes signed by the leader’s ML-DSA key (verifier recomputes identically).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn leader_attestation_signing_bytes(
    slot: u64,
    parent_block_hash: &[u8; 32],
    qrng_value: &[u8; 32],
    qrng_epoch: u64,
    seed_k: &[u8; 32],
    rollup_context_digest: &[u8; 32],
    smt_root_pre: Option<&[u8; 32]>,
    claimed_leader_id: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(128);
    m.extend_from_slice(PREFIX);
    m.extend_from_slice(&slot.to_le_bytes());
    m.extend_from_slice(parent_block_hash);
    m.extend_from_slice(qrng_value);
    m.extend_from_slice(&qrng_epoch.to_le_bytes());
    m.extend_from_slice(seed_k);
    m.extend_from_slice(rollup_context_digest);
    match smt_root_pre {
        Some(r) => {
            m.push(1);
            m.extend_from_slice(r);
        }
        None => m.push(0),
    }
    m.extend_from_slice(claimed_leader_id);
    m
}

/// 32-byte public candidate id derived from ML-DSA public key encoding.
#[must_use]
pub fn leader_id_from_ml_dsa_public_key(pk_bytes: &[u8]) -> [u8; 32] {
    crate::hashing::blake3_hash(pk_bytes)
}
