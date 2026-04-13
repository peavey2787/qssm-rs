//! Millionaire’s Duel demo: **Public-Difference ZK Proof** integration (LE + ML-DSA + SMT).
//!
//! # V1.0 privacy (honest naming)
//! This demo is a **Public-Difference ZK Proof**: the Lyubashevsky layer hides the opening witness
//! and does not place Alice’s and Bob’s **absolute** balances in the public LE message, but the
//! encoded public scalar **`m` reveals the distance (difference)** between them under the shift
//! encoding—enough to decide the winner ([`duel_holds`] ⇔ Alice ahead). The on-chain verifier
//! accepts any in-range encoding from [`valid_duel_public_message`] (Alice ahead, Bob ahead, or tie).
//! **V2.0** may hide the delta (e.g. witness-hiding range / MS-style paths).
//!
//! # Constants
//! Leaderboard SMT key: [`leaderboard_key`] = `hash_domain(DOMAIN ‖ "MSSQ_DUEL_LEADERBOARD_V1")`.

#![forbid(unsafe_code)]

use mssq_batcher::{verify_leader_attestation_ctx, LeaderAttestation, ProofError, TxProofVerifier};
use qssm_common::L2Transaction;
use qssm_le::{
    verify_lattice, Commitment, LatticeProof, PublicInstance, RqPoly, VerifyingKey, MAX_MESSAGE, N,
};
use qssm_utils::RollupContext;

/// UTF-8 prestige tag stored in `payload[8..]` (up to 24 bytes land in the SMT leaf tail).
pub const WEALTHIEST_KNIGHT_TAG: &[u8] = b"WealthiestKnight";

/// `m = v_A - v_B + DUEL_SHIFT`; winner iff `m > DUEL_SHIFT`.
pub const DUEL_SHIFT: u64 = 1 << 20;
/// Maximum allowed balance for demo participants (`v_A`, `v_B` must be `< MAX_DEMO_BALANCE`).
pub const MAX_DEMO_BALANCE: u64 = 1 << 19;

const PROOF_MAGIC: &[u8] = b"MDUEL\x01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MillionairesDuelError {
    BalanceOutOfRange,
    MessageOutOfRange,
}

/// SMT key for duel leaderboard (domain-tagged BLAKE3).
#[must_use]
pub fn leaderboard_key() -> [u8; 32] {
    qssm_utils::duel_leaderboard_key()
}

pub fn public_message_for_duel(v_a: u64, v_b: u64) -> Result<u64, MillionairesDuelError> {
    if v_a >= MAX_DEMO_BALANCE || v_b >= MAX_DEMO_BALANCE {
        return Err(MillionairesDuelError::BalanceOutOfRange);
    }
    let diff = (v_a as i128) - (v_b as i128);
    let m = diff
        .checked_add(DUEL_SHIFT as i128)
        .ok_or(MillionairesDuelError::MessageOutOfRange)?;
    if m < 0 || m >= MAX_MESSAGE as i128 {
        return Err(MillionairesDuelError::MessageOutOfRange);
    }
    Ok(m as u64)
}

/// `true` iff the public duel scalar indicates **Alice’s balance exceeds Bob’s** (`m > DUEL_SHIFT`).
#[must_use]
pub fn duel_holds(public_m: u64) -> bool {
    public_m > DUEL_SHIFT
}

/// `true` iff `m` can be produced by [`public_message_for_duel`] for some `v_a, v_b < MAX_DEMO_BALANCE`
/// (covers Alice ahead, Bob ahead, and ties). Used by the verifier instead of [`duel_holds`] alone.
#[must_use]
pub fn valid_duel_public_message(m: u64) -> bool {
    if m >= MAX_MESSAGE {
        return false;
    }
    let m = i128::from(m);
    let shift = i128::from(DUEL_SHIFT);
    let diff = m - shift;
    let max_abs = i128::from(MAX_DEMO_BALANCE.saturating_sub(1));
    diff >= -max_abs && diff <= max_abs
}

/// First 8 bytes LE `u64` + [`WEALTHIEST_KNIGHT_TAG`].
#[must_use]
pub fn prestige_payload(wins: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + WEALTHIEST_KNIGHT_TAG.len());
    v.extend_from_slice(&wins.to_le_bytes());
    v.extend_from_slice(WEALTHIEST_KNIGHT_TAG);
    v
}

/// Parsed compound proof for one duel settlement transaction.
#[derive(Debug, Clone)]
pub struct MillionairesProofBundle {
    pub attestation: LeaderAttestation,
    pub crs_seed: [u8; 32],
    pub public_message: u64,
    pub commitment: Commitment,
    pub proof: LatticeProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofWireError {
    TooShort,
    BadMagic,
    BadLengths,
    Truncated,
}

fn push_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn read_u64(data: &[u8], i: &mut usize) -> Result<u64, ProofWireError> {
    if *i + 8 > data.len() {
        return Err(ProofWireError::Truncated);
    }
    let x = u64::from_le_bytes(data[*i..*i + 8].try_into().unwrap());
    *i += 8;
    Ok(x)
}

fn read_u32(data: &[u8], i: &mut usize) -> Result<u32, ProofWireError> {
    if *i + 4 > data.len() {
        return Err(ProofWireError::Truncated);
    }
    let x = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap());
    *i += 4;
    Ok(x)
}

fn read_bytes<'a>(data: &'a [u8], i: &mut usize, len: usize) -> Result<&'a [u8], ProofWireError> {
    if *i + len > data.len() {
        return Err(ProofWireError::Truncated);
    }
    let s = &data[*i..*i + len];
    *i += len;
    Ok(s)
}

fn push_poly(v: &mut Vec<u8>, p: &RqPoly) {
    for c in p.0 {
        v.extend_from_slice(&c.to_le_bytes());
    }
}

fn read_poly(data: &[u8], i: &mut usize) -> Result<RqPoly, ProofWireError> {
    let mut c = [0u32; N];
    for slot in &mut c {
        if *i + 4 > data.len() {
            return Err(ProofWireError::Truncated);
        }
        *slot = u32::from_le_bytes(data[*i..*i + 4].try_into().unwrap());
        *i += 4;
    }
    Ok(RqPoly(c))
}

fn encode_attestation(att: &LeaderAttestation) -> Vec<u8> {
    let mut v = Vec::new();
    push_u64(&mut v, att.slot);
    v.extend_from_slice(&att.parent_block_hash);
    v.extend_from_slice(&att.qrng_value);
    push_u64(&mut v, att.qrng_epoch);
    v.extend_from_slice(&att.claimed_leader_id);
    let pk_len: u32 = att
        .signing_public_key
        .len()
        .try_into()
        .expect("pk length fits u32");
    v.extend_from_slice(&pk_len.to_le_bytes());
    v.extend_from_slice(&att.signing_public_key);
    let sig_len: u32 = att.signature.len().try_into().expect("sig length fits u32");
    v.extend_from_slice(&sig_len.to_le_bytes());
    v.extend_from_slice(&att.signature);
    match &att.smt_root_pre {
        Some(r) => {
            v.push(1);
            v.extend_from_slice(r);
        }
        None => v.push(0),
    }
    v
}

fn decode_attestation(data: &[u8], i: &mut usize) -> Result<LeaderAttestation, ProofWireError> {
    let slot = read_u64(data, i)?;
    let parent_block_hash = read_bytes(data, i, 32)?
        .try_into()
        .map_err(|_| ProofWireError::Truncated)?;
    let qrng_value = read_bytes(data, i, 32)?
        .try_into()
        .map_err(|_| ProofWireError::Truncated)?;
    let qrng_epoch = read_u64(data, i)?;
    let claimed_leader_id = read_bytes(data, i, 32)?
        .try_into()
        .map_err(|_| ProofWireError::Truncated)?;
    let pk_len = read_u32(data, i)? as usize;
    let signing_public_key = read_bytes(data, i, pk_len)?.to_vec();
    let sig_len = read_u32(data, i)? as usize;
    let signature = read_bytes(data, i, sig_len)?.to_vec();
    let flag = read_bytes(data, i, 1)?[0];
    let smt_root_pre = if flag == 1 {
        Some(
            read_bytes(data, i, 32)?
                .try_into()
                .map_err(|_| ProofWireError::Truncated)?,
        )
    } else if flag == 0 {
        None
    } else {
        return Err(ProofWireError::BadLengths);
    };
    Ok(LeaderAttestation {
        slot,
        parent_block_hash,
        qrng_value,
        qrng_epoch,
        claimed_leader_id,
        signing_public_key,
        signature,
        smt_root_pre,
    })
}

/// Encode attestation + LE bundle for `tx.proof`.
#[must_use]
pub fn encode_millionaires_proof(
    att: &LeaderAttestation,
    crs_seed: [u8; 32],
    public_message: u64,
    commitment: &Commitment,
    proof: &LatticeProof,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(PROOF_MAGIC);
    v.extend_from_slice(&encode_attestation(att));
    v.extend_from_slice(&crs_seed);
    push_u64(&mut v, public_message);
    push_poly(&mut v, &commitment.0);
    push_poly(&mut v, &proof.t);
    push_poly(&mut v, &proof.z);
    v.extend_from_slice(&proof.challenge);
    v
}

/// Decode [`encode_millionaires_proof`] bytes.
pub fn decode_millionaires_proof(data: &[u8]) -> Result<MillionairesProofBundle, ProofWireError> {
    if data.len() < PROOF_MAGIC.len() {
        return Err(ProofWireError::TooShort);
    }
    if &data[..PROOF_MAGIC.len()] != PROOF_MAGIC {
        return Err(ProofWireError::BadMagic);
    }
    let mut i = PROOF_MAGIC.len();
    let attestation = decode_attestation(data, &mut i)?;
    let crs_seed = read_bytes(data, &mut i, 32)?
        .try_into()
        .map_err(|_| ProofWireError::Truncated)?;
    let public_message = read_u64(data, &mut i)?;
    let c0 = read_poly(data, &mut i)?;
    let t = read_poly(data, &mut i)?;
    let z = read_poly(data, &mut i)?;
    let challenge = read_bytes(data, &mut i, 32)?
        .try_into()
        .map_err(|_| ProofWireError::Truncated)?;
    if i != data.len() {
        return Err(ProofWireError::BadLengths);
    }
    Ok(MillionairesProofBundle {
        attestation,
        crs_seed,
        public_message,
        commitment: Commitment(c0),
        proof: LatticeProof { t, z, challenge },
    })
}

/// Verifies ML-DSA (via context) + LE + duel inequality + leaderboard `tx.id`.
pub struct MillionairesDuelVerifier {
    pub expected_slot: u64,
    pub candidates: Vec<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_duel_public_message_matches_public_message_for_duel() {
        for v_a in [0u64, 40, MAX_DEMO_BALANCE - 1] {
            for v_b in [0u64, 56, MAX_DEMO_BALANCE - 1] {
                let m = public_message_for_duel(v_a, v_b).expect("in range");
                assert!(
                    valid_duel_public_message(m),
                    "v_a={v_a} v_b={v_b} m={m}"
                );
            }
        }
    }

    #[test]
    fn valid_duel_public_message_rejects_out_of_band() {
        assert!(!valid_duel_public_message(MAX_MESSAGE));
        assert!(!valid_duel_public_message(DUEL_SHIFT + MAX_DEMO_BALANCE));
        // One more than max negative gap: |v_a - v_b| would need to be MAX_DEMO_BALANCE.
        assert!(!valid_duel_public_message(DUEL_SHIFT - MAX_DEMO_BALANCE));
    }
}

impl TxProofVerifier for MillionairesDuelVerifier {
    fn verify_tx(&self, tx: &L2Transaction, ctx: &RollupContext) -> Result<(), ProofError> {
        if tx.id != leaderboard_key() {
            return Err(ProofError::Invalid);
        }
        let bundle = decode_millionaires_proof(&tx.proof).map_err(|_| ProofError::Invalid)?;
        verify_leader_attestation_ctx(
            &bundle.attestation,
            ctx,
            self.expected_slot,
            &self.candidates,
        )
        .map_err(|_| ProofError::Invalid)?;
        if !valid_duel_public_message(bundle.public_message) {
            return Err(ProofError::Invalid);
        }
        let vk = VerifyingKey::from_seed(bundle.crs_seed);
        let public = PublicInstance {
            message: bundle.public_message,
        };
        let digest = ctx.digest();
        match verify_lattice(&vk, &public, &bundle.commitment, &bundle.proof, &digest) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(ProofError::Invalid),
        }
    }
}

/// Hex-encode `key` for `[SMT State] Slot:` lines (full 64 hex chars).
#[must_use]
pub fn format_slot_hex(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Space-separated uppercase hex for raw leaf bytes (Substack-friendly).
#[must_use]
pub fn format_leaf_data_hex(leaf: &[u8; 32]) -> String {
    leaf.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse wins from first 8 bytes and detect [`WEALTHIEST_KNIGHT_TAG`] in the tail.
pub fn parse_leaderboard_leaf(leaf: &[u8; 32]) -> (u64, bool) {
    let wins = u64::from_le_bytes(leaf[0..8].try_into().unwrap());
    let has_tag = leaf[8..]
        .windows(WEALTHIEST_KNIGHT_TAG.len())
        .any(|w| w == WEALTHIEST_KNIGHT_TAG);
    (wins, has_tag)
}
