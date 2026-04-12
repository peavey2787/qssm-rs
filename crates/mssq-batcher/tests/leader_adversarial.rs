//! Invalid-leader defenses: tampered limbs, wrong slot / QRNG, non-winner claims.

use mssq_batcher::{
    elect_leader, mssq_seed_from_anchor, verify_leader_attestation, BatcherError, LeaderAttestation,
};
use qssm_common::{MockKaspaAdapter, SovereignAnchor};

fn anchor_at_slot_10() -> MockKaspaAdapter {
    let mut a = MockKaspaAdapter::new([0xAB; 32]);
    a.set_slot(10);
    a.tick_fast();
    a
}

fn candidates() -> [[u8; 32]; 3] {
    [[1u8; 32], [2u8; 32], [3u8; 32]]
}

fn good_attestation(anchor: &MockKaspaAdapter, cands: &[[u8; 32]]) -> LeaderAttestation {
    let seed = mssq_seed_from_anchor(anchor);
    let winner = elect_leader(&seed, cands).unwrap();
    LeaderAttestation {
        slot: anchor.get_current_slot(),
        parent_block_hash: anchor.parent_block_hash_prev(),
        qrng_value: anchor.latest_qrng_value(),
        qrng_epoch: anchor.qrng_epoch(),
        claimed_leader_id: winner,
    }
}

#[test]
fn tampered_parent_block_hash_rejected() {
    let anchor = anchor_at_slot_10();
    let cands = candidates();
    let mut att = good_attestation(&anchor, &cands);
    att.parent_block_hash[0] ^= 0xFF;
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::MismatchedParentBlockHash));
}

#[test]
fn tampered_qrng_rejected() {
    let anchor = anchor_at_slot_10();
    let cands = candidates();
    let mut att = good_attestation(&anchor, &cands);
    att.qrng_value[31] ^= 1;
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::MismatchedQrng));
}

#[test]
fn wrong_slot_rejected() {
    let anchor = anchor_at_slot_10();
    let cands = candidates();
    let mut att = good_attestation(&anchor, &cands);
    att.slot = 11;
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::WrongSlot));
}

#[test]
fn stale_qrng_epoch_rejected() {
    let mut anchor = anchor_at_slot_10();
    let cands = candidates();
    let att_before = good_attestation(&anchor, &cands);
    anchor.advance_qrng_epoch();
    let err = verify_leader_attestation(&anchor, &att_before, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::MismatchedQrng));
}

#[test]
fn slot_10_attestation_fails_under_slot_11_anchor() {
    let mut anchor = anchor_at_slot_10();
    let cands = candidates();
    let att = good_attestation(&anchor, &cands);
    anchor.advance_slot();
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::WrongSlot));
}

#[test]
fn not_winning_leader_rejected() {
    let anchor = anchor_at_slot_10();
    let cands = candidates();
    let seed = mssq_seed_from_anchor(&anchor);
    let winner = elect_leader(&seed, &cands).unwrap();
    let mut loser = cands[0];
    if loser == winner {
        loser = cands[1];
    }
    let att = LeaderAttestation {
        slot: anchor.get_current_slot(),
        parent_block_hash: anchor.parent_block_hash_prev(),
        qrng_value: anchor.latest_qrng_value(),
        qrng_epoch: anchor.qrng_epoch(),
        claimed_leader_id: loser,
    };
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::NotWinningLeader));
}

#[test]
fn leader_not_in_candidate_set() {
    let anchor = anchor_at_slot_10();
    let cands = candidates();
    let mut att = good_attestation(&anchor, &cands);
    att.claimed_leader_id = [0xEE; 32];
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::LeaderNotInCandidateSet));
}

#[test]
fn qrng_only_change_changes_seed() {
    let mut a = anchor_at_slot_10();
    let s0 = mssq_seed_from_anchor(&a);
    a.advance_qrng_epoch();
    let s1 = mssq_seed_from_anchor(&a);
    assert_ne!(s0, s1);
}
