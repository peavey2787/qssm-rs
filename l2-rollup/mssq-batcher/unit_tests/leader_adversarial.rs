//! Invalid-leader defenses: tampered limbs, wrong slot / QRNG, ML-DSA failures.

use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{KeyGen, MlDsa65, Seed};
use mssq_batcher::{
    elect_leader, mssq_seed_from_anchor, rollup_context_from_l1, verify_leader_attestation,
    BatcherError, LeaderAttestation,
};
use qssm_traits::L1Anchor;
use qssm_kaspa::MockKaspaAdapter;
use qssm_utils::{leader_attestation_signing_bytes, leader_id_from_ml_dsa_public_key};

fn signing_key_from_test_seed(byte: u8) -> ml_dsa::SigningKey<MlDsa65> {
    let mut s = [byte; 32];
    s[1] = byte.wrapping_add(1);
    MlDsa65::from_seed(&Seed::from(s))
}

fn anchor_at_slot_10() -> MockKaspaAdapter {
    let mut a = MockKaspaAdapter::new([0xAB; 32]);
    a.set_slot(10);
    a.tick_fast();
    a
}

fn sign_attestation(
    sk: &ml_dsa::SigningKey<MlDsa65>,
    anchor: &MockKaspaAdapter,
    leader_id: [u8; 32],
    smt: Option<[u8; 32]>,
) -> LeaderAttestation {
    let seed = mssq_seed_from_anchor(anchor);
    let ctx = rollup_context_from_l1(anchor);
    let d = ctx.digest();
    let msg = leader_attestation_signing_bytes(
        anchor.get_current_slot(),
        &anchor.parent_block_hash_prev(),
        &anchor.latest_qrng_value(),
        anchor.qrng_epoch(),
        &seed,
        &d,
        smt.as_ref(),
        &leader_id,
    );
    let sig = sk.sign(&msg);
    let pk = sk.verifying_key().encode();
    LeaderAttestation {
        slot: anchor.get_current_slot(),
        parent_block_hash: anchor.parent_block_hash_prev(),
        qrng_value: anchor.latest_qrng_value(),
        qrng_epoch: anchor.qrng_epoch(),
        claimed_leader_id: leader_id,
        signing_public_key: pk.as_slice().to_vec(),
        signature: sig.encode().as_slice().to_vec(),
        smt_root_pre: smt,
    }
}

fn setup_leader() -> (
    MockKaspaAdapter,
    ml_dsa::SigningKey<MlDsa65>,
    [u8; 32],
    [[u8; 32]; 1],
) {
    let anchor = anchor_at_slot_10();
    let sk = signing_key_from_test_seed(0xC1);
    let pk = sk.verifying_key().encode();
    let id = leader_id_from_ml_dsa_public_key(pk.as_slice());
    let cands = [id];
    (anchor, sk, id, cands)
}

#[test]
fn tampered_parent_block_hash_rejected() {
    let (anchor, sk, id, cands) = setup_leader();
    let mut att = sign_attestation(&sk, &anchor, id, None);
    att.parent_block_hash[0] ^= 0xFF;
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::MismatchedParentBlockHash));
}

#[test]
fn tampered_qrng_rejected() {
    let (anchor, sk, id, cands) = setup_leader();
    let mut att = sign_attestation(&sk, &anchor, id, None);
    att.qrng_value[31] ^= 1;
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::MismatchedQrng));
}

#[test]
fn wrong_slot_rejected() {
    let (anchor, sk, id, cands) = setup_leader();
    let mut att = sign_attestation(&sk, &anchor, id, None);
    att.slot = 11;
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::WrongSlot));
}

#[test]
fn stale_qrng_epoch_rejected() {
    let mut anchor = anchor_at_slot_10();
    let sk = signing_key_from_test_seed(0xC2);
    let id = leader_id_from_ml_dsa_public_key(sk.verifying_key().encode().as_slice());
    let cands = [id];
    let att = sign_attestation(&sk, &anchor, id, None);
    anchor.advance_qrng_epoch();
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::MismatchedQrng));
}

#[test]
fn slot_10_attestation_fails_under_slot_11_anchor() {
    let mut anchor = anchor_at_slot_10();
    let sk = signing_key_from_test_seed(0xC2);
    let id = leader_id_from_ml_dsa_public_key(sk.verifying_key().encode().as_slice());
    let cands = [id];
    let att = sign_attestation(&sk, &anchor, id, None);
    anchor.advance_slot();
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::WrongSlot));
}

#[test]
fn not_winning_leader_rejected() {
    let anchor = anchor_at_slot_10();
    let sk_a = signing_key_from_test_seed(0xA1);
    let sk_b = signing_key_from_test_seed(0xB2);
    let id_a = leader_id_from_ml_dsa_public_key(sk_a.verifying_key().encode().as_slice());
    let id_b = leader_id_from_ml_dsa_public_key(sk_b.verifying_key().encode().as_slice());
    let cands = [id_a, id_b];
    let seed = mssq_seed_from_anchor(&anchor);
    let winner = elect_leader(&seed, &cands).unwrap();
    let loser = if winner == id_a { id_b } else { id_a };
    let sk_loser = if winner == id_a { &sk_b } else { &sk_a };
    let att = sign_attestation(sk_loser, &anchor, loser, None);
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::NotWinningLeader));
}

#[test]
fn leader_not_in_candidate_set() {
    let (anchor, sk, id, cands) = setup_leader();
    let mut att = sign_attestation(&sk, &anchor, id, None);
    att.claimed_leader_id = [0xEE; 32];
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::LeaderNotInCandidateSet));
}

#[test]
fn leader_key_id_mismatch_rejected() {
    let (anchor, sk, id, cands) = setup_leader();
    let mut att = sign_attestation(&sk, &anchor, id, None);
    let sk_other = signing_key_from_test_seed(0x77);
    att.signing_public_key = sk_other.verifying_key().encode().as_slice().to_vec();
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::LeaderKeyIdMismatch));
}

#[test]
fn invalid_signature_rejected() {
    let (anchor, sk, id, cands) = setup_leader();
    let mut att = sign_attestation(&sk, &anchor, id, None);
    att.signature[0] ^= 0xFF;
    let err = verify_leader_attestation(&anchor, &att, &cands).unwrap_err();
    assert!(matches!(err, BatcherError::InvalidSignature));
}

#[test]
fn finalized_parent_stable_until_promoted() {
    let mut a = MockKaspaAdapter::new([1u8; 32]);
    a.set_slot(5);
    a.set_auto_finalize(false);
    let h0 = a.parent_block_hash_prev();
    a.tick_fast();
    assert_eq!(a.parent_block_hash_prev(), h0);
    a.finalize_volatile();
    assert_ne!(a.parent_block_hash_prev(), h0);
}

#[test]
fn qrng_only_change_changes_seed() {
    let mut a = anchor_at_slot_10();
    let s0 = mssq_seed_from_anchor(&a);
    a.advance_qrng_epoch();
    let s1 = mssq_seed_from_anchor(&a);
    assert_ne!(s0, s1);
}
