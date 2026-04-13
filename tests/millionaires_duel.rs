//! Integration: Millionaire’s Duel (Public-Difference ZK + ML-DSA + leaderboard SMT).
#![forbid(unsafe_code)]

#[cfg(not(debug_assertions))]
use std::time::Duration;
use std::time::Instant;

use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{KeyGen, MlDsa65, Seed};
use mssq_batcher::{
    apply_batch, elect_leader, mssq_seed_from_anchor, sort_lexicographical, BatcherError,
    LeaderAttestation, RollupState,
};
use qssm_common::{rollup_context_from_l1, Batch, L1Anchor, L2Transaction, MockKaspaAdapter};
use qssm_le::{prove_arithmetic, verify_lattice, PublicInstance, VerifyingKey, Witness};
use qssm_ref::millionaires_duel::{
    decode_millionaires_proof, duel_holds, encode_millionaires_proof, leaderboard_key,
    parse_leaderboard_leaf, prestige_payload, public_message_for_duel, MillionairesDuelVerifier,
};
use qssm_utils::{leader_attestation_signing_bytes, leader_id_from_ml_dsa_public_key};

fn anchor_finalized(slot: u64) -> MockKaspaAdapter {
    let mut a = MockKaspaAdapter::new([0x11; 32]);
    a.set_slot(slot);
    a.set_auto_finalize(false);
    a.tick_fast();
    a.finalize_volatile();
    a
}

fn sign_att(
    sk: &ml_dsa::SigningKey<MlDsa65>,
    anchor: &MockKaspaAdapter,
    leader_id: [u8; 32],
    ctx_digest: [u8; 32],
) -> LeaderAttestation {
    let seed = mssq_seed_from_anchor(anchor);
    let msg = leader_attestation_signing_bytes(
        anchor.get_current_slot(),
        &anchor.parent_block_hash_prev(),
        &anchor.latest_qrng_value(),
        anchor.qrng_epoch(),
        &seed,
        &ctx_digest,
        None,
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
        smt_root_pre: None,
    }
}

fn build_duel_tx(
    anchor: &MockKaspaAdapter,
    ctx_digest: [u8; 32],
    v_a: u64,
    v_b: u64,
    crs: [u8; 32],
) -> (L2Transaction, [[u8; 32]; 2]) {
    let sk_alice = MlDsa65::from_seed(&Seed::from([0xC1u8; 32]));
    let sk_bob = MlDsa65::from_seed(&Seed::from([0xC2u8; 32]));
    let id_a = leader_id_from_ml_dsa_public_key(sk_alice.verifying_key().encode().as_slice());
    let id_b = leader_id_from_ml_dsa_public_key(sk_bob.verifying_key().encode().as_slice());
    let cands = [id_a, id_b];
    let seed = mssq_seed_from_anchor(anchor);
    let winner = elect_leader(&seed, &cands).unwrap();
    let sk_winner = if winner == id_a { &sk_alice } else { &sk_bob };

    let public_m = public_message_for_duel(v_a, v_b).expect("balances");
    assert!(duel_holds(public_m));

    let vk = VerifyingKey::from_seed(crs);
    let public = PublicInstance { message: public_m };
    let witness = Witness {
        r: [0i32; qssm_le::N],
    };
    let (commitment, proof) = prove_arithmetic(&vk, &public, &witness, &ctx_digest).expect("prove");

    let att = sign_att(sk_winner, anchor, winner, ctx_digest);
    let wire = encode_millionaires_proof(&att, vk.crs_seed, public_m, &commitment, &proof);
    let tx = L2Transaction {
        id: leaderboard_key(),
        proof: wire,
        payload: prestige_payload(1),
    };
    (tx, cands)
}

#[test]
fn valid_duel_updates_leaderboard_leaf() {
    let anchor = anchor_finalized(9);
    let ctx = rollup_context_from_l1(&anchor);
    let d = ctx.digest();
    let (tx, cands) = build_duel_tx(&anchor, d, 1000, 500, [0x5Eu8; 32]);
    let batch = Batch {
        txs: sort_lexicographical(vec![tx]),
    };
    let mut state = RollupState::new();
    let r0 = state.root();
    let verifier = MillionairesDuelVerifier {
        expected_slot: anchor.get_current_slot(),
        candidates: cands.to_vec(),
    };
    apply_batch(&mut state, &batch, &ctx, &verifier).unwrap();
    assert_ne!(state.root(), r0);
    let leaf = state.smt.get(&leaderboard_key()).expect("leaf");
    let (wins, tag) = parse_leaderboard_leaf(leaf);
    assert_eq!(wins, 1);
    assert!(tag);
}

#[test]
fn duel_rejects_when_alice_not_richer() {
    let anchor = anchor_finalized(3);
    let ctx = rollup_context_from_l1(&anchor);
    let d = ctx.digest();
    let public_m = public_message_for_duel(400, 900).unwrap();
    assert!(!duel_holds(public_m));

    let sk_alice = MlDsa65::from_seed(&Seed::from([0xD1u8; 32]));
    let sk_bob = MlDsa65::from_seed(&Seed::from([0xD2u8; 32]));
    let id_a = leader_id_from_ml_dsa_public_key(sk_alice.verifying_key().encode().as_slice());
    let id_b = leader_id_from_ml_dsa_public_key(sk_bob.verifying_key().encode().as_slice());
    let cands = [id_a, id_b];
    let seed = mssq_seed_from_anchor(&anchor);
    let winner = elect_leader(&seed, &cands).unwrap();
    let sk_winner = if winner == id_a { &sk_alice } else { &sk_bob };

    let vk = VerifyingKey::from_seed([0x3Cu8; 32]);
    let public = PublicInstance { message: public_m };
    let witness = Witness {
        r: [0i32; qssm_le::N],
    };
    let (commitment, proof) = prove_arithmetic(&vk, &public, &witness, &d).expect("prove");
    let att = sign_att(sk_winner, &anchor, winner, d);
    let wire = encode_millionaires_proof(&att, vk.crs_seed, public_m, &commitment, &proof);
    let tx = L2Transaction {
        id: leaderboard_key(),
        proof: wire,
        payload: prestige_payload(1),
    };
    let batch = Batch {
        txs: sort_lexicographical(vec![tx]),
    };
    let mut state = RollupState::new();
    let r0 = state.root();
    let verifier = MillionairesDuelVerifier {
        expected_slot: anchor.get_current_slot(),
        candidates: cands.to_vec(),
    };
    let err = apply_batch(&mut state, &batch, &ctx, &verifier).unwrap_err();
    assert!(matches!(err, BatcherError::ProofVerificationFailed));
    assert_eq!(state.root(), r0);
}

#[test]
fn wrong_rollup_context_digest_rejects() {
    let anchor = anchor_finalized(5);
    let ctx = rollup_context_from_l1(&anchor);
    let d_good = ctx.digest();
    let (tx, cands) = build_duel_tx(&anchor, d_good, 1000, 500, [0x71u8; 32]);

    let mut bad_ctx = ctx;
    bad_ctx.finalized_blue_score = bad_ctx.finalized_blue_score.wrapping_add(1);
    assert_ne!(bad_ctx.digest(), d_good);

    let batch = Batch {
        txs: sort_lexicographical(vec![tx.clone()]),
    };
    let mut state = RollupState::new();
    let r0 = state.root();
    let verifier = MillionairesDuelVerifier {
        expected_slot: anchor.get_current_slot(),
        candidates: cands.to_vec(),
    };
    let err = apply_batch(&mut state, &batch, &bad_ctx, &verifier).unwrap_err();
    assert!(matches!(err, BatcherError::ProofVerificationFailed));
    assert_eq!(state.root(), r0);
}

#[test]
fn bad_signature_rejects() {
    let anchor = anchor_finalized(6);
    let ctx = rollup_context_from_l1(&anchor);
    let d = ctx.digest();
    let (mut tx, cands) = build_duel_tx(&anchor, d, 1000, 500, [0x72u8; 32]);
    let mut bundle = decode_millionaires_proof(&tx.proof).unwrap();
    if !bundle.attestation.signature.is_empty() {
        bundle.attestation.signature[0] ^= 0xFF;
    }
    tx.proof = encode_millionaires_proof(
        &bundle.attestation,
        bundle.crs_seed,
        bundle.public_message,
        &bundle.commitment,
        &bundle.proof,
    );
    let batch = Batch {
        txs: sort_lexicographical(vec![tx]),
    };
    let mut state = RollupState::new();
    let verifier = MillionairesDuelVerifier {
        expected_slot: anchor.get_current_slot(),
        candidates: cands.to_vec(),
    };
    let err = apply_batch(&mut state, &batch, &ctx, &verifier).unwrap_err();
    assert!(matches!(err, BatcherError::ProofVerificationFailed));
}

#[test]
fn verify_lattice_latency_release_god_mode() {
    let vk = VerifyingKey::from_seed([0x99; 32]);
    let public = PublicInstance {
        message: public_message_for_duel(1000, 500).unwrap(),
    };
    let witness = Witness {
        r: [0i32; qssm_le::N],
    };
    let ctx = [0xEEu8; 32];
    let (c, p) = prove_arithmetic(&vk, &public, &witness, &ctx).expect("prove");
    let t0 = Instant::now();
    let ok = verify_lattice(&vk, &public, &c, &p, &ctx).expect("verify");
    let latency = t0.elapsed();
    assert!(ok);

    if cfg!(debug_assertions) {
        println!(
            "DEBUG MODE: Verify took {:.3}ms. Switch to cargo test --release to see God-Mode speed.",
            latency.as_secs_f64() * 1000.0
        );
    }

    #[cfg(not(debug_assertions))]
    assert!(
        latency < Duration::from_millis(10),
        "Performance regression: verify_lattice took {:?}",
        latency
    );
}
