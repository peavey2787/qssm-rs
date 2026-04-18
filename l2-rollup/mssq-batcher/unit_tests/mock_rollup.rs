//! Root smoke: finalized anchor -> ML-DSA leader -> MS + rollup context -> SMT state.

use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{KeyGen, MlDsa65, Seed};
use mssq_batcher::{
    apply_batch, elect_leader, rollup_context_from_l1, sort_lexicographical,
    verify_leader_attestation, LeaderAttestation, RollupState,
};
use qssm_traits::{Batch, L1Anchor, L1BatchSink, L2Transaction};
use qssm_examples::verify::AcceptAllTxVerifier;
use qssm_kaspa::MockKaspaAdapter;
use qssm_ms::{commit, prove, verify};
use qssm_utils::{leader_attestation_signing_bytes, leader_id_from_ml_dsa_public_key, mssq_seed_k};

#[test]
fn test_egalitarian_sequencing() {
    let mut anchor = MockKaspaAdapter::new([0x42; 32]);
    anchor.set_slot(10);
    anchor.tick_fast();

    let sk = MlDsa65::from_seed(&Seed::from([0x4Du8; 32]));
    let pk_enc = sk.verifying_key().encode();
    let pk_vec = pk_enc.as_slice().to_vec();
    let leader_id = leader_id_from_ml_dsa_public_key(pk_enc.as_slice());
    let candidates = [leader_id];

    let seed = mssq_seed_k(
        &anchor.parent_block_hash_prev(),
        &anchor.latest_qrng_value(),
    );
    let winner = elect_leader(&seed, &candidates).unwrap();
    assert_eq!(winner, leader_id);

    let ctx = rollup_context_from_l1(&anchor);
    let ctx_digest = ctx.digest();
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
    let sig_vec = sig.encode().as_slice().to_vec();

    let att = LeaderAttestation {
        slot: anchor.get_current_slot(),
        parent_block_hash: anchor.parent_block_hash_prev(),
        qrng_value: anchor.latest_qrng_value(),
        qrng_epoch: anchor.qrng_epoch(),
        claimed_leader_id: winner,
        signing_public_key: pk_vec,
        signature: sig_vec,
        smt_root_pre: None,
    };
    verify_leader_attestation(&anchor, &att, &candidates).unwrap();

    let ctx = rollup_context_from_l1(&anchor);
    let ctx_d = ctx.digest();
    let demo_ctx = b"mssq-demo-v1";
    let entropy = anchor.get_ledger_entropy();
    let (root_alice, salts_alice) = commit([7u8; 32], entropy).unwrap();
    let (_, salts_bob) = commit([9u8; 32], entropy).unwrap();
    let proof_alice = prove(10_000, 5_000, &salts_alice, entropy, demo_ctx, &ctx_d).unwrap();
    assert!(verify(
        root_alice,
        &proof_alice,
        entropy,
        10_000,
        5_000,
        demo_ctx,
        &ctx_d,
    ));
    assert!(prove(5_000, 10_000, &salts_bob, entropy, demo_ctx, &ctx_d).is_err());

    let id_alice = [1u8; 32];
    let id_bob = [2u8; 32];
    let mut builder = RollupState::new();
    let tx_alice = L2Transaction {
        id: id_alice,
        proof: builder.smt.prove(&id_alice).encode(),
        payload: b"alice".to_vec(),
    };
    apply_batch(
        &mut builder,
        &Batch {
            txs: vec![tx_alice.clone()],
        },
        &ctx,
        &AcceptAllTxVerifier,
    )
    .unwrap();
    let tx_bob = L2Transaction {
        id: id_bob,
        proof: builder.smt.prove(&id_bob).encode(),
        payload: b"bob".to_vec(),
    };
    let sorted_batch = Batch {
        txs: sort_lexicographical(vec![tx_alice, tx_bob]),
    };
    let mut state = RollupState::new();
    let r0 = state.root();
    apply_batch(&mut state, &sorted_batch, &ctx, &AcceptAllTxVerifier).unwrap();
    assert_ne!(state.root(), r0);

    anchor.post_batch(&sorted_batch).unwrap();
    assert_eq!(anchor.posted_batches().len(), 1);
}
