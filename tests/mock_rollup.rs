//! Root smoke: mock anchor → PQ leader attestation → MS inequality → lex sort → deterministic state.

use mssq_batcher::{
    apply_batch, elect_leader, sort_lexicographical, verify_leader_attestation, LeaderAttestation,
};
use qssm_common::{Batch, L2Transaction, MockKaspaAdapter, SmtRoot, SovereignAnchor};
use qssm_ms::{commit, prove, verify};

#[test]
fn test_egalitarian_sequencing() {
    let mut anchor = MockKaspaAdapter::new([0x42; 32]);
    anchor.set_slot(10);
    anchor.tick_fast();

    let candidates = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let seed = mssq_batcher::mssq_seed_from_anchor(&anchor);
    let winner = elect_leader(&seed, &candidates).unwrap();
    let att = LeaderAttestation {
        slot: anchor.get_current_slot(),
        parent_block_hash: anchor.parent_block_hash_prev(),
        qrng_value: anchor.latest_qrng_value(),
        qrng_epoch: anchor.qrng_epoch(),
        claimed_leader_id: winner,
    };
    verify_leader_attestation(&anchor, &att, &candidates).unwrap();

    let ctx = b"mssq-demo-v1";
    let entropy = anchor.get_ledger_entropy();
    let (root_alice, salts_alice) = commit(10_000u64, [7u8; 32], entropy).unwrap();
    let (_, salts_bob) = commit(5_000u64, [9u8; 32], entropy).unwrap();
    let proof_alice = prove(10_000, 5_000, &salts_alice, entropy, ctx).unwrap();
    assert!(verify(
        root_alice,
        &proof_alice,
        entropy,
        10_000,
        5_000,
        ctx
    ));
    assert!(prove(5_000, 10_000, &salts_bob, entropy, ctx).is_err());

    let sorted_batch = Batch {
        txs: sort_lexicographical(vec![
            L2Transaction {
                id: [2u8; 32],
                proof: vec![1, 2, 3],
                payload: b"bob".to_vec(),
            },
            L2Transaction {
                id: [1u8; 32],
                proof: vec![4, 5],
                payload: b"alice".to_vec(),
            },
        ]),
    };
    let root0 = SmtRoot([0u8; 32]);
    let r1 = apply_batch(root0, &sorted_batch).unwrap();
    assert_eq!(r1, apply_batch(root0, &sorted_batch).unwrap());

    anchor.post_batch(&sorted_batch).unwrap();
    assert_eq!(anchor.posted_batches().len(), 1);
}
