//! Lexicographic sequencing and duplicate-ID batch semantics.

use mssq_batcher::{apply_batch, sort_lexicographical, BatcherError};
use qssm_common::{Batch, L2Transaction, SmtRoot};

fn tx(id_byte: u8, proof_tag: u8) -> L2Transaction {
    L2Transaction {
        id: [id_byte; 32],
        proof: vec![proof_tag],
        payload: vec![id_byte],
    }
}

#[test]
fn three_permutations_sort_to_same_order() {
    let a = tx(1, 10);
    let b = tx(2, 20);
    let c = tx(3, 30);
    let p1 = vec![a.clone(), b.clone(), c.clone()];
    let p2 = vec![c.clone(), a.clone(), b.clone()];
    let p3 = vec![b.clone(), c, a];
    let s1 = sort_lexicographical(p1);
    let s2 = sort_lexicographical(p2);
    let s3 = sort_lexicographical(p3);
    assert_eq!(s1.len(), 3);
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
    assert_eq!(s1[0].id, [1u8; 32]);
    assert_eq!(s1[1].id, [2u8; 32]);
    assert_eq!(s1[2].id, [3u8; 32]);
}

#[test]
fn duplicate_tx_id_in_batch_errors_state_stays_unreachable() {
    let t = tx(7, 1);
    let batch = Batch {
        txs: vec![t.clone(), t],
    };
    let root0 = SmtRoot([0u8; 32]);
    let err = apply_batch(root0, &batch).unwrap_err();
    assert!(matches!(err, BatcherError::DuplicateTxId));
    // Same root if caller aborts on error (no partial apply API).
    let ok_batch = Batch {
        txs: vec![tx(7, 1), tx(8, 2)],
    };
    let r = apply_batch(root0, &ok_batch).unwrap();
    assert_ne!(r.0, root0.0);
}
