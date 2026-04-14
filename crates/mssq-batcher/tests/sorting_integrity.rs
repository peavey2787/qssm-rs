//! Lexicographic sequencing, duplicate-ID batch semantics, proof gate.

use mssq_batcher::{
    apply_batch, sort_lexicographical, BatcherError, ProofError, RollupState, TxProofVerifier,
};
use qssm_common::{Batch, L2Transaction};
use qssm_utils::{RollupContext, StateMirrorTree};

fn tx(id_byte: u8, proof_tag: u8) -> L2Transaction {
    L2Transaction {
        id: [id_byte; 32],
        proof: vec![proof_tag], // replaced per test before apply_batch
        payload: {
            let mut p = vec![0x01];
            p.extend_from_slice(&1_u64.to_le_bytes());
            p
        },
    }
}

struct DenyAll;
impl TxProofVerifier for DenyAll {
    fn verify_tx(&self, _tx: &L2Transaction, _ctx: &RollupContext) -> Result<(), ProofError> {
        Err(ProofError::Invalid)
    }
}

struct AcceptAll;
impl TxProofVerifier for AcceptAll {
    fn verify_tx(&self, _tx: &L2Transaction, _ctx: &RollupContext) -> Result<(), ProofError> {
        Ok(())
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
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
}

#[test]
fn duplicate_tx_id_errors_before_proof() {
    let mut state = RollupState::new();
    let mut t = tx(7, 1);
    t.proof = state.smt.prove(&t.id).encode();
    let batch = Batch {
        txs: vec![t.clone(), t],
    };
    let ctx = RollupContext {
        finalized_block_hash: [0u8; 32],
        finalized_blue_score: 0,
        qrng_epoch: 0,
        qrng_value: [0u8; 32],
    };
    let err = apply_batch(&mut state, &batch, &ctx, &AcceptAll).unwrap_err();
    assert!(matches!(err, BatcherError::DuplicateTxId));
}

#[test]
fn failing_proof_aborts_batch() {
    let batch = Batch {
        txs: vec![tx(1, 1), tx(2, 2)],
    };
    let ctx = RollupContext {
        finalized_block_hash: [1u8; 32],
        finalized_blue_score: 1,
        qrng_epoch: 0,
        qrng_value: [2u8; 32],
    };
    let mut state = RollupState::new();
    let r0 = state.root();
    let err = apply_batch(&mut state, &batch, &ctx, &DenyAll).unwrap_err();
    assert!(matches!(err, BatcherError::ProofVerificationFailed));
    assert_eq!(state.root(), r0);
}

#[test]
fn accept_all_updates_root() {
    let mut state = RollupState::new();
    let mut t = tx(3, 1);
    t.proof = state.smt.prove(&t.id).encode();
    let batch = Batch { txs: vec![t] };
    let ctx = RollupContext {
        finalized_block_hash: [0u8; 32],
        finalized_blue_score: 0,
        qrng_epoch: 0,
        qrng_value: [0u8; 32],
    };
    let r0 = state.root();
    apply_batch(&mut state, &batch, &ctx, &AcceptAll).unwrap();
    assert_ne!(state.root(), r0);
}

#[test]
fn smt_empty_root_constant() {
    assert_eq!(StateMirrorTree::new().root(), StateMirrorTree::empty_root());
}
