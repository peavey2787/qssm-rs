use mssq_batcher::{apply_batch, BatcherError, ProofError, RollupState, TxProofVerifier};
use qssm_common::{Batch, L2Transaction};
use qssm_utils::RollupContext;

struct AcceptAll;
impl TxProofVerifier for AcceptAll {
    fn verify_tx(&self, _tx: &L2Transaction, _ctx: &RollupContext) -> Result<(), ProofError> {
        Ok(())
    }
}

fn ctx() -> RollupContext {
    RollupContext {
        finalized_block_hash: [0u8; 32],
        finalized_blue_score: 0,
        qrng_epoch: 0,
        qrng_value: [0u8; 32],
    }
}

#[test]
fn second_conflicting_proof_for_same_leaf_is_rejected() {
    let mut state = RollupState::new();
    let leaf = [9u8; 32];
    let stale_proof = state.smt.prove(&leaf).encode();

    let tx1 = L2Transaction {
        id: leaf,
        proof: stale_proof.clone(),
        payload: {
            let mut p = vec![0x01];
            p.extend_from_slice(&5_u64.to_le_bytes());
            p
        },
    };
    apply_batch(&mut state, &Batch { txs: vec![tx1] }, &ctx(), &AcceptAll).expect("first tx");

    let tx2 = L2Transaction {
        id: leaf,
        proof: stale_proof,
        payload: {
            let mut p = vec![0x01];
            p.extend_from_slice(&7_u64.to_le_bytes());
            p
        },
    };
    let err = apply_batch(&mut state, &Batch { txs: vec![tx2] }, &ctx(), &AcceptAll)
        .expect_err("stale proof should fail");
    assert!(matches!(err, BatcherError::InvalidMerkleProof));
}
