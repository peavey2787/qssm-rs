#![cfg(feature = "ms-engine-b")]

//! Integration: [`MsGhostMirrorOp`] runs reference `qssm_ms::verify` under the shared poly-op API.

use qssm_gadget::poly_ops::{LatticePolyOp, MsGhostMirrorInput, MsGhostMirrorOp, PolyOpContext};
use qssm_gadget::r1cs::MockProver;
use qssm_ms::{commit, prove};

#[test]
fn ms_ghost_mirror_polyop_synthesize_after_prove() {
    let seed = [3u8; 32];
    let ledger = [4u8; 32];
    let rollup = [5u8; 32];
    let (root, salts) = commit(10, seed, ledger).expect("commit");
    let proof = prove(100, 50, &salts, ledger, b"ctx", &rollup).expect("prove");
    let op = MsGhostMirrorOp;
    let mut ctx = PolyOpContext::new("ms");
    let mut cs = MockProver::new();
    let out = op
        .synthesize_with_context(
            MsGhostMirrorInput {
                root,
                proof,
                binding_entropy: ledger,
                value: 100,
                target: 50,
                context: b"ctx".to_vec(),
                binding_context: rollup,
            },
            &mut cs,
            &mut ctx,
        )
        .expect("synthesize");
    assert_eq!(out.fs_v2_challenge.len(), 32);
    assert_eq!(out.root, root.0);
}
