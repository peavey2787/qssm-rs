#![cfg(feature = "ms-engine-b")]

use qssm_gadget::poly_ops::{
    EngineABindingInput, EngineABindingOp, LatticePolyOp, MsGhostMirrorInput, MsGhostMirrorOp,
    PolyOpContext,
};
use qssm_gadget::r1cs::MockProver;
use qssm_ms::{commit, prove};
use qssm_utils::blake3_hash;

fn relation_digest(value: u64, target: u64, challenge: [u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(48);
    v.extend_from_slice(&value.to_le_bytes());
    v.extend_from_slice(&target.to_le_bytes());
    v.extend_from_slice(&challenge);
    blake3_hash(&v)
}

fn baseline_inputs() -> (EngineABindingInput, u64, u64, Vec<u8>) {
    let seed = [3u8; 32];
    let ledger = [4u8; 32];
    let rollup = [5u8; 32];
    let state_root = blake3_hash(b"state-root");
    let value = 100u64;
    let target = 50u64;
    let context = b"ctx".to_vec();

    let (root, salts) = commit(10, seed, ledger).expect("commit");
    let proof = prove(value, target, &salts, ledger, &context, &rollup).expect("prove");

    // Baseline: Engine B verifies with same entropy/context.
    let ms = MsGhostMirrorOp;
    let mut ms_ctx = PolyOpContext::new("ms");
    let mut ms_cs = MockProver::new();
    ms.synthesize_with_context(
        MsGhostMirrorInput {
            root,
            proof: proof.clone(),
            binding_entropy: ledger,
            value,
            target,
            context: context.clone(),
            binding_context: rollup,
        },
        &mut ms_cs,
        &mut ms_ctx,
    )
    .expect("ms verify path");

    let mut input = EngineABindingInput {
        state_root,
        ms_root: root.0,
        relation_digest: relation_digest(value, target, proof.challenge),
        ms_fs_v2_challenge: proof.challenge,
        binding_context: rollup,
        device_entropy_link: ledger,
        claimed_seam_commitment: [0u8; 32],
    };
    input.claimed_seam_commitment = EngineABindingOp::commitment_digest(&input);
    (input, value, target, context)
}

#[test]
fn engine_a_binding_rejects_tweaked_device_entropy_link() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.device_entropy_link[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = MockProver::new();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "tampered entropy link must fail seam verify");
}

#[test]
fn engine_a_binding_rejects_tweaked_state_root() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.state_root[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = MockProver::new();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "tampered state root must fail seam verify");
}
