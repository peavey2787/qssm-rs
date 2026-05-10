//! Backend conformance tests: structural constraint system that tracks allocations
//! and constraint counts for regression detection.

use qssm_gadget::{
    ConstraintSystem, EngineABindingInput, EngineABindingOp, LatticePolyOp, PolyOpContext, VarId,
    VarKind,
};
use qssm_ms::{commit_value_v2, prove_predicate_only_v2, PredicateOnlyStatementV2};
use qssm_utils::blake3_hash;
use qssm_utils::hashing::{hash_domain, DOMAIN_MS};

/// A constraint system that counts allocations and constraint invocations.
#[derive(Debug, Default)]
struct CountingConstraintSystem {
    next_var: u32,
    xor_count: u32,
    full_adder_count: u32,
    equal_count: u32,
}

impl ConstraintSystem for CountingConstraintSystem {
    fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
        let id = VarId(self.next_var);
        self.next_var = self.next_var.saturating_add(1);
        id
    }

    fn enforce_xor(&mut self, _x: VarId, _y: VarId, _and_xy: VarId, _z: VarId) {
        self.xor_count += 1;
    }

    fn enforce_full_adder(&mut self, _a: VarId, _b: VarId, _cin: VarId, _sum: VarId, _cout: VarId) {
        self.full_adder_count += 1;
    }

    fn enforce_equal(&mut self, _a: VarId, _b: VarId) {
        self.equal_count += 1;
    }
}

fn bitness_global_challenges_digest(challenges: &[[u8; 32]]) -> [u8; 32] {
    let len_bytes = (challenges.len() as u32).to_le_bytes();
    let mut chunks: Vec<&[u8]> = Vec::with_capacity(challenges.len() + 1);
    chunks.push(&len_bytes);
    for challenge in challenges {
        chunks.push(challenge.as_slice());
    }
    hash_domain(DOMAIN_MS, &chunks)
}

fn baseline_inputs() -> EngineABindingInput {
    let seed = [3u8; 32];
    let binding_entropy = [4u8; 32];
    let rollup = [5u8; 32];
    let state_root = blake3_hash(b"state-root");
    let value = u64::MAX;
    let target = u64::MAX - 1;
    let context = b"ctx".to_vec();

    let (commitment, witness) = commit_value_v2(value, seed, binding_entropy).expect("commit v2");
    let statement =
        PredicateOnlyStatementV2::new(commitment, target, binding_entropy, rollup, context.clone());
    let proof = prove_predicate_only_v2(&statement, &witness, [7u8; 32]).expect("prove v2");
    let bitness = proof
        .bitness_global_challenges()
        .expect("bitness global challenges");
    let comparison = proof
        .comparison_global_challenge()
        .expect("comparison global challenge");

    let mut input = EngineABindingInput {
        state_root,
        ms_v2_statement_digest: *proof.statement_digest(),
        ms_v2_result_bit: u8::from(proof.result()),
        ms_v2_bitness_global_challenges_digest: bitness_global_challenges_digest(&bitness),
        ms_v2_comparison_global_challenge: comparison,
        ms_v2_transcript_digest: proof.transcript_digest(),
        binding_context: rollup,
        device_entropy_link: binding_entropy,
        truth_digest: blake3_hash(b"truth-digest-conformance"),
        entropy_anchor: blake3_hash(b"entropy-anchor-conformance"),
        claimed_seam_commitment: [0u8; 32],
        require_ms_verified: true,
    };
    input.claimed_seam_commitment = EngineABindingOp::commitment_digest(&input);
    input
}

#[test]
fn valid_baseline_accepted_by_counting_cs() {
    let input = baseline_inputs();
    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("conformance");
    let mut cs = CountingConstraintSystem::default();
    let res = op.synthesize_with_context(input, &mut cs, &mut ctx);
    assert!(res.is_ok(), "valid baseline must be accepted: {res:?}");
}

#[test]
fn tampered_witness_rejected_by_counting_cs() {
    let mut input = baseline_inputs();
    input.state_root[0] ^= 0xFF;
    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("conformance");
    let mut cs = CountingConstraintSystem::default();
    let res = op.synthesize_with_context(input, &mut cs, &mut ctx);
    assert!(res.is_err(), "tampered state_root must be rejected");
}

#[test]
fn constraint_count_regression() {
    let input = baseline_inputs();
    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("conformance");
    let mut cs = CountingConstraintSystem::default();
    let _out = op
        .synthesize_with_context(input, &mut cs, &mut ctx)
        .expect("baseline must pass");

    // The seam operator uses hash-based commit-then-open, not R1CS constraints.
    // Pin the expected structural counts: any change indicates a layout regression.
    assert_eq!(
        cs.next_var, 0,
        "seam operator must not allocate R1CS variables"
    );
    assert_eq!(
        cs.xor_count, 0,
        "seam operator must not emit XOR constraints"
    );
    assert_eq!(
        cs.full_adder_count, 0,
        "seam operator must not emit full-adder constraints"
    );
    assert_eq!(
        cs.equal_count, 0,
        "seam operator must not emit equality constraints"
    );

    let total = cs.xor_count + cs.full_adder_count + cs.equal_count;
    assert_eq!(
        total, 0,
        "seam operator total constraint count must be zero"
    );

    // The seam binding output must contain non-zero digests.
    assert_ne!(
        _out.seam_commitment_digest, [0u8; 32],
        "seam commitment digest must be non-zero"
    );
    assert_ne!(
        _out.seam_open_digest, [0u8; 32],
        "seam open digest must be non-zero"
    );
    assert_ne!(
        _out.seam_binding_digest, [0u8; 32],
        "seam binding digest must be non-zero"
    );
}

#[test]
fn deterministic_constraint_layout() {
    let input1 = baseline_inputs();
    let input2 = baseline_inputs();

    let mut cs1 = CountingConstraintSystem::default();
    let mut cs2 = CountingConstraintSystem::default();
    let mut ctx1 = PolyOpContext::new("det1");
    let mut ctx2 = PolyOpContext::new("det2");
    let op = EngineABindingOp;

    let _ = op
        .synthesize_with_context(input1, &mut cs1, &mut ctx1)
        .unwrap();
    let _ = op
        .synthesize_with_context(input2, &mut cs2, &mut ctx2)
        .unwrap();

    assert_eq!(
        cs1.next_var, cs2.next_var,
        "variable count must be deterministic"
    );
    assert_eq!(
        cs1.xor_count, cs2.xor_count,
        "xor constraint count must be deterministic"
    );
    assert_eq!(
        cs1.full_adder_count, cs2.full_adder_count,
        "full_adder constraint count must be deterministic"
    );
    assert_eq!(
        cs1.equal_count, cs2.equal_count,
        "equal constraint count must be deterministic"
    );
}
