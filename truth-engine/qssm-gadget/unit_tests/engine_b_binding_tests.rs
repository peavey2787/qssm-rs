use qssm_gadget::LatticePolyOp;
use qssm_gadget::PolyOpContext;
use qssm_gadget::{ConstraintSystem, VarId, VarKind};
use qssm_gadget::{EngineABindingInput, EngineABindingOp};
use qssm_ms::{commit_value_v2, prove_predicate_only_v2, PredicateOnlyStatementV2};
use qssm_utils::hashing::{hash_domain, DOMAIN_MS};
use qssm_utils::blake3_hash;

#[derive(Debug, Default)]
struct NoopConstraintSystem {
    next_var: u32,
}

impl ConstraintSystem for NoopConstraintSystem {
    fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
        let id = VarId(self.next_var);
        self.next_var = self.next_var.saturating_add(1);
        id
    }

    fn enforce_xor(&mut self, _x: VarId, _y: VarId, _and_xy: VarId, _z: VarId) {}

    fn enforce_full_adder(&mut self, _a: VarId, _b: VarId, _cin: VarId, _sum: VarId, _cout: VarId) {
    }

    fn enforce_equal(&mut self, _a: VarId, _b: VarId) {}
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

fn baseline_inputs() -> (EngineABindingInput, u64, u64, Vec<u8>) {
    let seed = [3u8; 32];
    let binding_entropy = [4u8; 32];
    let rollup = [5u8; 32];
    let state_root = blake3_hash(b"state-root");
    let value = u64::MAX;
    let target = u64::MAX - 1;
    let context = b"ctx".to_vec();

    let (commitment, witness) =
        commit_value_v2(value, seed, binding_entropy).expect("commit v2");
    let statement = PredicateOnlyStatementV2::new(
        commitment,
        target,
        binding_entropy,
        rollup,
        context.clone(),
    );
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
        truth_digest: blake3_hash(b"truth-digest-baseline"),
        entropy_anchor: blake3_hash(b"entropy-anchor-baseline"),
        claimed_seam_commitment: [0u8; 32],
        require_ms_verified: true,
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
    let mut cs = NoopConstraintSystem::default();
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
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "tampered state root must fail seam verify");
}

#[test]
fn engine_a_binding_rejects_tweaked_ms_root() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_statement_digest[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "tampered ms_v2_statement_digest must fail seam verify");
}

#[test]
fn engine_a_binding_rejects_tweaked_result_bit() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_result_bit ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "tampered ms_v2_result_bit must fail seam verify"
    );
}

#[test]
fn engine_a_binding_rejects_tweaked_binding_context() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.binding_context[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "tampered binding_context must fail seam verify"
    );
}

#[test]
fn engine_a_binding_rejects_tweaked_ms_v2_bitness_global_challenges_digest() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_bitness_global_challenges_digest[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "tampered ms_v2_bitness_global_challenges_digest must fail seam verify"
    );
}

#[test]
fn engine_a_binding_rejects_wrong_claimed_seam_commitment() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.claimed_seam_commitment[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "tampered claimed_seam_commitment must fail commit-then-open"
    );
}

#[test]
fn engine_a_binding_rejects_require_ms_verified_false() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.require_ms_verified = false;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "require_ms_verified=false must fail");
}

#[test]
fn engine_a_binding_rejects_all_zero_state_root() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.state_root = [0u8; 32];

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "all-zero state_root must be rejected");
}

#[test]
fn engine_a_binding_rejects_all_zero_ms_root() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_statement_digest = [0u8; 32];

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "all-zero ms_v2_statement_digest must be rejected");
}

// ── Gap 3: byte-swap within a single field must be detected ───────────────

#[test]
fn byte_swap_within_field_detected() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    // Swap first two bytes of state_root (not a bit-flip — a positional swap).
    tampered.state_root.swap(0, 1);

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "byte-swap within state_root must fail seam verify"
    );
}

#[test]
fn engine_a_binding_rejects_all_zero_device_entropy_link() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.device_entropy_link = [0u8; 32];

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "all-zero device_entropy_link must be rejected"
    );
}

#[test]
fn engine_a_binding_rejects_tweaked_truth_digest() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.truth_digest[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "tampered truth_digest must fail seam verify");
}

#[test]
fn engine_a_binding_rejects_tweaked_entropy_anchor() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.entropy_anchor[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "tampered entropy_anchor must fail seam verify"
    );
}

#[test]
fn engine_a_binding_rejects_all_zero_truth_digest() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.truth_digest = [0u8; 32];

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "all-zero truth_digest must be rejected");
}

#[test]
fn engine_a_binding_rejects_all_zero_entropy_anchor() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.entropy_anchor = [0u8; 32];

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "all-zero entropy_anchor must be rejected");
}

#[test]
fn engine_a_binding_rejects_all_zero_ms_v2_bitness_global_challenges_digest() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_bitness_global_challenges_digest = [0u8; 32];

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "all-zero ms_v2_bitness_global_challenges_digest must be rejected"
    );
}

#[test]
fn seam_digest_changes_when_statement_digest_changes() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_statement_digest[0] ^= 0x01;
    assert_ne!(
        EngineABindingOp::commitment_digest(&input),
        EngineABindingOp::commitment_digest(&tampered)
    );
}

#[test]
fn seam_digest_changes_when_result_bit_changes() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_result_bit ^= 0x01;
    assert_ne!(
        EngineABindingOp::commitment_digest(&input),
        EngineABindingOp::commitment_digest(&tampered)
    );
}

#[test]
fn seam_digest_changes_when_any_bitness_global_challenge_changes() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_bitness_global_challenges_digest[0] ^= 0x01;
    assert_ne!(
        EngineABindingOp::commitment_digest(&input),
        EngineABindingOp::commitment_digest(&tampered)
    );
}

#[test]
fn seam_digest_changes_when_comparison_global_challenge_changes() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_comparison_global_challenge[0] ^= 0x01;
    assert_ne!(
        EngineABindingOp::commitment_digest(&input),
        EngineABindingOp::commitment_digest(&tampered)
    );
}

#[test]
fn seam_digest_changes_when_transcript_digest_changes() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_v2_transcript_digest[0] ^= 0x01;
    assert_ne!(
        EngineABindingOp::commitment_digest(&input),
        EngineABindingOp::commitment_digest(&tampered)
    );
}

#[test]
fn engine_a_binding_valid_baseline_succeeds() {
    let (input, _value, _target, _context) = baseline_inputs();

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(input, &mut cs, &mut ctx);
    assert!(res.is_ok(), "valid baseline inputs must succeed");
}
