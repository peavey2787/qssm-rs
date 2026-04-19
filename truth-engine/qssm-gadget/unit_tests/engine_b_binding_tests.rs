use qssm_gadget::LatticePolyOp;
use qssm_gadget::PolyOpContext;
use qssm_gadget::{ConstraintSystem, VarId, VarKind};
use qssm_gadget::{EngineABindingInput, EngineABindingOp};
use qssm_ms::{commit, prove, verify};
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

    let (root, salts) = commit(seed, ledger).expect("commit");
    let proof = prove(value, target, &salts, ledger, &context, &rollup).expect("prove");

    assert!(verify(
        root, &proof, ledger, value, target, &context, &rollup,
    ));

    let mut input = EngineABindingInput {
        state_root,
        ms_root: *root.as_bytes(),
        relation_digest: relation_digest(value, target, *proof.challenge()),
        ms_fs_v2_challenge: *proof.challenge(),
        binding_context: rollup,
        device_entropy_link: ledger,
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
    tampered.ms_root[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "tampered ms_root must fail seam verify");
}

#[test]
fn engine_a_binding_rejects_tweaked_relation_digest() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.relation_digest[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "tampered relation_digest must fail seam verify"
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
fn engine_a_binding_rejects_tweaked_ms_fs_v2_challenge() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_fs_v2_challenge[0] ^= 0x01;

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(
        res.is_err(),
        "tampered ms_fs_v2_challenge must fail seam verify"
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
    tampered.ms_root = [0u8; 32];

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "all-zero ms_root must be rejected");
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
fn engine_a_binding_rejects_all_zero_ms_fs_v2_challenge() {
    let (input, _value, _target, _context) = baseline_inputs();
    let mut tampered = input.clone();
    tampered.ms_fs_v2_challenge = [0u8; 32];

    let op = EngineABindingOp;
    let mut ctx = PolyOpContext::new("engine_a_binding");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(tampered, &mut cs, &mut ctx);
    assert!(res.is_err(), "all-zero ms_fs_v2_challenge must be rejected");
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
