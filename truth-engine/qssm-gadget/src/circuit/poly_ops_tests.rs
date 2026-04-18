//! Tests formerly hosted in the poly_ops.rs compatibility shim.

use qssm_utils::blake3_hash;
use qssm_utils::hashing::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION;

use super::binding::TruthWitness;
use super::binding_contract::{
    BindingLabel, BindingPhase, BindingReservoir, Nomination, PublicBindingContract,
};
use super::context::PolyOpContext;
use super::cs_tracing::PolyOpTracingCs;
use super::handshake::{EngineAPublicJson, TRANSCRIPT_MAP_LAYOUT_VERSION};
use super::lattice_polyop::LatticePolyOp;
use super::operators::{
    effective_external_entropy, merkle_truth_pipe, xor32, EntropyInjectionOp,
    MerkleParentBlake3Op, TruthLimbV2Params,
};
use super::r1cs::{Blake3Gadget, ConstraintSystem, VarId, VarKind};
use crate::primitives::blake3_compress::hash_merkle_parent_witness;

#[derive(Debug, Default)]
struct CountingConstraintSystem {
    next_var: u32,
    constraint_count: u64,
}

impl CountingConstraintSystem {
    fn constraint_count(&self) -> u64 {
        self.constraint_count
    }
}

impl ConstraintSystem for CountingConstraintSystem {
    fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
        let id = VarId(self.next_var);
        self.next_var = self.next_var.saturating_add(1);
        id
    }

    fn enforce_xor(&mut self, _x: VarId, _y: VarId, _and_xy: VarId, _z: VarId) {
        self.constraint_count = self.constraint_count.saturating_add(1);
    }

    fn enforce_full_adder(
        &mut self,
        _a: VarId,
        _b: VarId,
        _cin: VarId,
        _sum: VarId,
        _cout: VarId,
    ) {
        self.constraint_count = self.constraint_count.saturating_add(1);
    }

    fn enforce_equal(&mut self, _a: VarId, _b: VarId) {
        self.constraint_count = self.constraint_count.saturating_add(1);
    }
}

#[test]
fn transcript_map_version_matches_utils() {
    assert_eq!(TRANSCRIPT_MAP_LAYOUT_VERSION, LE_FS_PUBLIC_BINDING_LAYOUT_VERSION);
}

#[test]
fn poly_op_tracing_cs_merkle_synthesis_ok() {
    let witness = hash_merkle_parent_witness(&[1u8; 32], &[2u8; 32]);
    let mut ctx = PolyOpContext::new("test");
    let mut prover = CountingConstraintSystem::default();
    {
        let mut trace = PolyOpTracingCs {
            inner: &mut prover,
            ctx: &mut ctx,
        };
        Blake3Gadget::synthesize_merkle_parent_hash(&mut trace, &witness);
    }
    assert_eq!(prover.constraint_count(), 65_184);
}

#[test]
fn degree_exceeded_carries_var_ids() {
    let mut ctx = PolyOpContext::new("deg");
    ctx.register_binary_product(VarId(0), VarId(1), VarId(2), "test").unwrap();
    ctx.ensure_len(6);
    ctx.mul_depth[3] = 1;
    ctx.mul_depth[4] = 1;
    let error = ctx
        .register_binary_product(VarId(3), VarId(4), VarId(5), "boom")
        .unwrap_err();
    assert_eq!(error.lhs, VarId(3));
    assert_eq!(error.rhs, VarId(4));
    assert_eq!(error.and_out, VarId(5));
}

#[test]
fn binding_reservoir_btree_labels_are_canonical_order() {
    let mut reservoir = BindingReservoir::default();
    reservoir.nominate(BindingPhase::Aux, BindingLabel("zebra".into()), vec![1]).unwrap();
    reservoir.nominate(BindingPhase::Aux, BindingLabel("alpha".into()), vec![2]).unwrap();
    let keys: Vec<_> = reservoir.by_phase.get(&BindingPhase::Aux).unwrap().keys().cloned().collect();
    assert_eq!(keys[0].0, "alpha");
    assert_eq!(keys[1].0, "zebra");
}

#[test]
fn engine_a_public_json_key_order() {
    let witness = TruthWitness::bind([9u8; 32], [8u8; 32], 1, 2, 0, [7u8; 32], [6u8; 32], false);
    let public = EngineAPublicJson::from_witness(&witness);
    public.validate_transcript_map().unwrap();
    let value = public.to_ordered_json_value().unwrap();
    let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, vec!["message_limb_u30".to_string(), "digest_coeff_vector_u4".to_string()]);
}

#[test]
fn public_binding_contract_merge_rejects_duplicate_label() {
    let mut left = PublicBindingContract::default();
    left.nominations.push((BindingPhase::Aux, BindingLabel("x".into()), Nomination { bytes: vec![1] }));
    let mut right = PublicBindingContract::default();
    right.nominations.push((BindingPhase::Aux, BindingLabel("x".into()), Nomination { bytes: vec![2] }));
    assert!(left.merge(&right).is_err());
}

// ── Gap 5: transcript-tampering tests ─────────────────────────────────────

#[test]
fn transcript_tamper_truncated_coeff_vector_rejected() {
    let witness = TruthWitness::bind([9u8; 32], [8u8; 32], 1, 2, 0, [7u8; 32], [6u8; 32], false);
    let mut public = EngineAPublicJson::from_witness(&witness);
    public.digest_coeff_vector_u4.truncate(32);
    assert!(
        public.validate_transcript_map().is_err(),
        "truncated coeff vector must be rejected by transcript validation"
    );
}

#[test]
fn transcript_tamper_extended_coeff_vector_rejected() {
    let witness = TruthWitness::bind([9u8; 32], [8u8; 32], 1, 2, 0, [7u8; 32], [6u8; 32], false);
    let mut public = EngineAPublicJson::from_witness(&witness);
    public.digest_coeff_vector_u4.push(0);
    assert!(
        public.validate_transcript_map().is_err(),
        "extended coeff vector must be rejected by transcript validation"
    );
}

#[test]
fn transcript_tamper_empty_coeff_vector_rejected() {
    let witness = TruthWitness::bind([9u8; 32], [8u8; 32], 1, 2, 0, [7u8; 32], [6u8; 32], false);
    let mut public = EngineAPublicJson::from_witness(&witness);
    public.digest_coeff_vector_u4.clear();
    assert!(
        public.validate_transcript_map().is_err(),
        "empty coeff vector must be rejected by transcript validation"
    );
}

fn truth_pipe_shared_ctx_merkle_then_truth_ok_inner() {
    let pipe = merkle_truth_pipe(
        MerkleParentBlake3Op::new(blake3_hash(b"L"), blake3_hash(b"R")),
        TruthLimbV2Params {
            binding_context: [5u8; 32],
            n: 1,
            k: 0,
            bit_at_k: 0,
            challenge: [6u8; 32],
            external_entropy: [7u8; 32],
            external_entropy_included: false,
            device_entropy_link: None,
        },
    );
    let mut ctx = PolyOpContext::new("pipe");
    let out = pipe.run_diagnostic(&mut ctx).expect("run");
    out.truth_witness.validate().expect("truth witness should validate");
}

#[test]
fn truth_pipe_shared_ctx_merkle_then_truth_ok() {
    const STACK: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(truth_pipe_shared_ctx_merkle_then_truth_ok_inner)
        .expect("spawn")
        .join()
        .expect("join panicked");
}

fn device_entropy_link_xor_changes_engine_a_public_inner() {
    let left = blake3_hash(b"A");
    let right = blake3_hash(b"B");
    let merkle = MerkleParentBlake3Op::new(left, right);
    let floor = [3u8; 32];
    let challenge = [2u8; 32];
    let rollup = [1u8; 32];
    let root = merkle
        .clone()
        .pipe_truth(TruthLimbV2Params {
            binding_context: rollup,
            n: 0,
            k: 0,
            bit_at_k: 0,
            challenge,
            external_entropy: floor,
            external_entropy_included: false,
            device_entropy_link: None,
        })
        .run_diagnostic(&mut PolyOpContext::new("a"))
        .expect("a")
        .truth_witness;
    let with_link = merkle
        .pipe_truth(TruthLimbV2Params {
            binding_context: rollup,
            n: 0,
            k: 0,
            bit_at_k: 0,
            challenge,
            external_entropy: floor,
            external_entropy_included: false,
            device_entropy_link: Some([0xffu8; 32]),
        })
        .run_diagnostic(&mut PolyOpContext::new("b"))
        .expect("b")
        .truth_witness;
    assert_ne!(root.message_limb, with_link.message_limb);
}

#[test]
fn device_entropy_link_xor_changes_engine_a_public() {
    const STACK: usize = 32 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(device_entropy_link_xor_changes_engine_a_public_inner)
        .expect("spawn")
        .join()
        .expect("join panicked");
}

#[test]
fn ms_binding_entropy_for_fs_challenge_is_raw_device_link() {
    let floor = [3u8; 32];
    let link = [0xabu8; 32];
    let pipe = merkle_truth_pipe(
        MerkleParentBlake3Op::new([1u8; 32], [2u8; 32]),
        TruthLimbV2Params {
            binding_context: [0u8; 32],
            n: 0,
            k: 0,
            bit_at_k: 0,
            challenge: [0u8; 32],
            external_entropy: floor,
            external_entropy_included: false,
            device_entropy_link: Some(link),
        },
    );
    let fallback = [9u8; 32];
    assert_eq!(pipe.ms_binding_entropy_for_fs_challenge(fallback), link);
    assert_eq!(pipe.second.params.ms_binding_entropy_digest(fallback), link);
    assert_eq!(effective_external_entropy(&pipe.second.params), xor32(floor, link));
}

#[test]
fn entropy_injection_weak_bytes_err_when_enforced() {
    let op = EntropyInjectionOp::new();
    let mut ctx = PolyOpContext::new("e");
    let mut prover = CountingConstraintSystem::default();
    let result = op.synthesize_with_context(vec![0u8; 300], &mut prover, &mut ctx);
    assert!(result.is_err());
}

#[test]
fn manual_refresh_boolean_wire_copy_records_metadata() {
    let mut ctx = PolyOpContext::new("seg");
    let mut prover = CountingConstraintSystem::default();
    let old = {
        let mut trace = PolyOpTracingCs {
            inner: &mut prover,
            ctx: &mut ctx,
        };
        trace.allocate_variable(VarKind::Private)
    };
    let fresh = {
        let mut trace = PolyOpTracingCs {
            inner: &mut prover,
            ctx: &mut ctx,
        };
        trace.refresh_boolean_wire_copy(old, "unit_copy", Some("seg_x"))
    };
    assert_ne!(fresh.0, old.0);
    assert_eq!(ctx.manual_refresh_count, 1);
    assert_eq!(ctx.auto_refresh_count, 0);
    assert_eq!(ctx.refresh_metadata.len(), 1);
    assert_eq!(ctx.refresh_metadata[0].label, "unit_copy");
    assert_eq!(ctx.refresh_metadata[0].kind, "manual");
}

#[test]
fn auto_refresh_xor_inserts_equal_copy_on_depth_tie_left() {
    let mut ctx = PolyOpContext::new("auto");
    ctx.set_auto_refresh_enabled(true);
    let mut prover = CountingConstraintSystem::default();
    let before = prover.constraint_count();
    {
        let mut trace = PolyOpTracingCs {
            inner: &mut prover,
            ctx: &mut ctx,
        };
        let a0 = trace.allocate_variable(VarKind::Private);
        let b0 = trace.allocate_variable(VarKind::Private);
        let and0 = trace.allocate_variable(VarKind::Private);
        let z0 = trace.allocate_variable(VarKind::Private);
        trace.enforce_xor(a0, b0, and0, z0);

        let a1 = trace.allocate_variable(VarKind::Private);
        let b1 = trace.allocate_variable(VarKind::Private);
        let and1 = trace.allocate_variable(VarKind::Private);
        let z1 = trace.allocate_variable(VarKind::Private);
        trace.enforce_xor(a1, b1, and1, z1);

        let and_xy = trace.allocate_variable(VarKind::Private);
        let z2 = trace.allocate_variable(VarKind::Private);
        trace.enforce_xor(and0, and1, and_xy, z2);
    }
    assert_eq!(ctx.auto_refresh_count, 1);
    assert!(prover.constraint_count() >= before + 4);
    let metadata = &ctx.refresh_metadata[0];
    assert_eq!(metadata.kind, "auto_xor");
    assert!(metadata.label.contains("lhs"));
}