use qssm_gadget::{
    ConstraintSystem, LatticePolyOp, MsPredicateOnlyV2BridgeInput, MsPredicateOnlyV2BridgeOp,
    PolyOpContext, VarId, VarKind,
};
use qssm_ms::{commit_value_v2, prove_predicate_only_v2, PredicateOnlyStatementV2};

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

fn sample_input() -> MsPredicateOnlyV2BridgeInput {
    let binding_entropy = [7u8; 32];
    let binding_context = [9u8; 32];
    let context = b"age_gate_fast".to_vec();
    let (commitment, witness) =
        commit_value_v2(u64::MAX, [3u8; 32], binding_entropy).expect("commit v2");
    let statement = PredicateOnlyStatementV2::new(
        commitment,
        u64::MAX - 1,
        binding_entropy,
        binding_context,
        context,
    );
    let proof = prove_predicate_only_v2(&statement, &witness, [4u8; 32]).expect("prove v2");
    MsPredicateOnlyV2BridgeInput { statement, proof }
}

#[test]
fn v2_proof_must_verify_before_binding() {
    let input = sample_input();
    let tampered_statement = PredicateOnlyStatementV2::new(
        input.statement.commitment().clone(),
        input.statement.target().saturating_sub(1),
        *input.statement.binding_entropy(),
        *input.statement.binding_context(),
        input.statement.context().to_vec(),
    );
    let op = MsPredicateOnlyV2BridgeOp;
    let mut ctx = PolyOpContext::new("ms_v2_bridge");
    let mut cs = NoopConstraintSystem::default();
    let res = op.synthesize_with_context(
        MsPredicateOnlyV2BridgeInput {
            statement: tampered_statement,
            proof: input.proof,
        },
        &mut cs,
        &mut ctx,
    );
    assert!(
        res.is_err(),
        "bridge must reject if verify_predicate_only_v2 fails"
    );
}

#[test]
fn no_active_bridge_path_consumes_ghostmirror_challenge() {
    let operators_mod = include_str!("../src/circuit/operators/mod.rs").replace('\r', "");
    let lib_rs = include_str!("../src/lib.rs").replace('\r', "");
    let seam_rs = include_str!("../src/circuit/operators/engine_a_binding.rs").replace('\r', "");

    assert!(
        !operators_mod.contains("ms_ghost_mirror"),
        "active operator surface must not expose legacy ms_ghost_mirror"
    );
    assert!(
        !lib_rs.contains("MsGhostMirror"),
        "crate facade must not export legacy ghost mirror bridge"
    );
    assert!(
        !seam_rs.contains("ms_fs_v2_challenge"),
        "active seam material must not consume ms_fs_v2_challenge"
    );
}
