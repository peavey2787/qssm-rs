#[test]
fn spec_vs_code_fingerprint_test() {
    let exec_spec =
        include_str!("../../../docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md");

    let zk_mod = include_str!("../src/reduction_zk/mod.rs");
    let zk_simulators = include_str!("../src/reduction_zk/simulate/simulators.rs");
    let zk_simulators_extra = include_str!("../src/reduction_zk/simulate/simulators_extra.rs");
    let zk_helpers_le = include_str!("../src/reduction_zk/simulate/helpers_le.rs");
    let zk_types = include_str!("../src/reduction_zk/core/types_core.rs");
    let le_commit = include_str!("../../qssm-le/src/protocol/commit.rs");
    let ms_v2 = [
        include_str!("../../qssm-ms/src/v2/mod.rs"),
        include_str!("../../qssm-ms/src/v2/types.rs"),
        include_str!("../../qssm-ms/src/v2/protocol.rs"),
        include_str!("../../qssm-ms/src/v2/internals.rs"),
        include_str!("../../qssm-ms/src/v2/wire_constructors.rs"),
    ]
    .join("\n");

    // FS labels/domains that must stay pinned.
    for token in [
        "QSSM-ZK-SIM-v1.0",
        "qssm_global_sim_ms_seed",
        "qssm_global_sim_le_seed",
        "le_global_sim_commitment_short",
        "le_global_sim_z",
        "le_global_sim_challenge_seed",
        "le_programmed_query_digest",
        "QSSM-LE-FS-LYU-v1.0",
        "QSSM-LE-CHALLENGE-POLY-v1.0",
        "cross_protocol_digest_v1",
        "QSSM-LE-V1-COMMIT...............",
        "QSSM-MS-V1-VERIFY...............",
        "predicate_only_v2_bitness_query",
        "predicate_only_v2_comparison_query",
        "predicate_only_v2_query_scalar",
    ] {
        assert!(
            exec_spec.contains(token),
            "execution spec missing FS token: {token}"
        );
    }

    assert!(
        zk_mod.contains("QSSM-ZK-SIM-v1.0"),
        "simulator code missing token: QSSM-ZK-SIM-v1.0"
    );
    for token in ["qssm_global_sim_ms_seed", "qssm_global_sim_le_seed"] {
        assert!(
            zk_simulators.contains(token),
            "simulator code missing token: {token}"
        );
    }

    for token in [
        "le_global_sim_commitment_short",
        "le_global_sim_z",
        "le_global_sim_challenge_seed",
    ] {
        assert!(
            zk_simulators_extra.contains(token),
            "LE simulator code missing token: {token}"
        );
    }
    assert!(
        zk_helpers_le.contains("le_programmed_query_digest"),
        "LE simulator code missing token: le_programmed_query_digest"
    );

    for token in [
        "QSSM-LE-FS-LYU-v1.0",
        "QSSM-LE-CHALLENGE-POLY-v1.0",
        "cross_protocol_digest_v1",
        "QSSM-LE-V1-COMMIT...............",
        "QSSM-MS-V1-VERIFY...............",
    ] {
        assert!(le_commit.contains(token), "LE code missing token: {token}");
    }

    for token in [
        "predicate_only_v2_bitness_query",
        "predicate_only_v2_comparison_query",
        "predicate_only_v2_query_scalar",
    ] {
        assert!(ms_v2.contains(token), "MS v2 code missing token: {token}");
    }

    // Transcript field names and ordering inventory in execution spec.
    for token in [
        "commitment_coeffs",
        "t_coeffs",
        "z_coeffs",
        "challenge_seed",
        "programmed_oracle_query_digest",
        "statement_digest",
        "result",
        "bitness_global_challenges",
        "comparison_global_challenge",
        "transcript_digest",
    ] {
        assert!(
            exec_spec.contains(token),
            "execution spec missing transcript field token: {token}"
        );
    }

    // Concrete structs must expose those field names.
    assert!(zk_types.contains("pub struct SimulatedLeTranscript"));
    assert!(zk_types.contains("pub commitment_coeffs: Vec<u32>"));
    assert!(zk_types.contains("pub t_coeffs: Vec<u32>"));
    assert!(zk_types.contains("pub z_coeffs: Vec<u32>"));
    assert!(zk_types.contains("pub challenge_seed: [u8; 32]"));
    assert!(zk_types.contains("pub programmed_oracle_query_digest: [u8; 32]"));

    // Simulator signature inventory must remain aligned with execution spec.
    for fn_sig in [
        "simulate_qssm_transcript",
        "simulate_ms_v2_transcript",
        "simulate_le_transcript",
        "simulate_le_core",
    ] {
        assert!(
            exec_spec.contains(fn_sig),
            "execution spec missing simulator function inventory: {fn_sig}"
        );
    }
    assert!(zk_simulators.contains("pub fn simulate_qssm_transcript("));
    assert!(zk_simulators_extra.contains("pub fn simulate_ms_v2_transcript("));
    assert!(zk_simulators_extra.contains("pub fn simulate_le_transcript("));
    assert!(zk_simulators_extra.contains("pub(crate) fn simulate_le_core("));
}
