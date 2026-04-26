use qssm_proofs::lattice::external_validation::{
    build_current_le_set_b_validation_artifact, independent_recompute_le_set_b_validation,
    validate_external_report_against_artifact, ExternalLeSetBValidationReport,
    LE_HVZK_VALIDATION_SCHEMA_VERSION,
};

#[test]
fn independent_recompute_matches_current_artifact() {
    let artifact = build_current_le_set_b_validation_artifact();
    let report = independent_recompute_le_set_b_validation(
        artifact.n,
        artifact.eta,
        artifact.gamma,
        artifact.beta,
        artifact.c_poly_size,
        artifact.c_poly_span,
        artifact.security_param_epsilon_log2,
        artifact.query_budget_log2,
    );
    validate_external_report_against_artifact(&artifact, &report)
        .expect("independent recomputation must match artifact");
}

#[test]
fn external_fixture_matches_current_artifact() {
    let artifact = build_current_le_set_b_validation_artifact();
    let fixture = include_str!("fixtures/le_set_b_hvzk_validation_v1.json");
    let report: ExternalLeSetBValidationReport =
        serde_json::from_str(fixture).expect("fixture must deserialize");
    assert_eq!(report.schema_version, LE_HVZK_VALIDATION_SCHEMA_VERSION);
    validate_external_report_against_artifact(&artifact, &report)
        .expect("external numeric fixture must match current artifact");
}
