//! Template resolution integration tests.
//!
//! Verifies the template gallery, predicate evaluation, and JSON template
//! parsing across crate boundaries.

use qssm_templates::{
    resolve, standard_templates, eval_predicate, eval_all_predicates,
    QssmTemplate, PredicateError, QSSM_TEMPLATE_VERSION,
};
use serde_json::json;

// ── Gallery resolution ───────────────────────────────────────────────

#[test]
fn resolve_known_template() {
    let t = resolve("age-gate-21");
    assert!(t.is_some(), "age-gate-21 must be in the standard gallery");
    let t = t.unwrap();
    assert_eq!(t.id(), "age-gate-21");
    assert_eq!(t.qssm_template_version(), QSSM_TEMPLATE_VERSION);
}

#[test]
fn resolve_unknown_template_returns_none() {
    assert!(resolve("nonexistent-template").is_none());
    assert!(resolve("").is_none());
}

#[test]
fn standard_templates_is_not_empty() {
    let templates = standard_templates();
    assert!(!templates.is_empty(), "gallery must contain at least one template");
}

#[test]
fn all_standard_templates_have_unique_ids() {
    let templates = standard_templates();
    let mut ids: Vec<&str> = templates.iter().map(|t| t.id()).collect();
    let original_count = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), original_count, "template IDs must be unique");
}

#[test]
fn all_standard_templates_resolvable() {
    for t in standard_templates() {
        let resolved = resolve(t.id());
        assert!(resolved.is_some(), "template '{}' must be resolvable by ID", t.id());
    }
}

// ── Predicate evaluation ─────────────────────────────────────────────

#[test]
fn valid_claim_passes_predicate() {
    let t = resolve("age-gate-21").unwrap();
    let claim = json!({ "claim": { "age_years": 25 } });
    t.verify_public_claim(&claim).expect("predicate should pass");
}

#[test]
fn underage_claim_fails_predicate() {
    let t = resolve("age-gate-21").unwrap();
    let claim = json!({ "claim": { "age_years": 17 } });
    let err = t.verify_public_claim(&claim).unwrap_err();
    // The predicate returns OutOfRange for age below threshold.
    assert!(
        matches!(err, PredicateError::OutOfRange),
        "underage must fail predicate: {err:?}"
    );
}

#[test]
fn missing_field_fails_predicate() {
    let t = resolve("age-gate-21").unwrap();
    let claim = json!({ "claim": {} });
    let err = t.verify_public_claim(&claim).unwrap_err();
    assert!(matches!(err, PredicateError::MissingField(_)));
}

#[test]
fn wrong_type_fails_predicate() {
    let t = resolve("age-gate-21").unwrap();
    let claim = json!({ "claim": { "age_years": "twenty-five" } });
    let err = t.verify_public_claim(&claim).unwrap_err();
    assert!(matches!(err, PredicateError::NotANumber(_)));
}

// ── Template construction ────────────────────────────────────────────

#[test]
fn proof_of_age_constructor_produces_valid_template() {
    let t = QssmTemplate::proof_of_age("custom-age-check");
    assert_eq!(t.id(), "custom-age-check");
    assert_eq!(t.qssm_template_version(), QSSM_TEMPLATE_VERSION);
    assert!(!t.predicates().is_empty());
}

#[test]
fn custom_template_evaluates_predicates() {
    let t = QssmTemplate::proof_of_age("my-gate");
    let ok_claim = json!({ "claim": { "age_years": 30 } });
    t.verify_public_claim(&ok_claim).expect("30 >= 21");

    let bad_claim = json!({ "claim": { "age_years": 18 } });
    assert!(t.verify_public_claim(&bad_claim).is_err());
}

// ── JSON template round-trip ─────────────────────────────────────────

#[test]
fn template_json_round_trip() {
    let original = resolve("age-gate-21").unwrap();
    let json_bytes = serde_json::to_vec(&original).expect("serialize");
    let recovered = QssmTemplate::from_json_slice(&json_bytes).expect("deserialize");
    assert_eq!(original.id(), recovered.id());
    assert_eq!(original.qssm_template_version(), recovered.qssm_template_version());
}

// ── eval_predicate / eval_all_predicates direct ──────────────────────

#[test]
fn eval_all_predicates_on_valid_claim() {
    let t = resolve("age-gate-21").unwrap();
    let claim = json!({ "claim": { "age_years": 25 } });
    eval_all_predicates(&claim, t.predicates()).expect("all predicates pass");
}

#[test]
fn eval_predicate_individually() {
    let t = resolve("age-gate-21").unwrap();
    let claim = json!({ "claim": { "age_years": 25 } });
    for block in t.predicates() {
        eval_predicate(&claim, block).expect("individual predicate should pass");
    }
}

// ── Cross-crate template usage ───────────────────────────────────────

#[test]
fn template_used_in_full_prove_verify_pipeline() {
    use qssm_api::ProofContext;
    use qssm_utils::hashing::blake3_hash;

    let ctx = ProofContext::new(blake3_hash(b"TEMPLATE-PIPELINE-SEED"));
    let t = resolve("age-gate-21").unwrap();
    let claim = json!({ "claim": { "age_years": 30 } });
    let binding = blake3_hash(b"TEMPLATE-PIPELINE-BINDING");
    let entropy = blake3_hash(b"TEMPLATE-PIPELINE-ENTROPY");

    let proof = qssm_local_prover::prove(&ctx, &t, &claim, 100, 50, binding, entropy)
        .expect("prove");
    let ok = qssm_api::verify(&ProofContext::new(blake3_hash(b"TEMPLATE-PIPELINE-SEED")), &t, &claim, &proof, binding)
        .expect("verify");
    assert!(ok);
}
