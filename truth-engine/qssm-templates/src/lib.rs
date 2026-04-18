//! Template gallery, predicate evaluation, and resolver for QSSM verifier policy.

mod predicate;
#[cfg(feature = "script-helpers")]
mod predicate_templates;
mod template;

pub use predicate::{
    eval_all_predicates, eval_predicate, json_at_path, predicate_blocks_from_template_value, CmpOp,
    PredicateBlock, PredicateError,
};
#[cfg(feature = "script-helpers")]
pub use predicate_templates::{
    age_gate_script, millionaires_duel_script, parametric_age_gate_vk,
    parametric_millionaires_duel_vk, parse_template_id_param, simple_math_script,
    standard_library_script,
};
pub use template::{QssmTemplate, TemplateAnchorKind, TemplateError, QSSM_TEMPLATE_VERSION};

/// All built-in templates shipped with the SDK.
#[must_use]
pub fn standard_templates() -> Vec<QssmTemplate> {
    vec![
        QssmTemplate::proof_of_age("age-gate-21"),
    ]
}

/// Resolve a template by `id` from the standard library.
///
/// Returns `None` if `id` is not a known built-in template.
#[must_use]
pub fn resolve(id: &str) -> Option<QssmTemplate> {
    match id {
        "age-gate-21" => Some(QssmTemplate::proof_of_age("age-gate-21")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn standard_templates_non_empty() {
        assert!(!standard_templates().is_empty());
    }

    #[test]
    fn resolve_known_id() {
        let t = resolve("age-gate-21").expect("should resolve");
        assert_eq!(t.id(), "age-gate-21");
    }

    #[test]
    fn resolve_unknown_returns_none() {
        assert!(resolve("nonexistent").is_none());
    }

    #[test]
    fn age_gate_template_verifies_valid_claim() {
        let t = resolve("age-gate-21").unwrap();
        let claim = json!({ "claim": { "age_years": 25 } });
        t.verify_public_claim(&claim).unwrap();
    }

    #[test]
    fn age_gate_template_rejects_underage() {
        let t = resolve("age-gate-21").unwrap();
        let claim = json!({ "claim": { "age_years": 18 } });
        assert!(t.verify_public_claim(&claim).is_err());
    }
}

