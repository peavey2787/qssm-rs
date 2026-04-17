//! Template gallery and resolver for QSSM predicate templates.
//!
//! Re-exports the core template types from `qssm-gadget` and provides
//! convenience functions for discovering and loading standard templates.

pub use qssm_gadget::template::{QssmTemplate, TemplateAnchorKind, QSSM_TEMPLATE_VERSION};
pub use qssm_gadget::predicate::{PredicateBlock, PredicateError};
pub use qssm_gadget::{
    age_gate_script, millionaires_duel_script, simple_math_script,
    parametric_age_gate_vk, parametric_millionaires_duel_vk,
    standard_library_script, parse_template_id_param,
};

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
    standard_templates().into_iter().find(|t| t.id == id)
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
        assert_eq!(t.id, "age-gate-21");
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

