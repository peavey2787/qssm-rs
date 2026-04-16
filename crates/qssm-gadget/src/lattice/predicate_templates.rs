//! Standard **PredicateBlock** scripts (“Standard Library of Truth”) for common Lab flows.
//!
//! Extend the system by adding a new `template_id` arm in [`standard_library_script`] and new
//! [`PredicateBlock`](super::predicate::PredicateBlock) kinds in Rust when you need shapes JSON cannot express yet
//! (for example `merkle_inclusion` or `threshold_sig`).

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTemplateId {
    pub base_id: String,
    pub param: Option<String>,
}

/// Parse `id:param` for Lab-side parametric law generation.
#[must_use]
pub fn parse_template_id_param(raw: &str) -> ParsedTemplateId {
    if let Some((base, p)) = raw.split_once(':') {
        ParsedTemplateId {
            base_id: base.to_string(),
            param: Some(p.to_string()),
        }
    } else {
        ParsedTemplateId {
            base_id: raw.to_string(),
            param: None,
        }
    }
}

/// Millionaire-style comparison: outcome lives in a **bucket** without revealing exact balances.
#[must_use]
pub fn millionaires_duel_script() -> Value {
    json!({
        "template_id": "millionaires_duel_v1",
        "predicates": [
            {
                "kind": "range",
                "field": "prover_package.millionaires.outcome_bucket",
                "min": 0,
                "max": 1
            }
        ]
    })
}

/// Age-style gate using an **at-least** numeric floor (Lab binds `claim.account_age_years` to Kaspa‑anchored policy).
#[must_use]
pub fn age_gate_kaspa_script() -> Value {
    json!({
        "template_id": "age_gate_kaspa_v1",
        "predicates": [
            {
                "kind": "at_least",
                "field": "claim.account_age_years",
                "min": 21
            }
        ]
    })
}

/// Minimal arithmetic attestation: prover exposes `claim.answer` that must equal an expected constant.
#[must_use]
pub fn simple_math_script() -> Value {
    json!({
        "template_id": "simple_math_v1",
        "predicates": [
            {
                "kind": "compare",
                "field": "claim.answer",
                "op": "eq",
                "rhs": 42
            }
        ]
    })
}

/// ZK-ready VK descriptor for age-gate circuits where the threshold is hidden behind a commitment.
#[must_use]
pub fn parametric_age_gate_vk(blinded_limit: [u8; 32]) -> Value {
    json!({
        "template_id": "age_gate_kaspa_zk_v1",
        "constraints": [
            {
                "kind": "zk_field_comparison",
                "lhs_field": "claim.account_age_years",
                "public_input_commitment_hex": format!("0x{}", hex::encode(blinded_limit))
            }
        ]
    })
}

/// ZK-ready VK descriptor for millionaire duel buckets where boundary map remains private.
#[must_use]
pub fn parametric_millionaires_duel_vk(blinded_bucket_root: [u8; 32]) -> Value {
    json!({
        "template_id": "millionaires_duel_zk_v1",
        "constraints": [
            {
                "kind": "zk_bucket_membership",
                "bucket_field": "prover_package.millionaires.outcome_bucket",
                "public_input_commitment_hex": format!("0x{}", hex::encode(blinded_bucket_root))
            }
        ]
    })
}

/// Resolve a well-known **`template_id`** to the JSON document consumed by [`super::predicate::predicate_blocks_from_template_value`].
#[must_use]
pub fn standard_library_script(template_id: &str) -> Option<Value> {
    // Resolver intentionally ignores `:param` suffixes; param expansion is Lab-side.
    let parsed = parse_template_id_param(template_id);
    match parsed.base_id.as_str() {
        // ZK families never embed literal parameters.
        "age_gate_kaspa_zk_v1" => Some(json!({ "template_id": "age_gate_kaspa_zk_v1" })),
        "millionaires_duel_zk_v1" => Some(json!({ "template_id": "millionaires_duel_zk_v1" })),
        "simple_math_zk_v1" => Some(json!({ "template_id": "simple_math_zk_v1" })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_template_id_param_split() {
        let p = parse_template_id_param("simple_math_zk_v1:100");
        assert_eq!(p.base_id, "simple_math_zk_v1");
        assert_eq!(p.param.as_deref(), Some("100"));
    }

    #[test]
    fn parametric_vk_contains_commitment() {
        let v = parametric_age_gate_vk([7u8; 32]);
        let got = v["constraints"][0]["public_input_commitment_hex"]
            .as_str()
            .unwrap();
        assert!(got.starts_with("0x"));
        assert_eq!(got.len(), 66);
    }
}
