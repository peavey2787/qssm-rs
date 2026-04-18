use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTemplateId {
    pub base_id: String,
    pub param: Option<String>,
}

#[must_use]
pub fn parse_template_id_param(raw: &str) -> ParsedTemplateId {
    if let Some((base, param)) = raw.split_once(':') {
        ParsedTemplateId {
            base_id: base.to_string(),
            param: Some(param.to_string()),
        }
    } else {
        ParsedTemplateId {
            base_id: raw.to_string(),
            param: None,
        }
    }
}

#[must_use]
pub fn millionaires_duel_script() -> Value {
    json!({
        "template_id": "millionaires_duel_v1",
        "predicates": [
            {
                "kind": "range",
                "field": "claim.bucket",
                "min": 0,
                "max": 7
            }
        ]
    })
}

#[must_use]
pub fn age_gate_script() -> Value {
    json!({
        "template_id": "age_gate_v1",
        "predicates": [
            {
                "kind": "at_least",
                "field": "claim.account_age_years",
                "min": 21
            }
        ]
    })
}

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

#[must_use]
pub fn parametric_age_gate_vk(blinded_limit: [u8; 32]) -> Value {
    json!({
        "template_id": "age_gate_zk_v1",
        "constraints": [
            {
                "kind": "public_input_commitment",
                "public_input_commitment_hex": format!("0x{}", hex::encode(blinded_limit))
            }
        ]
    })
}

#[must_use]
pub fn parametric_millionaires_duel_vk(blinded_bucket_root: [u8; 32]) -> Value {
    json!({
        "template_id": "millionaires_duel_zk_v1",
        "constraints": [
            {
                "kind": "public_input_commitment",
                "public_input_commitment_hex": format!("0x{}", hex::encode(blinded_bucket_root))
            }
        ]
    })
}

#[must_use]
pub fn standard_library_script(template_id: &str) -> Option<Value> {
    let parsed = parse_template_id_param(template_id);
    match parsed.base_id.as_str() {
        "age_gate_v1" => Some(age_gate_script()),
        "millionaires_duel_v1" => Some(millionaires_duel_script()),
        "simple_math_v1" => Some(simple_math_script()),
        "age_gate_zk_v1" => Some(json!({ "template_id": "age_gate_zk_v1" })),
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
        let parsed = parse_template_id_param("simple_math_zk_v1:100");
        assert_eq!(parsed.base_id, "simple_math_zk_v1");
        assert_eq!(parsed.param.as_deref(), Some("100"));
    }

    #[test]
    fn parametric_vk_contains_commitment() {
        let value = parametric_age_gate_vk([7u8; 32]);
        let got = value["constraints"][0]["public_input_commitment_hex"]
            .as_str()
            .unwrap();
        assert!(got.starts_with("0x"));
        assert_eq!(got.len(), 66);
    }
}