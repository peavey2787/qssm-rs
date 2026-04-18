use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::predicate::{eval_all_predicates, proof_of_age_predicates, PredicateBlock, PredicateError};

pub const QSSM_TEMPLATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateAnchorKind {
    AnchorHash,
    StaticRoot,
    TimestampUnixSecs,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QssmTemplate {
    pub qssm_template_version: u32,
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub allowed_anchor_kinds: Vec<TemplateAnchorKind>,
    pub predicates: Vec<PredicateBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lattice_vk_seed_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl QssmTemplate {
    #[must_use]
    pub fn proof_of_age(id: impl Into<String>) -> Self {
        Self {
            qssm_template_version: QSSM_TEMPLATE_VERSION,
            id: id.into(),
            title: "Proof of age (21+)".to_string(),
            description: Some(
                "Public claim must include claim.age_years between 21 and 150 (inclusive).".into(),
            ),
            allowed_anchor_kinds: vec![
                TemplateAnchorKind::AnchorHash,
                TemplateAnchorKind::StaticRoot,
                TemplateAnchorKind::TimestampUnixSecs,
            ],
            predicates: proof_of_age_predicates(),
            lattice_vk_seed_hex: None,
            notes: None,
        }
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    pub fn verify_public_claim(&self, public_claim: &Value) -> Result<(), PredicateError> {
        eval_all_predicates(public_claim, &self.predicates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_json() {
        let template = QssmTemplate::proof_of_age("demo-age");
        let serialized = serde_json::to_string_pretty(&template).unwrap();
        let parsed: QssmTemplate = serde_json::from_str(&serialized).unwrap();
        assert_eq!(template, parsed);
    }

    #[test]
    fn proof_of_age_claim() {
        let template = QssmTemplate::proof_of_age("x");
        let claim = json!({ "claim": { "age_years": 22 } });
        template.verify_public_claim(&claim).unwrap();
    }
}