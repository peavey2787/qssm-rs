//! Lightweight **`.qssm`** template document (JSON): predicates + allowed entropy anchors + verifier hints.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::predicate::{eval_all_predicates, PredicateBlock};

pub const QSSM_TEMPLATE_VERSION: u32 = 1;

/// Anchor kinds a verifier may accept when checking proofs bound with this template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateAnchorKind {
    KaspaParentBlock,
    StaticRoot,
    TimestampUnixSecs,
}

/// JSON serializable form of a **`.qssm`** file (any app can load and run [`QssmTemplate::verify_public_claim`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QssmTemplate {
    pub qssm_template_version: u32,
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Which anchor kinds provers may use for [`crate::entropy::EntropyAnchor`].
    pub allowed_anchor_kinds: Vec<TemplateAnchorKind>,
    pub predicates: Vec<PredicateBlock>,
    /// Hex **32** bytes — must match prover when checking QSSM‑LE demo proofs (**`VerifyingKey::from_seed`**).
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
                TemplateAnchorKind::KaspaParentBlock,
                TemplateAnchorKind::StaticRoot,
                TemplateAnchorKind::TimestampUnixSecs,
            ],
            predicates: crate::predicate::proof_of_age_predicates(),
            lattice_vk_seed_hex: None,
            notes: None,
        }
    }

    /// Parse **`.qssm`** JSON bytes.
    pub fn from_json_slice(s: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(s)
    }

    /// Run all [`Self::predicates`] on **`public_claim`** (JSON object).
    pub fn verify_public_claim(
        &self,
        public_claim: &Value,
    ) -> Result<(), crate::predicate::PredicateError> {
        eval_all_predicates(public_claim, &self.predicates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_json() {
        let t = QssmTemplate::proof_of_age("demo-age");
        let s = serde_json::to_string_pretty(&t).unwrap();
        let t2: QssmTemplate = serde_json::from_str(&s).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn proof_of_age_claim() {
        let t = QssmTemplate::proof_of_age("x");
        let claim = json!({ "claim": { "age_years": 22 } });
        t.verify_public_claim(&claim).unwrap();
    }
}
