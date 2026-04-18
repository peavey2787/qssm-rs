use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::predicate::{eval_all_predicates, proof_of_age_predicates, PredicateBlock, PredicateError};

pub const QSSM_TEMPLATE_VERSION: u32 = 1;

/// Errors when loading or validating a [`QssmTemplate`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TemplateError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported template version: {0} (expected {QSSM_TEMPLATE_VERSION})")]
    UnsupportedVersion(u32),
    #[error("template must have at least one predicate")]
    EmptyPredicates,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TemplateAnchorKind {
    AnchorHash,
    StaticRoot,
    TimestampUnixSecs,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct QssmTemplate {
    qssm_template_version: u32,
    id: String,
    title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    allowed_anchor_kinds: Vec<TemplateAnchorKind>,
    predicates: Vec<PredicateBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lattice_vk_seed_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
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

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, TemplateError> {
        let t: Self = serde_json::from_slice(bytes)?;
        if t.qssm_template_version != QSSM_TEMPLATE_VERSION {
            return Err(TemplateError::UnsupportedVersion(t.qssm_template_version));
        }
        if t.predicates.is_empty() {
            return Err(TemplateError::EmptyPredicates);
        }
        Ok(t)
    }

    pub fn verify_public_claim(&self, public_claim: &Value) -> Result<(), PredicateError> {
        eval_all_predicates(public_claim, &self.predicates)
    }

    // ── Read-only accessors ─────────────────────────────────

    #[must_use]
    pub fn qssm_template_version(&self) -> u32 {
        self.qssm_template_version
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    #[must_use]
    pub fn allowed_anchor_kinds(&self) -> &[TemplateAnchorKind] {
        &self.allowed_anchor_kinds
    }

    #[must_use]
    pub fn predicates(&self) -> &[PredicateBlock] {
        &self.predicates
    }

    #[must_use]
    pub fn lattice_vk_seed_hex(&self) -> Option<&str> {
        self.lattice_vk_seed_hex.as_deref()
    }

    #[must_use]
    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }

    // ── Builder-style setters (return Self for chaining) ───

    #[must_use]
    pub fn with_lattice_vk_seed_hex(mut self, hex: impl Into<String>) -> Self {
        self.lattice_vk_seed_hex = Some(hex.into());
        self
    }

    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
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

    #[test]
    fn from_json_rejects_wrong_version() {
        let mut t = QssmTemplate::proof_of_age("test");
        t.qssm_template_version = 999;
        let bytes = serde_json::to_vec(&t).unwrap();
        let err = QssmTemplate::from_json_slice(&bytes).unwrap_err();
        assert!(matches!(err, TemplateError::UnsupportedVersion(999)));
    }

    #[test]
    fn from_json_rejects_empty_predicates() {
        let mut t = QssmTemplate::proof_of_age("test");
        t.predicates.clear();
        let bytes = serde_json::to_vec(&t).unwrap();
        let err = QssmTemplate::from_json_slice(&bytes).unwrap_err();
        assert!(matches!(err, TemplateError::EmptyPredicates));
    }
}