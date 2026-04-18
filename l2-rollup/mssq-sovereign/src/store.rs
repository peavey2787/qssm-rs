//! Step persistence and binding validation for append-only JSONL streams.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::checkpoint::{WRAP_CONTEXT_DOMAIN, WRAP_SCHEMA_VERSION};
use crate::{decode_hex32, StepEnvelope};

/// Errors specific to step storage / binding validation.
#[derive(Debug)]
pub(crate) enum StoreError {
    BadContextDomain { expected: String, got: String },
    BadSchemaVersion { expected: String, got: String },
    BindingContextHexMismatch,
    BindingContextMismatch,
    StepIndexOutOfSequence { expected: u64, got: u64 },
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Validate a step envelope against stream binding invariants.
///
/// Checks context_domain, schema_version, binding_context_hex, and step_index.
pub(crate) fn validate_step_binding(
    step: &StepEnvelope,
    expected_binding_context: [u8; 32],
    expected_step_index: u64,
) -> Result<(), StoreError> {
    let w = &step.wrapper_v1;
    if w.context_domain != WRAP_CONTEXT_DOMAIN {
        return Err(StoreError::BadContextDomain {
            expected: WRAP_CONTEXT_DOMAIN.into(),
            got: w.context_domain.clone(),
        });
    }
    if w.schema_version != WRAP_SCHEMA_VERSION {
        return Err(StoreError::BadSchemaVersion {
            expected: WRAP_SCHEMA_VERSION.into(),
            got: w.schema_version.clone(),
        });
    }
    let digest_from_envelope = decode_hex32(&w.binding_context_hex)
        .map_err(|_| StoreError::BindingContextHexMismatch)?;
    if digest_from_envelope != expected_binding_context {
        return Err(StoreError::BindingContextMismatch);
    }
    if w.step_index != expected_step_index {
        return Err(StoreError::StepIndexOutOfSequence {
            expected: expected_step_index,
            got: w.step_index,
        });
    }
    Ok(())
}

/// Append one JSON line to the steps JSONL file.
pub(crate) fn append_step_line(step: &StepEnvelope, path: &Path) -> Result<(), StoreError> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}", serde_json::to_string(step)?)?;
    f.flush()?;
    Ok(())
}

pub(crate) fn rollup_file_stem(digest: &[u8; 32]) -> String {
    hex::encode(digest)
}
