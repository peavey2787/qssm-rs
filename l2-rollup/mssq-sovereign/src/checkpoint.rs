//! Checkpoint types and window-digest logic for append-only streams.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::hex_lower_prefixed;

/// Domain tag for rolling window integrity over consecutive step hashes.
pub const DOMAIN_WINDOW_V1: &[u8] = b"QSSM-WRAP-WINDOW-v1";

/// Normative context domain string (must match every [`crate::WrapperV1::context_domain`]).
pub const WRAP_CONTEXT_DOMAIN: &str = "QSSM-WRAP-CONTEXT-v1";

/// Normative wrapper schema version.
pub const WRAP_SCHEMA_VERSION: &str = "qssm-hybrid-wrapper-v1";

/// One line in `checkpoints/<rollup>.jsonl` (canonical JSON via JCS when written).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccumulatorCheckpoint {
    pub schema_version: String,
    pub binding_context_hex: String,
    pub context_domain: String,
    pub checkpoint_every: u64,
    pub checkpoint_step_index: u64,
    pub checkpoint_accumulator_hex: String,
    pub window_start_step_index: u64,
    pub window_end_step_index: u64,
    pub window_step_hashes_blake3_hex: String,
    pub created_unix_ms: u64,
}

/// BLAKE3(DOMAIN_WINDOW_V1 ‖ step_hash[0] ‖ … ‖ step_hash[n-1])
#[must_use]
pub fn window_step_hashes_digest(step_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_WINDOW_V1);
    for sh in step_hashes {
        h.update(sh);
    }
    *h.finalize().as_bytes()
}

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build a checkpoint struct from accumulator state and the current window.
pub(crate) fn create_checkpoint(
    step_index: u64,
    checkpoint_every: u64,
    binding_context: [u8; 32],
    current_accumulator: [u8; 32],
    window_step_hashes: &[[u8; 32]],
) -> AccumulatorCheckpoint {
    let window_digest = window_step_hashes_digest(window_step_hashes);
    let window_start = step_index + 1 - checkpoint_every;
    AccumulatorCheckpoint {
        schema_version: WRAP_SCHEMA_VERSION.into(),
        binding_context_hex: hex_lower_prefixed(&binding_context),
        context_domain: WRAP_CONTEXT_DOMAIN.into(),
        checkpoint_every,
        checkpoint_step_index: step_index,
        checkpoint_accumulator_hex: hex_lower_prefixed(&current_accumulator),
        window_start_step_index: window_start,
        window_end_step_index: step_index,
        window_step_hashes_blake3_hex: hex_lower_prefixed(&window_digest),
        created_unix_ms: now_unix_ms(),
    }
}

/// Errors specific to checkpoint writing.
#[derive(Debug)]
pub(crate) enum CheckpointWriteError {
    Canonical(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for CheckpointWriteError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Write one JCS-canonical checkpoint line to the JSONL file.
pub(crate) fn write_checkpoint_line(
    ckpt: &AccumulatorCheckpoint,
    path: &Path,
) -> Result<(), CheckpointWriteError> {
    let ckpt_line = serde_jcs::to_string(ckpt)
        .map_err(|e| CheckpointWriteError::Canonical(e.to_string()))?;
    let mut cf = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(cf, "{ckpt_line}")?;
    cf.flush()?;
    Ok(())
}
