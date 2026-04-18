//! Degree tracking, error types, and copy-refresh metadata for poly-op orchestration.

#![forbid(unsafe_code)]

use std::fmt;

use serde::Serialize;
use thiserror::Error;

use qssm_utils::EntropyAuditError;

use super::r1cs::VarId;

/// One R1CS **copy-refresh** edge: new private wire equal to an older high-depth boolean wire.
///
/// Emitted in `prover_package.json` as **`refresh_metadata`** (machine-readable for analytics /
/// hardware witness assignment). Indices are **`VarId.0`** in allocation order for the active
/// synthesizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CopyRefreshMeta {
    pub new_idx: u32,
    pub old_idx: u32,
    /// Fine-grained site (e.g. `Blake3_Round_5`); use stable strings for analytics rollups.
    pub label: String,
    /// Coarser grouping (e.g. `merkle_parent_compression`); optional for manual refreshes.
    pub segment: Option<String>,
    /// `manual` | `auto_xor` for analytics.
    pub kind: &'static str,
}

/// Default ratio `(manual + auto refresh copies) / R1CS constraint lines` above which
/// downstream package builders should record a high-degree-pressure warning.
pub const DEFAULT_REFRESH_PRESSURE_WARN_RATIO: f64 = 0.15;

/// Tracks multiplicative depth for XOR **and** gates (`and_xy = x · y` on boolean wires).
#[derive(Debug)]
pub struct PolyOpContext {
    pub(crate) segment: String,
    /// Per `VarId.0`, multiplicative depth (0 = fresh / linear-only use as AND input).
    pub(crate) mul_depth: Vec<u8>,
    /// First `DegreeExceeded` observed during synthesis (Poison remaining hooks).
    pub(crate) degree_violation: Option<DegreeExceeded>,
    /// Sound R1CS copy-refreshes (see [`refresh_boolean_wire_copy`]).
    pub refresh_metadata: Vec<CopyRefreshMeta>,
    pub manual_refresh_count: u32,
    pub auto_refresh_count: u32,
    /// When set, [`PolyOpTracingCs`](super::cs_tracing::PolyOpTracingCs) may insert copy-refreshes before XOR binary products.
    pub auto_refresh_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegreeExceeded {
    pub lhs: VarId,
    pub rhs: VarId,
    pub and_out: VarId,
    pub segment: String,
    pub operation: &'static str,
}

impl fmt::Display for DegreeExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "degree-2 budget exceeded in segment {:?}: {} on wires lhs={} rhs={} (and_out={}); split with a fresh witness segment / refresh",
            self.segment, self.operation, self.lhs.0, self.rhs.0, self.and_out.0
        )
    }
}

impl std::error::Error for DegreeExceeded {}

#[derive(Debug, Error)]
pub enum PolyOpError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Degree(#[from] DegreeExceeded),
    /// Entropy audit failed (density + χ²), including prover-package device-link hard-stop.
    #[error(transparent)]
    WeakEntropy(#[from] EntropyAuditError),
    #[error("witness handle already consumed: {0}")]
    WitnessSpent(&'static str),
    #[error("binding: {0}")]
    Binding(String),
    #[error("phase slot conflict: {0}")]
    PhaseSlotConflict(String),
    #[error("transcript map: {0}")]
    TranscriptMapViolation(String),
}

impl PolyOpContext {
    #[must_use]
    pub fn new(segment: impl Into<String>) -> Self {
        Self {
            segment: segment.into(),
            mul_depth: Vec::new(),
            degree_violation: None,
            refresh_metadata: Vec::new(),
            manual_refresh_count: 0,
            auto_refresh_count: 0,
            auto_refresh_enabled: false,
        }
    }

    pub fn set_segment(&mut self, s: impl Into<String>) {
        self.segment = s.into();
    }

    pub fn set_auto_refresh_enabled(&mut self, enabled: bool) {
        self.auto_refresh_enabled = enabled;
    }

    #[must_use]
    pub fn total_refresh_count(&self) -> u32 {
        self.manual_refresh_count
            .saturating_add(self.auto_refresh_count)
    }

    pub fn take_degree_violation(&mut self) -> Option<DegreeExceeded> {
        self.degree_violation.take()
    }

    pub(crate) fn push_refresh_meta(
        &mut self,
        new_idx: u32,
        old_idx: u32,
        label: String,
        segment: Option<String>,
        kind: &'static str,
    ) {
        self.refresh_metadata.push(CopyRefreshMeta {
            new_idx,
            old_idx,
            label,
            segment,
            kind,
        });
    }

    /// Clears recorded copy metadata (counts unchanged) for reuse after a pipe stage.
    pub fn take_refresh_metadata(&mut self) -> Vec<CopyRefreshMeta> {
        std::mem::take(&mut self.refresh_metadata)
    }

    #[must_use]
    pub fn wire_mul_depth(&self, id: VarId) -> u8 {
        self.depth_of(id)
    }

    /// Force **`id`** to depth **0** after a sound **`enforce_equal`** copy (new allocation).
    pub(crate) fn reset_wire_mul_depth_zero(&mut self, id: VarId) {
        let i = id.0 as usize;
        if self.mul_depth.len() < i + 1 {
            self.mul_depth.resize(i + 1, 0);
        } else {
            self.mul_depth[i] = 0;
        }
    }

    pub(crate) fn ensure_len(&mut self, len: usize) {
        if self.mul_depth.len() < len {
            self.mul_depth.resize(len, 0);
        }
    }

    fn depth_of(&self, id: VarId) -> u8 {
        self.mul_depth.get(id.0 as usize).copied().unwrap_or(0)
    }

    /// Call for every boolean **`and_xy = x · y`** row before emitting the constraint.
    pub fn register_binary_product(
        &mut self,
        x: VarId,
        y: VarId,
        and_xy: VarId,
        operation: &'static str,
    ) -> Result<(), DegreeExceeded> {
        if self.degree_violation.is_some() {
            return Ok(());
        }
        let dx = self.depth_of(x);
        let dy = self.depth_of(y);
        if dx >= 1 && dy >= 1 {
            return Err(DegreeExceeded {
                lhs: x,
                rhs: y,
                and_out: and_xy,
                segment: self.segment.clone(),
                operation,
            });
        }
        let d = dx.max(dy).saturating_add(1);
        let idx = and_xy.0 as usize;
        self.ensure_len(idx + 1);
        self.mul_depth[idx] = self.mul_depth[idx].max(d);
        Ok(())
    }
}
