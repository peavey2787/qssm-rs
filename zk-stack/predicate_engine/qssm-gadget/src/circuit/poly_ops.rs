//! Poly-Ops: typed composition, **`PolyOpContext`** degree rails, phased **`BindingReservoir`**,
//! **`TranscriptMap`** vs `qssm-le`, and **`ProverPackageBuilder`** for `prover_package.json`.
//!
//! Pipes share one **`ConstraintSystem`** and one cumulative **`PolyOpContext`** across stages
//! ([`OpPipe`]). Public-binding nominations from **`B`** may depend on **`A::Output`**; merge order
//! is **`A::public_binding_requirements_for_input`** then **`B::public_binding_requirements_for_input`**.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use serde::ser::SerializeMap;
use serde::Serialize;
use serde::Serializer;
use serde_json::json;

use qssm_utils::hashing::{hash_domain, LE_FS_PUBLIC_BINDING_LAYOUT_VERSION};
use qssm_utils::{blake3_hash, validate_entropy_full, EntropyAuditError};

use super::binding::{SovereignWitness, DIGEST_COEFF_VECTOR_SIZE};
use super::r1cs::{Blake3Gadget, ConstraintSystem, R1csLineExporter, VarId, VarKind};
use crate::blake3_compress::hash_merkle_parent_witness;
use crate::merkle::MERKLE_DEPTH_MS;
use crate::primitives::blake3_compress::MerkleParentHashWitness;
use crate::prover_json::{
    merkle_parent_hash_witness_value, merkle_parent_private_wire_count,
    sovereign_private_wire_count,
};

#[cfg(feature = "ms-engine-b")]
use qssm_ms::{verify as ms_verify, GhostMirrorProof, Root as MsRoot};

/// Merkle witness JSON with optional **`r1cs_refresh_private_wires`** tail (Index-Append metadata).
#[must_use]
pub fn merkle_parent_hash_witness_value_with_refresh(
    w: &MerkleParentHashWitness,
    refresh: &[CopyRefreshMeta],
) -> serde_json::Value {
    let mut v = merkle_parent_hash_witness_value(w);
    if !refresh.is_empty() {
        if let Some(o) = v.as_object_mut() {
            o.insert(
                "r1cs_refresh_private_wires".into(),
                serde_json::to_value(refresh).expect("refresh_metadata serde"),
            );
        }
    }
    v
}

/// Pretty JSON for Merkle parent witness including copy-refresh rows for hardware provers.
#[must_use]
pub fn merkle_parent_hash_witness_to_prover_json_with_refresh(
    w: &MerkleParentHashWitness,
    refresh: &[CopyRefreshMeta],
) -> String {
    serde_json::to_string_pretty(&merkle_parent_hash_witness_value_with_refresh(w, refresh))
        .expect("merkle parent witness json")
}

// ---------------------------------------------------------------------------
// Dead man's switch: gadget TranscriptMap must bump with qssm-utils when LE FS packing changes.
// ---------------------------------------------------------------------------

/// Must equal [`qssm_utils::hashing::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`].
pub const TRANSCRIPT_MAP_LAYOUT_VERSION: u32 = 1;
const DOMAIN_SEAM_COMMIT_V1: &str = "QSSM-SEAM-COMMIT-v1";
const DOMAIN_SEAM_OPEN_V1: &str = "QSSM-SEAM-OPEN-v1";
const DOMAIN_SEAM_BINDING_V1: &str = "QSSM-SEAM-BINDING-v1";

const _: () = assert!(
    TRANSCRIPT_MAP_LAYOUT_VERSION == LE_FS_PUBLIC_BINDING_LAYOUT_VERSION,
    "bump TRANSCRIPT_MAP_LAYOUT_VERSION when TranscriptMap / engine_a_public layout changes, then sync qssm-utils LE_FS_PUBLIC_BINDING_LAYOUT_VERSION with qssm-le commit.rs"
);

// ---------------------------------------------------------------------------
// TranscriptMap — `engine_a_public` key order (must match lattice_bridge / prover_package consumers).
// ---------------------------------------------------------------------------

/// JSON keys under `engine_a_public` in **canonical wire order** (digest mode for L2 handshake).
pub const ENGINE_A_PUBLIC_KEYS_IN_ORDER: &[&str] = &["message_limb_u30", "digest_coeff_vector_u4"];

// ---------------------------------------------------------------------------
// PolyOpContext + errors
// ---------------------------------------------------------------------------

/// One R1CS **copy-refresh** edge: new private wire equal to an older high-depth boolean wire.
///
/// Emitted in `prover_package.json` as **`refresh_metadata`** (machine-readable for analytics /
/// hardware witness assignment). Indices are **`VarId.0`** in allocation order for the active
/// [`R1csLineExporter`](super::r1cs::R1csLineExporter) / synthesizer.
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
/// [`ProverPackageBuilder`] records a high-degree-pressure warning.
pub const DEFAULT_REFRESH_PRESSURE_WARN_RATIO: f64 = 0.15;

/// Tracks multiplicative depth for XOR **and** gates (`and_xy = x · y` on boolean wires).
#[derive(Debug)]
pub struct PolyOpContext {
    segment: String,
    /// Per `VarId.0`, multiplicative depth (0 = fresh / linear-only use as AND input).
    mul_depth: Vec<u8>,
    /// First `DegreeExceeded` observed during synthesis (Poison remaining hooks).
    degree_violation: Option<DegreeExceeded>,
    /// Sound R1CS copy-refreshes (see [`refresh_boolean_wire_copy`]).
    pub refresh_metadata: Vec<CopyRefreshMeta>,
    pub manual_refresh_count: u32,
    pub auto_refresh_count: u32,
    /// When set, [`PolyOpTracingCs`] may insert copy-refreshes before XOR binary products (spec: deepest-first, left tie).
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

#[derive(Debug, thiserror::Error)]
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

    fn push_refresh_meta(
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

    fn ensure_len(&mut self, len: usize) {
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

// ---------------------------------------------------------------------------
// ConstraintSystem wrapper — threads PolyOpContext into XOR hooks.
// ---------------------------------------------------------------------------

pub struct PolyOpTracingCs<'a, C: ConstraintSystem> {
    pub inner: &'a mut C,
    pub ctx: &'a mut PolyOpContext,
}

impl<'a, C: ConstraintSystem> PolyOpTracingCs<'a, C> {
    /// Sound copy-refresh: new private wire **`fresh`**, **`enforce_equal(fresh, old)`**, depth **0** for **`fresh`**.
    ///
    /// Records [`CopyRefreshMeta`] with **`kind: "manual"`** for [`PolyOpContext::refresh_metadata`].
    pub fn refresh_boolean_wire_copy(
        &mut self,
        old: VarId,
        label: &str,
        segment: Option<&str>,
    ) -> VarId {
        let fresh = self.allocate_variable(VarKind::Private);
        self.inner.enforce_equal(fresh, old);
        self.ctx.reset_wire_mul_depth_zero(fresh);
        let seg = segment
            .map(|s| s.to_string())
            .or_else(|| Some(self.ctx.segment.clone()));
        self.ctx
            .push_refresh_meta(fresh.0, old.0, label.to_string(), seg, "manual");
        self.ctx.manual_refresh_count = self.ctx.manual_refresh_count.saturating_add(1);
        fresh
    }

    fn refresh_boolean_wire_copy_auto(&mut self, old: VarId, label: &str) -> VarId {
        let fresh = self.allocate_variable(VarKind::Private);
        self.inner.enforce_equal(fresh, old);
        self.ctx.reset_wire_mul_depth_zero(fresh);
        self.ctx.push_refresh_meta(
            fresh.0,
            old.0,
            label.to_string(),
            Some(self.ctx.segment.clone()),
            "auto_xor",
        );
        self.ctx.auto_refresh_count = self.ctx.auto_refresh_count.saturating_add(1);
        fresh
    }
}

impl<C: ConstraintSystem> ConstraintSystem for PolyOpTracingCs<'_, C> {
    fn allocate_variable(&mut self, kind: VarKind) -> VarId {
        self.inner.allocate_variable(kind)
    }

    fn enforce_xor(&mut self, mut x: VarId, mut y: VarId, and_xy: VarId, z: VarId) {
        if self.ctx.auto_refresh_enabled {
            let dx = self.ctx.wire_mul_depth(x);
            let dy = self.ctx.wire_mul_depth(y);
            if dx >= 1 && dy >= 1 {
                let refresh_left = if dx > dy {
                    true
                } else if dy > dx {
                    false
                } else {
                    true
                };
                let label = format!("auto_xor:{}:lhs{}_rhs{}", self.ctx.segment, x.0, y.0);
                if refresh_left {
                    let old_x = x;
                    x = self.refresh_boolean_wire_copy_auto(old_x, &label);
                } else {
                    let old_y = y;
                    y = self.refresh_boolean_wire_copy_auto(old_y, &label);
                }
            }
        }
        if let Err(e) = self
            .ctx
            .register_binary_product(x, y, and_xy, "enforce_xor")
        {
            self.ctx.degree_violation = Some(e);
            return;
        }
        self.inner.enforce_xor(x, y, and_xy, z);
    }

    fn enforce_full_adder(&mut self, a: VarId, b: VarId, cin: VarId, sum: VarId, cout: VarId) {
        self.inner.enforce_full_adder(a, b, cin, sum, cout);
    }

    fn enforce_equal(&mut self, a: VarId, b: VarId) {
        self.inner.enforce_equal(a, b);
    }
}

// ---------------------------------------------------------------------------
// Phased BindingReservoir
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingPhase {
    PreCommit = 0,
    PublicBinding = 1,
    Aux = 2,
}

/// Label for `BTreeMap` nominations within a phase.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingLabel(pub String);

#[derive(Debug, Clone)]
pub struct Nomination {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct BindingReservoir {
    /// Per-phase, ordered map of auxiliary nominations (canonical `Ord` on label).
    pub by_phase: BTreeMap<BindingPhase, BTreeMap<BindingLabel, Nomination>>,
}

impl BindingReservoir {
    pub fn nominate(
        &mut self,
        phase: BindingPhase,
        label: BindingLabel,
        bytes: Vec<u8>,
    ) -> Result<(), PolyOpError> {
        let phase_map = self.by_phase.entry(phase).or_default();
        if phase_map
            .insert(label.clone(), Nomination { bytes })
            .is_some()
        {
            return Err(PolyOpError::PhaseSlotConflict(format!(
                "duplicate nomination label {:?}",
                label.0
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public binding contract (per-op declaration)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct PublicBindingContract {
    pub nominations: Vec<(BindingPhase, BindingLabel, Nomination)>,
}

impl PublicBindingContract {
    /// Concatenate nominations in order **`self`** then **`other`**, rejecting duplicate **`(phase, label)`**.
    pub fn merge(&self, other: &Self) -> Result<Self, PolyOpError> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for (p, l, n) in self.nominations.iter().chain(other.nominations.iter()) {
            let key = (*p, l.0.clone());
            if !seen.insert(key) {
                return Err(PolyOpError::PhaseSlotConflict(format!(
                    "duplicate (phase, label) {:?} {:?}",
                    p, l.0
                )));
            }
            out.push((*p, l.clone(), n.clone()));
        }
        Ok(Self { nominations: out })
    }

    pub fn merge_into(&self, reservoir: &mut BindingReservoir) -> Result<(), PolyOpError> {
        for (phase, label, nom) in &self.nominations {
            reservoir.nominate(*phase, label.clone(), nom.bytes.clone())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LatticePolyOp + typed handles
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateRoot32(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct MerkleParentBlake3Output {
    pub witness: MerkleParentHashWitness,
    pub state_root: StateRoot32,
    pub r1cs_text: String,
    pub contract: PublicBindingContract,
}

#[derive(Debug, Clone)]
pub struct MerkleParentBlake3Op {
    pub leaf_left: [u8; 32],
    pub leaf_right: [u8; 32],
}

impl MerkleParentBlake3Op {
    #[must_use]
    pub fn new(leaf_left: [u8; 32], leaf_right: [u8; 32]) -> Self {
        Self {
            leaf_left,
            leaf_right,
        }
    }

    /// Convenience: Merkle compress then sovereign limb (see [`MerkleSovereignPipe`]).
    #[must_use]
    pub fn pipe_sovereign(self, sovereign_params: SovereignLimbV2Params) -> MerkleSovereignPipe {
        merkle_sovereign_pipe(self, sovereign_params)
    }

    pub fn public_binding_contract(&self) -> PublicBindingContract {
        let witness = hash_merkle_parent_witness(&self.leaf_left, &self.leaf_right);
        let root = witness.digest();
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("merkle_state_root".into()),
            Nomination {
                bytes: root.to_vec(),
            },
        ));
        c
    }
}

#[derive(Debug, Clone)]
pub struct SovereignLimbV2Params {
    pub binding_context: [u8; 32],
    pub n: u8,
    pub k: u8,
    pub bit_at_k: u8,
    pub challenge: [u8; 32],
    pub sovereign_entropy: [u8; 32],
    pub nist_included: bool,
    /// Optional **32**-byte digest (e.g. BLAKE3 of device raw noise). When present, it is XOR-mixed
    /// into the sovereign floor **before** [`SovereignWitness::bind`] (normative for non-replay across devices).
    pub device_entropy_link: Option<[u8; 32]>,
}

impl SovereignLimbV2Params {
    /// MS Fiat–Shamir **binding entropy** (`qssm_ms` transcript `entropy`): raw **device link** digest when set.
    ///
    /// Sovereign bind uses [`effective_sovereign_entropy`] (`sovereign_entropy XOR link`). MS must use the
    /// **same** `link` bytes here—never XOR the link with the floor again.
    #[must_use]
    pub fn ms_binding_entropy_digest(&self, fallback: [u8; 32]) -> [u8; 32] {
        self.device_entropy_link.unwrap_or(fallback)
    }
}

#[inline]
fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// Floor bytes actually fed into [`SovereignWitness::bind`] (post device XOR when configured).
#[must_use]
pub fn effective_sovereign_entropy(params: &SovereignLimbV2Params) -> [u8; 32] {
    match params.device_entropy_link {
        Some(h) => xor32(params.sovereign_entropy, h),
        None => params.sovereign_entropy,
    }
}

/// Second stage of the sovereign handshake: sovereign limb parameters only; input is the Merkle **state root**.
#[derive(Debug, Clone)]
pub struct SovereignLimbV2Stage {
    pub params: SovereignLimbV2Params,
}

/// Backward-compatible name for [`SovereignLimbV2Stage`].
pub type SovereignLimbV2Op = SovereignLimbV2Stage;

impl SovereignLimbV2Stage {
    #[must_use]
    pub fn new(params: SovereignLimbV2Params) -> Self {
        Self { params }
    }

    pub fn public_binding_contract_for_root(
        &self,
        state_root: StateRoot32,
    ) -> Result<PublicBindingContract, PolyOpError> {
        let ent = effective_sovereign_entropy(&self.params);
        let w = SovereignWitness::bind(
            state_root.0,
            self.params.binding_context,
            self.params.n,
            self.params.k,
            self.params.bit_at_k,
            self.params.challenge,
            ent,
            self.params.nist_included,
        );
        if !w.validate() {
            return Err(PolyOpError::Binding(
                "SovereignWitness::validate failed".into(),
            ));
        }
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("sovereign_digest_coeff_binding".into()),
            Nomination {
                bytes: w.digest.to_vec(),
            },
        ));
        Ok(c)
    }
}

/// Raw entropy injection: BLAKE3 digest for reservoir / sovereign **device_entropy_link** wiring.
#[derive(Debug, Clone)]
pub struct EntropyInjectionOp {
    /// When true, [`validate_entropy_full`] runs on the raw sample (density + χ² when long enough).
    pub enforce_distribution: bool,
}

impl EntropyInjectionOp {
    #[must_use]
    pub fn new(enforce_distribution: bool) -> Self {
        Self {
            enforce_distribution,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntropyInjectionOutput {
    pub digest: [u8; 32],
    pub raw_len: usize,
}

/// Input envelope for Engine-B -> Engine-A commit-then-open seam binding.
#[derive(Debug, Clone)]
pub struct EngineABindingInput {
    pub state_root: [u8; 32],
    pub ms_root: [u8; 32],
    pub relation_digest: [u8; 32],
    pub ms_fs_v2_challenge: [u8; 32],
    pub binding_context: [u8; 32],
    pub device_entropy_link: [u8; 32],
    /// Commitment provided by the proving side and opened by recomputation.
    pub claimed_seam_commitment: [u8; 32],
}

/// Output artifacts emitted by a successful commit-then-open seam check.
#[derive(Debug, Clone)]
pub struct EngineABindingOutput {
    pub seam_commitment_digest: [u8; 32],
    pub seam_open_digest: [u8; 32],
    pub seam_binding_digest: [u8; 32],
}

/// Real Engine-B -> Engine-A seam operator implementing commit-then-open.
#[derive(Debug, Clone, Copy, Default)]
pub struct EngineABindingOp;

impl EngineABindingOp {
    /// Commit digest:
    /// `H(DOMAIN_SEAM_COMMIT_V1 || state_root || ms_root || relation_digest || device_entropy_link || binding_context)`.
    #[must_use]
    pub fn commitment_digest(input: &EngineABindingInput) -> [u8; 32] {
        hash_domain(
            DOMAIN_SEAM_COMMIT_V1,
            &[
                input.state_root.as_slice(),
                input.ms_root.as_slice(),
                input.relation_digest.as_slice(),
                input.device_entropy_link.as_slice(),
                input.binding_context.as_slice(),
            ],
        )
    }

    #[must_use]
    pub fn open_digest(input: &EngineABindingInput, seam_commitment: [u8; 32]) -> [u8; 32] {
        hash_domain(
            DOMAIN_SEAM_OPEN_V1,
            &[
                seam_commitment.as_slice(),
                input.ms_fs_v2_challenge.as_slice(),
                input.binding_context.as_slice(),
            ],
        )
    }

    #[must_use]
    pub fn binding_digest(input: &EngineABindingInput, seam_open: [u8; 32]) -> [u8; 32] {
        hash_domain(
            DOMAIN_SEAM_BINDING_V1,
            &[
                seam_open.as_slice(),
                input.ms_root.as_slice(),
                input.state_root.as_slice(),
            ],
        )
    }
}

/// Adapter between MS reference proofs and sovereign / LE layers (feature **`ms-engine-b`**).
#[cfg(feature = "ms-engine-b")]
#[derive(Debug, Clone, Copy, Default)]
pub struct MsGhostMirrorOp;

#[cfg(feature = "ms-engine-b")]
#[derive(Debug, Clone)]
pub struct MsGhostMirrorInput {
    pub root: MsRoot,
    pub proof: GhostMirrorProof,
    pub binding_entropy: [u8; 32],
    pub value: u64,
    pub target: u64,
    pub context: Vec<u8>,
    pub binding_context: [u8; 32],
}

#[cfg(feature = "ms-engine-b")]
impl MsGhostMirrorInput {
    /// Same 32-byte digest as [`SovereignLimbV2Params::ms_binding_entropy_digest`] for `binding_entropy` wiring.
    #[must_use]
    pub fn binding_entropy_from_sovereign(params: &SovereignLimbV2Params, fallback: [u8; 32]) -> [u8; 32] {
        params.ms_binding_entropy_digest(fallback)
    }
}

#[cfg(feature = "ms-engine-b")]
#[derive(Debug, Clone)]
pub struct MsGhostMirrorOutput {
    pub fs_v2_challenge: [u8; 32],
    pub root: [u8; 32],
}

pub trait LatticePolyOp: Send + Sync {
    type Input;
    type Output;

    /// Static / input-agnostic nominations (default empty).
    fn get_public_binding_requirements(&self) -> PublicBindingContract {
        PublicBindingContract::default()
    }

    /// Nominations that may depend on **`input`** (e.g. Merkle root-dependent paths in a later stage).
    ///
    /// For [`OpPipe`], nominations from **`B`** are merged inside `synthesize_with_context` after
    /// **`A::Output`** is known; this method on `OpPipe` returns only **`A`**’s contract (see doc on [`OpPipe`]).
    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> PublicBindingContract {
        let _ = input;
        self.get_public_binding_requirements()
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError>;
}

#[cfg(feature = "ms-engine-b")]
impl LatticePolyOp for MsGhostMirrorOp {
    type Input = MsGhostMirrorInput;
    type Output = MsGhostMirrorOutput;

    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> PublicBindingContract {
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_fs_v2_challenge".into()),
            Nomination {
                bytes: input.proof.challenge.to_vec(),
            },
        ));
        c
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        _cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("ms_ghost_mirror");
        let ok = ms_verify(
            input.root,
            &input.proof,
            input.binding_entropy,
            input.value,
            input.target,
            &input.context,
            &input.binding_context,
        );
        if !ok {
            return Err(PolyOpError::Binding(
                "qssm_ms::verify returned false for GhostMirrorProof".into(),
            ));
        }
        Ok(MsGhostMirrorOutput {
            fs_v2_challenge: input.proof.challenge,
            root: input.root.0,
        })
    }
}

impl LatticePolyOp for MerkleParentBlake3Op {
    type Input = ();
    type Output = MerkleParentBlake3Output;

    fn get_public_binding_requirements(&self) -> PublicBindingContract {
        self.public_binding_contract()
    }

    fn public_binding_requirements_for_input(&self, _input: &Self::Input) -> PublicBindingContract {
        self.public_binding_contract()
    }

    fn synthesize_with_context(
        &self,
        _input: Self::Input,
        cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("merkle_parent_blake3");
        let witness = hash_merkle_parent_witness(&self.leaf_left, &self.leaf_right);
        if !witness.validate() {
            return Err(PolyOpError::Binding(
                "invalid MerkleParentHashWitness".into(),
            ));
        }
        let state_root = StateRoot32(witness.digest());
        {
            let mut trace = PolyOpTracingCs { inner: cs, ctx };
            Blake3Gadget::synthesize_merkle_parent_hash(&mut trace, &witness);
        }
        if let Some(e) = ctx.take_degree_violation() {
            return Err(PolyOpError::Degree(e));
        }
        let contract = self.public_binding_contract();
        Ok(MerkleParentBlake3Output {
            witness,
            state_root,
            r1cs_text: String::new(),
            contract,
        })
    }
}

impl LatticePolyOp for SovereignLimbV2Stage {
    type Input = StateRoot32;
    type Output = SovereignWitness;

    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> PublicBindingContract {
        self.public_binding_contract_for_root(*input)
            .expect("sovereign public binding contract")
    }

    fn synthesize_with_context(
        &self,
        state_root: Self::Input,
        _cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("sovereign_limb_v2");
        let ent = effective_sovereign_entropy(&self.params);
        let w = SovereignWitness::bind(
            state_root.0,
            self.params.binding_context,
            self.params.n,
            self.params.k,
            self.params.bit_at_k,
            self.params.challenge,
            ent,
            self.params.nist_included,
        );
        if !w.validate() {
            return Err(PolyOpError::Binding(
                "SovereignWitness::validate failed".into(),
            ));
        }
        Ok(w)
    }
}

impl LatticePolyOp for EntropyInjectionOp {
    type Input = Vec<u8>;
    type Output = EntropyInjectionOutput;

    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> PublicBindingContract {
        let digest = blake3_hash(input);
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PreCommit,
            BindingLabel("entropy_device_blake3".into()),
            Nomination {
                bytes: digest.to_vec(),
            },
        ));
        c
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        _cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("entropy_injection");
        if self.enforce_distribution {
            validate_entropy_full(&input)?;
        }
        let digest = blake3_hash(&input);
        Ok(EntropyInjectionOutput {
            digest,
            raw_len: input.len(),
        })
    }
}

impl LatticePolyOp for EngineABindingOp {
    type Input = EngineABindingInput;
    type Output = EngineABindingOutput;

    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> PublicBindingContract {
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_fs_v2_challenge".into()),
            Nomination {
                bytes: input.ms_fs_v2_challenge.to_vec(),
            },
        ));
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("engine_a_seam_commitment".into()),
            Nomination {
                bytes: input.claimed_seam_commitment.to_vec(),
            },
        ));
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("engine_a_seam_context_digest".into()),
            Nomination {
                bytes: input.binding_context.to_vec(),
            },
        ));
        c
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        _cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("engine_a_binding");
        let recomputed = Self::commitment_digest(&input);
        if recomputed != input.claimed_seam_commitment {
            return Err(PolyOpError::Binding(
                "engine_a seam commit-then-open mismatch".into(),
            ));
        }
        let seam_open = Self::open_digest(&input, recomputed);
        let seam_binding = Self::binding_digest(&input, seam_open);
        Ok(EngineABindingOutput {
            seam_commitment_digest: recomputed,
            seam_open_digest: seam_open,
            seam_binding_digest: seam_binding,
        })
    }
}

// ---------------------------------------------------------------------------
// OpPipe — generic pair; shared `cs` + cumulative `ctx` across both stages.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OpPipe<A, B> {
    pub first: A,
    pub second: B,
}

impl<A, B> OpPipe<A, B> {
    #[must_use]
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A, B, I, M, O> LatticePolyOp for OpPipe<A, B>
where
    A: LatticePolyOp<Input = I, Output = M>,
    B: LatticePolyOp<Input = M, Output = O>,
{
    type Input = I;
    type Output = O;

    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> PublicBindingContract {
        self.first.public_binding_requirements_for_input(input)
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        let mid = self.first.synthesize_with_context(input, cs, ctx)?;
        self.second.synthesize_with_context(mid, cs, ctx)
    }
}

pub trait LatticePolyOpThen: LatticePolyOp + Sized {
    fn then<B>(self, second: B) -> OpPipe<Self, B>
    where
        B: LatticePolyOp<Input = Self::Output>,
    {
        OpPipe::new(self, second)
    }
}

impl<T: LatticePolyOp + Sized> LatticePolyOpThen for T {}

/// Sovereign handshake: Merkle parent BLAKE3 compress witness → sovereign limb (typed root handoff).
pub type MerkleSovereignPipe = OpPipe<MerkleParentBlake3Op, SovereignLimbV2Stage>;

#[must_use]
pub fn merkle_sovereign_pipe(
    merkle: MerkleParentBlake3Op,
    sovereign_params: SovereignLimbV2Params,
) -> MerkleSovereignPipe {
    OpPipe::new(merkle, SovereignLimbV2Stage::new(sovereign_params))
}

impl OpPipe<MerkleParentBlake3Op, SovereignLimbV2Stage> {
    /// Binding entropy for MS `fs_challenge` when mirroring this pipe: raw [`device_entropy_link`](SovereignLimbV2Params::device_entropy_link) or `fallback`.
    #[must_use]
    pub fn ms_binding_entropy_for_fs_challenge(&self, fallback: [u8; 32]) -> [u8; 32] {
        self.second.params.ms_binding_entropy_digest(fallback)
    }

    /// Runs Merkle then sovereign on **one** constraint exporter and **one** cumulative context.
    pub fn run(&self, ctx: &mut PolyOpContext) -> Result<SovereignPipeOutput, PolyOpError> {
        let mut exporter = R1csLineExporter::new();
        let merkle_out = self.first.synthesize_with_context((), &mut exporter, ctx)?;
        let c_merged = self
            .first
            .public_binding_requirements_for_input(&())
            .merge(
                &self
                    .second
                    .public_binding_requirements_for_input(&merkle_out.state_root),
            )?;
        let mut reservoir = BindingReservoir::default();
        c_merged.merge_into(&mut reservoir)?;
        let sovereign =
            self.second
                .synthesize_with_context(merkle_out.state_root, &mut exporter, ctx)?;
        let mut merkle_out = merkle_out;
        merkle_out.r1cs_text = exporter.into_string();
        if !ctx.auto_refresh_enabled {
            debug_assert_eq!(merkle_out.r1cs_text.lines().count(), 65_184);
        }
        let refresh_metadata = ctx.take_refresh_metadata();
        Ok(SovereignPipeOutput {
            merkle: merkle_out,
            sovereign,
            reservoir,
            refresh_metadata,
        })
    }
}

#[derive(Debug)]
pub struct SovereignPipeOutput {
    pub merkle: MerkleParentBlake3Output,
    pub sovereign: SovereignWitness,
    pub reservoir: BindingReservoir,
    /// R1CS copy-refreshes from Merkle (and later stages if any); taken from [`PolyOpContext`] at end of [`OpPipe::run`].
    pub refresh_metadata: Vec<CopyRefreshMeta>,
}

// ---------------------------------------------------------------------------
// ProverPackageBuilder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EngineAPublicJson {
    pub message_limb_u30: u64,
    pub digest_coeff_vector_u4: Vec<u32>,
}

impl Serialize for EngineAPublicJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut m = serializer.serialize_map(Some(ENGINE_A_PUBLIC_KEYS_IN_ORDER.len()))?;
        m.serialize_entry("message_limb_u30", &self.message_limb_u30)?;
        m.serialize_entry("digest_coeff_vector_u4", &self.digest_coeff_vector_u4)?;
        m.end()
    }
}

impl EngineAPublicJson {
    pub fn from_sovereign(w: &SovereignWitness) -> Self {
        Self {
            message_limb_u30: w.message_limb,
            digest_coeff_vector_u4: w.digest_coeff_vector.to_vec(),
        }
    }

    /// Validates key order and coeff count against [`TranscriptMap`].
    pub fn validate_transcript_map(&self) -> Result<(), PolyOpError> {
        if self.digest_coeff_vector_u4.len() != DIGEST_COEFF_VECTOR_SIZE {
            return Err(PolyOpError::TranscriptMapViolation(format!(
                "digest_coeff_vector_u4 len {} want {}",
                self.digest_coeff_vector_u4.len(),
                DIGEST_COEFF_VECTOR_SIZE
            )));
        }
        for &k in ENGINE_A_PUBLIC_KEYS_IN_ORDER {
            let ok = match k {
                "message_limb_u30" => true,
                "digest_coeff_vector_u4" => true,
                _ => false,
            };
            if !ok {
                return Err(PolyOpError::TranscriptMapViolation(format!(
                    "unknown engine_a_public key {k}"
                )));
            }
        }
        Ok(())
    }

    /// JSON value with **canonical key order** (see [`Serialize`] impl).
    pub fn to_ordered_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("engine_a_public json")
    }
}

#[derive(Debug, Clone)]
pub struct SovereignHandshakeArtifacts {
    pub anchor_hash: [u8; 32],
    pub leaf_left: [u8; 32],
    pub leaf_right: [u8; 32],
    pub nist_included: bool,
}

/// Optional gates for [`ProverPackageBuilder::build_sovereign_handshake_v1_with_options`].
#[derive(Debug, Clone, Default)]
pub struct SovereignBuildOptions {
    /// Raw bytes whose BLAKE3 digest may match [`SovereignLimbV2Params::device_entropy_link`].
    ///
    /// When `device_entropy_link` is **Some**, this sample is **required**: it must hash to that digest
    /// and pass [`qssm_utils::validate_entropy_full`] (density + χ²) or the build fails with [`PolyOpError::WeakEntropy`].
    ///
    /// When [`Self::reject_weak_entropy_sample`] is true and this is set, the same full audit runs even
    /// without a device link.
    pub entropy_sample_for_audit: Option<Vec<u8>>,
    pub reject_weak_entropy_sample: bool,
    /// When true, Merkle BLAKE3 synthesis uses **deepest-first** auto copy-refresh on XOR products (see gadget spec).
    pub auto_refresh_merkle_xor: bool,
    /// Override for [`DEFAULT_REFRESH_PRESSURE_WARN_RATIO`] (fraction of R1CS lines).
    pub refresh_pressure_warn_ratio: Option<f64>,
}

pub struct ProverPackageBuilder;

impl ProverPackageBuilder {
    /// Writes `prover_package.json`, witness JSON files, and R1CS manifest under `assets_dir`.
    pub fn build_sovereign_handshake_v1(
        assets_dir: &Path,
        pipe: &MerkleSovereignPipe,
        meta: &SovereignHandshakeArtifacts,
    ) -> Result<SovereignPipeOutput, PolyOpError> {
        Self::build_sovereign_handshake_v1_with_options(assets_dir, pipe, meta, &SovereignBuildOptions::default())
    }

    pub fn build_sovereign_handshake_v1_with_options(
        assets_dir: &Path,
        pipe: &MerkleSovereignPipe,
        meta: &SovereignHandshakeArtifacts,
        opts: &SovereignBuildOptions,
    ) -> Result<SovereignPipeOutput, PolyOpError> {
        if let Some(expected) = pipe.second.params.device_entropy_link {
            let raw = opts.entropy_sample_for_audit.as_deref().ok_or_else(|| {
                PolyOpError::Binding(
                    "entropy_sample_for_audit is required when sovereign device_entropy_link is set (prover entropy audit)"
                        .into(),
                )
            })?;
            if blake3_hash(raw) != expected {
                return Err(PolyOpError::Binding(
                    "entropy_sample_for_audit must BLAKE3-hash to device_entropy_link".into(),
                ));
            }
            validate_entropy_full(raw)?;
        } else if opts.reject_weak_entropy_sample {
            if let Some(ref sample) = opts.entropy_sample_for_audit {
                validate_entropy_full(sample)?;
            }
        }
        fs::create_dir_all(assets_dir)?;
        let mut ctx = PolyOpContext::new("sovereign_handshake_v1");
        ctx.set_auto_refresh_enabled(opts.auto_refresh_merkle_xor);
        let out = pipe.run(&mut ctx)?;
        let engine_public = EngineAPublicJson::from_sovereign(&out.sovereign);
        engine_public.validate_transcript_map()?;

        let sovereign_json = out.sovereign.to_prover_json();
        fs::write(
            assets_dir.join("sovereign_witness.json"),
            sovereign_json.as_str(),
        )?;

        let merkle_json = merkle_parent_hash_witness_to_prover_json_with_refresh(
            &out.merkle.witness,
            &out.refresh_metadata,
        );
        fs::write(
            assets_dir.join("merkle_parent_witness.json"),
            merkle_json.as_str(),
        )?;

        fs::write(
            assets_dir.join("r1cs_merkle_parent.manifest.txt"),
            out.merkle.r1cs_text.as_str(),
        )?;

        let sovereign_private_wires = sovereign_private_wire_count();
        let merkle_wires = merkle_parent_private_wire_count(&out.merkle.witness)
            .saturating_add(out.refresh_metadata.len());
        let r1cs_lines = out.merkle.r1cs_text.lines().count();
        let refresh_copies = out.refresh_metadata.len();
        let ratio = (refresh_copies as f64) / (r1cs_lines.max(1) as f64);
        let threshold = opts
            .refresh_pressure_warn_ratio
            .unwrap_or(DEFAULT_REFRESH_PRESSURE_WARN_RATIO);
        let mut warnings = Vec::<String>::new();
        if ratio >= threshold && refresh_copies > 0 {
            warnings.push(format!(
                "High degree pressure: copy-refresh count ({refresh_copies}) / R1CS constraint lines ({r1cs_lines}) = {:.2}% (threshold {:.1}%) — reconsider gadget layering or disable auto-refresh.",
                ratio * 100.0,
                threshold * 100.0
            ));
        }

        let refresh_meta_value = serde_json::to_value(&out.refresh_metadata)?;
        let warnings_value = serde_json::to_value(&warnings)?;

        let package = json!({
            "package_version": "qssm-sovereign-handshake-v1",
            "description": "Sovereign handshake: Merkle parent (BLAKE3 compress witness) + Sovereign limb for Engine A",
            "sim_anchor_hash_hex": hex::encode(meta.anchor_hash),
            "merkle_leaf_left_hex": hex::encode(meta.leaf_left),
            "merkle_leaf_right_hex": hex::encode(meta.leaf_right),
            "rollup_state_root_hex": hex::encode(out.merkle.state_root.0),
            "nist_beacon_included": meta.nist_included,
            "engine_a_public": engine_public.to_ordered_json_value(),
            "artifacts": {
                "sovereign_witness_json": "sovereign_witness.json",
                "merkle_parent_witness_json": "merkle_parent_witness.json",
                "r1cs_merkle_manifest_txt": "r1cs_merkle_parent.manifest.txt",
            },
            "witness_wire_counts": {
                "sovereign_private_bit_wires": sovereign_private_wires,
                "merkle_parent_private_bit_wires": merkle_wires,
            },
            "r1cs": {
                "constraint_line_count": r1cs_lines,
                "manifest_file": "r1cs_merkle_parent.manifest.txt",
                "line_format": "xor|full_adder|equal with tab-separated var indices",
            },
            "poly_ops": {
                "transcript_map_layout_version": TRANSCRIPT_MAP_LAYOUT_VERSION,
                "merkle_depth": MERKLE_DEPTH_MS,
                "refresh_copy_count": refresh_copies,
                "auto_refresh_merkle_xor": opts.auto_refresh_merkle_xor,
            },
            "refresh_metadata": refresh_meta_value,
            "warnings": warnings_value,
        });

        fs::write(
            assets_dir.join("prover_package.json"),
            serde_json::to_string_pretty(&package)?,
        )?;

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{MockProver, VarKind};
    use tempfile::tempdir;

    #[test]
    fn transcript_map_version_matches_utils() {
        assert_eq!(
            TRANSCRIPT_MAP_LAYOUT_VERSION,
            LE_FS_PUBLIC_BINDING_LAYOUT_VERSION
        );
    }

    #[test]
    fn poly_op_tracing_cs_merkle_synthesis_ok() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let w = hash_merkle_parent_witness(&left, &right);
        let mut ctx = PolyOpContext::new("test");
        let mut m = MockProver::new();
        {
            let mut trace = PolyOpTracingCs {
                inner: &mut m,
                ctx: &mut ctx,
            };
            Blake3Gadget::synthesize_merkle_parent_hash(&mut trace, &w);
        }
        assert_eq!(m.constraint_count(), 65_184);
    }

    #[test]
    fn degree_exceeded_carries_var_ids() {
        let mut ctx = PolyOpContext::new("deg");
        let x = VarId(0);
        let y = VarId(1);
        let and1 = VarId(2);
        ctx.register_binary_product(x, y, and1, "test").unwrap();
        ctx.ensure_len(6);
        ctx.mul_depth[3] = 1;
        ctx.mul_depth[4] = 1;
        let e = ctx
            .register_binary_product(VarId(3), VarId(4), VarId(5), "boom")
            .unwrap_err();
        assert_eq!(e.lhs, VarId(3));
        assert_eq!(e.rhs, VarId(4));
        assert_eq!(e.and_out, VarId(5));
    }

    #[test]
    fn binding_reservoir_btree_labels_are_canonical_order() {
        let mut a = BindingReservoir::default();
        a.nominate(BindingPhase::Aux, BindingLabel("zebra".into()), vec![1])
            .unwrap();
        a.nominate(BindingPhase::Aux, BindingLabel("alpha".into()), vec![2])
            .unwrap();
        let keys: Vec<_> = a
            .by_phase
            .get(&BindingPhase::Aux)
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys[0].0, "alpha");
        assert_eq!(keys[1].0, "zebra");
    }

    #[test]
    fn engine_a_public_json_key_order() {
        let root = [9u8; 32];
        let rollup = [8u8; 32];
        let ch = [7u8; 32];
        let ent = [6u8; 32];
        let w = SovereignWitness::bind(root, rollup, 1, 2, 0, ch, ent, false);
        let e = EngineAPublicJson::from_sovereign(&w);
        e.validate_transcript_map().unwrap();
        let v = e.to_ordered_json_value();
        let keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            vec![
                "message_limb_u30".to_string(),
                "digest_coeff_vector_u4".to_string()
            ]
        );
    }

    #[test]
    fn public_binding_contract_merge_rejects_duplicate_label() {
        let mut a = PublicBindingContract::default();
        a.nominations.push((
            BindingPhase::Aux,
            BindingLabel("x".into()),
            Nomination { bytes: vec![1] },
        ));
        let mut b = PublicBindingContract::default();
        b.nominations.push((
            BindingPhase::Aux,
            BindingLabel("x".into()),
            Nomination { bytes: vec![2] },
        ));
        assert!(a.merge(&b).is_err());
    }

    fn sovereign_pipe_shared_ctx_merkle_then_sovereign_ok_inner() {
        let left = blake3_hash(b"L");
        let right = blake3_hash(b"R");
        let rollup = [5u8; 32];
        let pipe = merkle_sovereign_pipe(
            MerkleParentBlake3Op::new(left, right),
            SovereignLimbV2Params {
                binding_context: rollup,
                n: 1,
                k: 0,
                bit_at_k: 0,
                challenge: [6u8; 32],
                sovereign_entropy: [7u8; 32],
                nist_included: false,
                device_entropy_link: None,
            },
        );
        let mut ctx = PolyOpContext::new("pipe");
        let out = pipe.run(&mut ctx).expect("run");
        assert_eq!(out.merkle.r1cs_text.lines().count(), 65_184);
        assert!(out.sovereign.validate());
    }

    #[test]
    fn sovereign_pipe_shared_ctx_merkle_then_sovereign_ok() {
        const STACK: usize = 32 * 1024 * 1024;
        std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(sovereign_pipe_shared_ctx_merkle_then_sovereign_ok_inner)
            .expect("spawn")
            .join()
            .expect("join panicked");
    }

    fn device_entropy_link_xor_changes_engine_a_public_inner() {
        let left = blake3_hash(b"A");
        let right = blake3_hash(b"B");
        let rollup = [1u8; 32];
        let ch = [2u8; 32];
        let floor = [3u8; 32];
        let link = [0xFFu8; 32];
        let merkle = MerkleParentBlake3Op::new(left, right);
        let root = merkle
            .clone()
            .pipe_sovereign(SovereignLimbV2Params {
                binding_context: rollup,
                n: 0,
                k: 0,
                bit_at_k: 0,
                challenge: ch,
                sovereign_entropy: floor,
                nist_included: false,
                device_entropy_link: None,
            })
            .run(&mut PolyOpContext::new("a"))
            .expect("a")
            .sovereign;
        let with_link = merkle
            .pipe_sovereign(SovereignLimbV2Params {
                binding_context: rollup,
                n: 0,
                k: 0,
                bit_at_k: 0,
                challenge: ch,
                sovereign_entropy: floor,
                nist_included: false,
                device_entropy_link: Some(link),
            })
            .run(&mut PolyOpContext::new("b"))
            .expect("b")
            .sovereign;
        assert_ne!(root.message_limb, with_link.message_limb);
    }

    #[test]
    fn device_entropy_link_xor_changes_engine_a_public() {
        const STACK: usize = 32 * 1024 * 1024;
        std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(device_entropy_link_xor_changes_engine_a_public_inner)
            .expect("spawn")
            .join()
            .expect("join panicked");
    }

    #[test]
    fn ms_binding_entropy_for_fs_challenge_is_raw_device_link() {
        let floor = [3u8; 32];
        let link = [0xABu8; 32];
        let pipe = merkle_sovereign_pipe(
            MerkleParentBlake3Op::new([1u8; 32], [2u8; 32]),
            SovereignLimbV2Params {
                binding_context: [0u8; 32],
                n: 0,
                k: 0,
                bit_at_k: 0,
                challenge: [0u8; 32],
                sovereign_entropy: floor,
                nist_included: false,
                device_entropy_link: Some(link),
            },
        );
        let fallback = [9u8; 32];
        assert_eq!(pipe.ms_binding_entropy_for_fs_challenge(fallback), link);
        assert_eq!(pipe.second.params.ms_binding_entropy_digest(fallback), link);
        assert_eq!(effective_sovereign_entropy(&pipe.second.params), xor32(floor, link));
    }

    #[test]
    fn prover_build_device_link_requires_entropy_sample() {
        let dir = tempdir().expect("tempdir");
        let left = blake3_hash(b"x");
        let right = blake3_hash(b"y");
        let pipe = merkle_sovereign_pipe(
            MerkleParentBlake3Op::new(left, right),
            SovereignLimbV2Params {
                binding_context: [1u8; 32],
                n: 0,
                k: 0,
                bit_at_k: 0,
                challenge: [2u8; 32],
                sovereign_entropy: [3u8; 32],
                nist_included: false,
                device_entropy_link: Some([7u8; 32]),
            },
        );
        let r = ProverPackageBuilder::build_sovereign_handshake_v1_with_options(
            dir.path(),
            &pipe,
            &SovereignHandshakeArtifacts {
                anchor_hash: [0u8; 32],
                leaf_left: left,
                leaf_right: right,
                nist_included: false,
            },
            &SovereignBuildOptions::default(),
        );
        match r {
            Err(PolyOpError::Binding(s)) => assert!(
                s.contains("entropy_sample_for_audit"),
                "unexpected message: {s}"
            ),
            other => panic!("expected Binding error, got {other:?}"),
        }
    }

    fn prover_build_device_link_with_audit_sample_ok_inner() {
        let dir = tempdir().expect("tempdir");
        let raw: Vec<u8> = (0u32..512)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
            .collect();
        validate_entropy_full(&raw).expect("audit sample should pass");
        let link = blake3_hash(&raw);
        let left = blake3_hash(b"L_AUDIT");
        let right = blake3_hash(b"R_AUDIT");
        let rollup = [5u8; 32];
        let pipe = merkle_sovereign_pipe(
            MerkleParentBlake3Op::new(left, right),
            SovereignLimbV2Params {
                binding_context: rollup,
                n: 0,
                k: 0,
                bit_at_k: 0,
                challenge: [6u8; 32],
                sovereign_entropy: [7u8; 32],
                nist_included: false,
                device_entropy_link: Some(link),
            },
        );
        ProverPackageBuilder::build_sovereign_handshake_v1_with_options(
            dir.path(),
            &pipe,
            &SovereignHandshakeArtifacts {
                anchor_hash: [8u8; 32],
                leaf_left: left,
                leaf_right: right,
                nist_included: false,
            },
            &SovereignBuildOptions {
                entropy_sample_for_audit: Some(raw),
                ..Default::default()
            },
        )
        .expect("build with device link + audit raw");
    }

    #[test]
    fn prover_build_device_link_with_audit_sample_ok() {
        const STACK: usize = 32 * 1024 * 1024;
        std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(prover_build_device_link_with_audit_sample_ok_inner)
            .expect("spawn")
            .join()
            .expect("join panicked");
    }

    #[test]
    fn entropy_injection_weak_bytes_err_when_enforced() {
        let op = EntropyInjectionOp::new(true);
        let bad = vec![0u8; 300];
        let mut ctx = PolyOpContext::new("e");
        let mut m = MockProver::new();
        let r = op.synthesize_with_context(bad, &mut m, &mut ctx);
        assert!(r.is_err());
    }

    #[test]
    fn manual_refresh_boolean_wire_copy_records_metadata() {
        let mut ctx = PolyOpContext::new("seg");
        let mut m = MockProver::new();
        let old = {
            let mut t = PolyOpTracingCs {
                inner: &mut m,
                ctx: &mut ctx,
            };
            t.allocate_variable(VarKind::Private)
        };
        let fresh = {
            let mut t = PolyOpTracingCs {
                inner: &mut m,
                ctx: &mut ctx,
            };
            t.refresh_boolean_wire_copy(old, "unit_copy", Some("seg_x"))
        };
        assert_ne!(fresh.0, old.0);
        assert_eq!(ctx.manual_refresh_count, 1);
        assert_eq!(ctx.auto_refresh_count, 0);
        assert_eq!(ctx.refresh_metadata.len(), 1);
        assert_eq!(ctx.refresh_metadata[0].label, "unit_copy");
        assert_eq!(ctx.refresh_metadata[0].kind, "manual");
    }

    #[test]
    fn auto_refresh_xor_inserts_equal_copy_on_depth_tie_left() {
        let mut ctx = PolyOpContext::new("auto");
        ctx.set_auto_refresh_enabled(true);
        let mut m = MockProver::new();
        let c0 = m.constraint_count();
        {
            let mut t = PolyOpTracingCs {
                inner: &mut m,
                ctx: &mut ctx,
            };
            let a0 = t.allocate_variable(VarKind::Private);
            let b0 = t.allocate_variable(VarKind::Private);
            let and0 = t.allocate_variable(VarKind::Private);
            let z0 = t.allocate_variable(VarKind::Private);
            t.enforce_xor(a0, b0, and0, z0);
            let a1 = t.allocate_variable(VarKind::Private);
            let b1 = t.allocate_variable(VarKind::Private);
            let and1 = t.allocate_variable(VarKind::Private);
            let z1 = t.allocate_variable(VarKind::Private);
            t.enforce_xor(a1, b1, and1, z1);
            let and_xy = t.allocate_variable(VarKind::Private);
            let z2 = t.allocate_variable(VarKind::Private);
            t.enforce_xor(and0, and1, and_xy, z2);
        }
        assert_eq!(ctx.auto_refresh_count, 1, "expected one auto-refresh");
        assert!(
            m.constraint_count() >= c0 + 4,
            "three xors plus one equal for copy-refresh (got {})",
            m.constraint_count()
        );
        let meta = &ctx.refresh_metadata[0];
        assert_eq!(meta.kind, "auto_xor");
        assert!(meta.label.contains("lhs"));
    }
}
