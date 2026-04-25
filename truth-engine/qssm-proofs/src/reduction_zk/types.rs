//! Core enums, game definitions, and input/output structs for the ZK layer.

use crate::ClaimType;
use qssm_le::{N, PublicInstance, VerifyingKey};
use serde::{Deserialize, Serialize};

// ── Core enums ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimulationStrategy {
    DistributionCollapse,
    ProgramSimulation,
}

impl SimulationStrategy {
    #[must_use]
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::DistributionCollapse => b"zk_dist_collapse_v1",
            Self::ProgramSimulation => b"zk_program_sim_v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStatus {
    ByConstruction,
    Conditional,
    BoundedUnderAssumptions,
    KnownProofConditionsNotMet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureClass {
    Structural,
    Parametric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GameSystem {
    Ms,
    Le,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    Satisfied,
    NotSatisfied,
    Conditional,
    Bounded,
    Tbd,
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridTranscriptSource {
    RealProver,
    Simulator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistributionFamily {
    MsV2Real,
    MsV2Hybrid1,
    MsV2Hybrid2,
    MsV2Simulated,
    LeSetBReal,
    LeSetBSimulated,
    ComposedH0,
    ComposedH1,
    ComposedH2,
    ComposedH3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssumptionKind {
    HashBinding,
    RomProgrammability,
    LeHvzkBound,
    DomainSeparation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssumptionId {
    A1,
    A2,
    A4,
}

impl AssumptionId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::A1 => "A1",
            Self::A2 => "A2",
            Self::A4 => "A4",
        }
    }
}

// ── Transcript surface ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptSurfaceDefinition {
    pub system: GameSystem,
    pub visible_fields: Vec<String>,
}

// ── Simulator log / failure ────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatorLogEntry {
    pub step: String,
    pub detail: String,
    pub requires_witness: bool,
    pub uses_independent_sampling: bool,
    pub uses_random_oracle_programming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatorFailure {
    pub class: FailureClass,
    pub location: String,
    pub detail: String,
}

// ── Public inputs ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsHiddenValuePublicInput {
    pub commitment_bit_points: Vec<[u8; 32]>,
    pub target: u64,
    pub binding_entropy: [u8; 32],
    pub binding_context: [u8; 32],
    pub context: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LePublicInput {
    pub vk: VerifyingKey,
    pub public: PublicInstance,
    pub binding_context: [u8; 32],
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QssmPublicInput {
    pub ms: MsHiddenValuePublicInput,
    pub le: LePublicInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QssmWitnessFixture {
    pub ms_statement: MsPublicStatement,
    pub le_witness_coeffs: [i32; N],
}

// ── MS public statement ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsPublicStatement {
    pub value: u64,
    pub target: u64,
    pub binding_entropy: [u8; 32],
    pub binding_context: [u8; 32],
    pub context: Vec<u8>,
}

impl MsPublicStatement {
    pub fn validate_yes_instance(&self) -> Result<(), super::ZkSimulationError> {
        if self.value <= self.target {
            return Err(super::ZkSimulationError::UnsatisfiedStatement);
        }
        Ok(())
    }
}

// ── Error type ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ZkSimulationError {
    #[error("simulation requires a satisfiable public statement (value must be > target)")]
    UnsatisfiedStatement,
    #[error("no valid nonce / bit pair found for the public statement")]
    NoValidNoncePair,
    #[error("merkle simulation failed: {0}")]
    Merkle(#[from] qssm_utils::MerkleError),
    #[error("ms transcript generation failed: {0}")]
    Ms(#[from] qssm_ms::MsError),
    #[error("le transcript generation failed: {0}")]
    Le(#[from] qssm_le::LeError),
    #[error("theorem invariant failed: {0}")]
    TheoremInvariant(String),
}

// ── Security claim row ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityClaimRow {
    pub component: String,
    pub property: String,
    pub status: ClaimStatus,
    pub notes: String,
}
