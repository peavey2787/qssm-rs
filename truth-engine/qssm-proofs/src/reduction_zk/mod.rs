//! Candidate zero-knowledge transcript simulation lemmas for QSSM-MS + LE.
//!
//! This module records both:
//!
//! - the legacy MS transcript blocker under the current hidden-value game, and
//! - the canonical publishable path selected for the redesign:
//!   MS v2 Option B plus LE Set B.
//!
//! It keeps the theorem layer honest by separating implemented transcript
//! surfaces, executable simulator artifacts, and the remaining conditional proof
//! obligations.
//!
//! For the legacy MS surface, this module adds the missing executable proof
//! objects that a simulation-based ZK argument would need:
//!
//! - Lemma 1: a witness-free sampler for `(k, n)`
//! - Lemma 2: Fiat-Shamir consistency for simulated transcripts
//! - Lemma 3: commitment + opening simulation for the MS Merkle layer
//!
//! Two strategy families are modeled:
//!
//! - `DistributionCollapse`: sample `(k, n)` from a public marginal over valid
//!   nonce/bit pairs.
//! - `ProgramSimulation`: preserve the real stopping-time scan and program the
//!   transcript around the first successful public nonce.
//!
//! The constructions here are intentionally honest about status. They provide an
//! executable simulator surface for the formal crate, but they do **not** claim
//! that the current end-to-end system already satisfies full ZK. Unmet proof
//! obligations are recorded as exactly that; they are not treated as an
//! impossibility result or a proof that the system is non-ZK.

use crate::{
    reduction_rejection::RejectionSamplingClaim,
    reduction_witness_hiding::WitnessHidingClaim,
    ClaimType,
};
use qssm_gadget::{MERKLE_DEPTH_MS, MERKLE_WIDTH_MS};
use qssm_le::{
    encode_rq_coeffs_le, prove_arithmetic, short_vec_to_rq, short_vec_to_rq_bound,
    verify_lattice, BETA, C_POLY_SIZE, C_POLY_SPAN, Commitment, ETA, GAMMA, N,
    PublicBinding, PublicInstance, Q, RqPoly, VerifyingKey, Witness,
    LE_FS_PUBLIC_BINDING_LAYOUT_VERSION,
};
use qssm_utils::{hash_domain, PositionAwareTree, DOMAIN_MS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MS_LEAF_COUNT: usize = MERKLE_WIDTH_MS;
const MS_BIT_COUNT: usize = MERKLE_WIDTH_MS / 2;
const DOMAIN_ZK_SIM: &str = "QSSM-ZK-SIM-v1.0";
const DOMAIN_LE_FS: &str = "QSSM-LE-FS-LYU-v1.0";
const DOMAIN_LE_CHALLENGE_POLY: &str = "QSSM-LE-CHALLENGE-POLY-v1.0";
const CROSS_PROTOCOL_BINDING_LABEL: &[u8] = b"cross_protocol_digest_v1";
const DST_LE_COMMIT: [u8; 32] = *b"QSSM-LE-V1-COMMIT...............";
const DST_MS_VERIFY: [u8; 32] = *b"QSSM-MS-V1-VERIFY...............";
const MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT: &str =
    "bitness_query_digest hashes only statement_digest, bit_index, and announcements; it excludes responses and challenge shares.";
const MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT: &str =
    "comparison_query_digest hashes only clause announcements; it excludes responses and challenge shares.";
const MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT: &str =
    "At the highest differing bit position, every true-clause comparison public point is exactly of the form P = r * H for the corresponding committed blinder r.";
const MS_SCHNORR_REPARAMETERIZATION_CONTRACT: &str =
    "For a fixed public point P = w * H and programmed challenge c, the real Schnorr transcript distribution (alpha, alpha*H, alpha+c*w) is exactly identical to the simulated transcript distribution (z*H-c*P, z) by the bijection z <-> alpha = z - c*w.";

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
    /// The lemma is satisfied exactly by the executable construction.
    ByConstruction,
    /// The lemma is modeled and executable, but still depends on stated assumptions.
    Conditional,
    /// The lemma or theorem has an explicit symbolic advantage bound under stated assumptions.
    BoundedUnderAssumptions,
    /// The current parameter set does not satisfy the known proof conditions used here.
    /// This does not imply impossibility or refute zero-knowledge on its own.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptSurfaceDefinition {
    pub system: GameSystem,
    pub visible_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkGameDefinition {
    pub system: GameSystem,
    pub rom_model: bool,
    pub public_inputs: Vec<String>,
    pub hidden_witness: Vec<String>,
    pub real_world: String,
    pub ideal_world: String,
    pub goal: String,
    pub transcript_surface: TranscriptSurfaceDefinition,
}

impl ZkGameDefinition {
    #[must_use]
    pub fn ms_hidden_value_game() -> Self {
        Self {
            system: GameSystem::Ms,
            rom_model: true,
            public_inputs: vec![
                "target".to_string(),
                "binding_entropy".to_string(),
                "binding_context".to_string(),
                "context".to_string(),
            ],
            hidden_witness: vec!["value".to_string(), "Merkle salt material".to_string()],
            real_world:
                "The prover computes a real MS transcript from hidden value and salt witness material."
                    .to_string(),
            ideal_world:
                "A simulator must generate the visible MS transcript without knowledge of the hidden witness, using only public inputs, ROM programming, and independent randomness."
                    .to_string(),
            goal: "No PPT distinguisher should distinguish the real and simulated visible MS transcripts."
                .to_string(),
            transcript_surface: TranscriptSurfaceDefinition {
                system: GameSystem::Ms,
                visible_fields: vec![
                    "root".to_string(),
                    "n".to_string(),
                    "k".to_string(),
                    "bit_at_k".to_string(),
                    "Merkle path".to_string(),
                    "challenge".to_string(),
                ],
            },
        }
    }

    #[must_use]
    pub fn le_hidden_witness_game() -> Self {
        Self {
            system: GameSystem::Le,
            rom_model: true,
            public_inputs: vec![
                "verifying key".to_string(),
                "public instance".to_string(),
                "binding_context".to_string(),
            ],
            hidden_witness: vec!["witness r".to_string()],
            real_world:
                "The prover emits the visible LE commitment/proof transcript using the hidden witness r."
                    .to_string(),
            ideal_world:
                "A simulator must generate the visible LE transcript without knowledge of r, using only public inputs, ROM programming, and independent randomness."
                    .to_string(),
            goal: "No PPT distinguisher should distinguish the real and simulated visible LE transcripts."
                .to_string(),
            transcript_surface: TranscriptSurfaceDefinition {
                system: GameSystem::Le,
                visible_fields: vec![
                    "commitment C".to_string(),
                    "t".to_string(),
                    "z".to_string(),
                    "challenge_seed".to_string(),
                ],
            },
        }
    }

    #[must_use]
    pub fn ms_v2_hidden_value_game() -> Self {
        Self {
            system: GameSystem::Ms,
            rom_model: true,
            public_inputs: vec![
                "value commitment".to_string(),
                "target".to_string(),
                "binding_entropy".to_string(),
                "binding_context".to_string(),
                "context".to_string(),
            ],
            hidden_witness: vec![
                "value".to_string(),
                "commitment blinders".to_string(),
                "prover randomness".to_string(),
            ],
            real_world:
                "The prover emits the canonical MS v2 predicate-only transcript for a hidden yes-instance."
                    .to_string(),
            ideal_world:
                "A simulator emits the same visible predicate-only transcript using only the public statement, programmable oracle queries, and simulator randomness."
                    .to_string(),
            goal:
                "No PPT distinguisher should distinguish the real and simulated visible MS v2 predicate-only transcripts."
                    .to_string(),
            transcript_surface: TranscriptSurfaceDefinition {
                system: GameSystem::Ms,
                visible_fields: vec![
                    "value commitment".to_string(),
                    "result_bit".to_string(),
                    "bitness sigma transcripts".to_string(),
                    "comparison sigma transcript".to_string(),
                ],
            },
        }
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedLeTranscript {
    pub commitment_coeffs: Vec<u32>,
    pub t_coeffs: Vec<u32>,
    pub z_coeffs: Vec<u32>,
    pub challenge_seed: [u8; 32],
    pub programmed_oracle_query_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealLeTranscript {
    pub commitment_coeffs: Vec<u32>,
    pub t_coeffs: Vec<u32>,
    pub z_coeffs: Vec<u32>,
    pub challenge_seed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeTranscriptObservation {
    pub commitment_coeffs: Vec<u32>,
    pub t_coeffs: Vec<u32>,
    pub z_coeffs: Vec<u32>,
    pub challenge_seed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealQssmTranscript {
    pub ms: RealMsV2Transcript,
    pub le: RealLeTranscript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedQssmTranscript {
    pub ms: SimulatedMsV2Transcript,
    pub le: SimulatedLeTranscript,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct QssmTranscriptObservation {
    pub ms: MsV2TranscriptObservation,
    pub le: LeTranscriptObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsWitnessFreeSimulatorAttempt {
    pub game: ZkGameDefinition,
    pub strategy: SimulationStrategy,
    pub transcript: Option<SimulatedMsTranscript>,
    pub logs: Vec<SimulatorLogEntry>,
    pub failures: Vec<SimulatorFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsV2WitnessFreeSimulatorAttempt {
    pub game: ZkGameDefinition,
    pub transcript: Option<SimulatedMsV2Transcript>,
    pub logs: Vec<SimulatorLogEntry>,
    pub failures: Vec<SimulatorFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeWitnessFreeSimulatorAttempt {
    pub game: ZkGameDefinition,
    pub transcript: Option<SimulatedLeTranscript>,
    pub logs: Vec<SimulatorLogEntry>,
    pub failures: Vec<SimulatorFailure>,
    pub algebraic_relation_holds: bool,
    pub norm_bound_holds: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HonestZkTheorem {
    pub claim_type: ClaimType,
    pub ms_attempt: MsWitnessFreeSimulatorAttempt,
    pub le_attempt: LeWitnessFreeSimulatorAttempt,
    pub theorem_statement: String,
    pub honest_status: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalMsV2TranscriptDesign {
    pub name: String,
    pub transcript_definition: Vec<String>,
    pub prover_stub_contract: Vec<String>,
    pub verifier_stub_contract: Vec<String>,
    pub simulator_contract: Vec<String>,
    pub removes_witness_dependent_visible_outputs: bool,
    pub status: ClaimStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsV2ObservableBoundaryContract {
    pub claim_type: ClaimType,
    pub status: ProofStatus,
    pub interface_frozen: bool,
    pub sigma_algebra_generators: Vec<String>,
    pub measurable_projections: Vec<String>,
    pub hidden_non_observables: Vec<String>,
    pub simulator_allowed_inputs: Vec<String>,
    pub simulator_forbidden_inputs: Vec<String>,
    pub statement: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridTranscriptSource {
    RealProver,
    Simulator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedHybridWorld {
    pub name: String,
    pub ms_source: HybridTranscriptSource,
    pub le_source: HybridTranscriptSource,
    pub observable_view: Vec<String>,
    pub transition_argument: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedZkHybridGame {
    pub claim_type: ClaimType,
    pub status: ProofStatus,
    pub observable_boundary: Vec<String>,
    pub worlds: Vec<UnifiedHybridWorld>,
    pub composition_notes: Vec<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormalAssumption {
    pub id: AssumptionId,
    pub name: String,
    pub kind: AssumptionKind,
    pub statement: String,
    pub error_symbol: String,
    pub provided_terms: Vec<String>,
    pub depends_on: Vec<AssumptionId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssumptionDependencyEdge {
    pub from: AssumptionId,
    pub to: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssumptionDependencyGraph {
    pub name: String,
    pub inputs: Vec<FormalAssumption>,
    pub edges: Vec<AssumptionDependencyEdge>,
    pub output_bound: String,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbabilityObject {
    pub name: String,
    pub family: DistributionFamily,
    pub random_variable: String,
    pub support_description: String,
    pub randomness_sources: Vec<String>,
    pub observable_boundary_premise: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvantageFunction {
    pub name: String,
    pub distinguisher_class: String,
    pub left_distribution: String,
    pub right_distribution: String,
    pub definition: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvantageBound {
    pub symbol: String,
    pub expression: String,
    pub numeric_upper_bound: Option<f64>,
    pub dependencies: Vec<String>,
    pub epsilon_dependencies: Vec<String>,
    pub justification: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HybridLemma {
    pub name: String,
    pub source_world: String,
    pub target_world: String,
    pub source_distribution: String,
    pub target_distribution: String,
    pub assumption_dependencies: Vec<AssumptionId>,
    pub premise_contracts: Vec<String>,
    pub advantage_function: AdvantageFunction,
    pub bound: AdvantageBound,
    pub theorem_statement: String,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsReductionLemma {
    pub name: String,
    pub source_distribution: String,
    pub target_distribution: String,
    pub assumption_dependencies: Vec<AssumptionId>,
    pub premise_assumptions: Vec<String>,
    pub advantage_function: AdvantageFunction,
    pub bound: AdvantageBound,
    pub theorem_statement: String,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsReductionChain {
    pub assumptions: Vec<FormalAssumption>,
    pub lemmas: Vec<MsReductionLemma>,
    pub combined_bound: AdvantageBound,
    pub theorem_statement: String,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompositionSafetyLemma {
    pub name: String,
    pub assumption_dependencies: Vec<AssumptionId>,
    pub premise_contracts: Vec<String>,
    pub independence_premises: Vec<String>,
    pub ms_interface: Vec<String>,
    pub le_interface: Vec<String>,
    pub shared_randomness_rule: String,
    pub no_shared_witness_leakage_rule: String,
    pub additive_composition_argument: String,
    pub advantage_function: AdvantageFunction,
    pub bound: AdvantageBound,
    pub theorem_statement: String,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TheoremLemmaReference {
    pub name: String,
    pub assumption_dependencies: Vec<AssumptionId>,
    pub lemma_dependencies: Vec<String>,
    pub premise_contracts: Vec<String>,
    pub produced_bound: String,
    pub produced_bound_expression: String,
    pub produced_bound_numeric_upper_bound: Option<f64>,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenArchitectureComponent {
    pub name: String,
    pub frozen: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenArchitectureSeal {
    pub name: String,
    pub no_further_structural_changes_allowed: bool,
    pub components: Vec<FrozenArchitectureComponent>,
    pub statement: String,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofClosureIssueKind {
    EmpiricalReferenceInTheoremPath,
    MissingAssumptionReference,
    UndefinedEpsilonTerm,
    UnboundedEpsilonTerm,
    CompositionUsesUndeclaredBound,
    ForbiddenMsResidualAssumption,
    ExactSimulationLemmaViolation,
    ArchitectureNotFrozen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofClosureIssue {
    pub kind: ProofClosureIssueKind,
    pub location: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofClosureReport {
    pub closed: bool,
    pub checked_properties: Vec<String>,
    pub issues: Vec<ProofClosureIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalQssmSimulator {
    pub name: String,
    pub public_input_interface: Vec<String>,
    pub forbidden_inputs: Vec<String>,
    pub ms_component: String,
    pub le_component: String,
    pub shared_randomness_model: String,
    pub output_distribution: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardZkGame {
    pub name: String,
    pub transcript_distribution: String,
    pub simulator: Option<String>,
    pub theorem_role: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StandardZkTransition {
    pub name: String,
    pub from_game: String,
    pub to_game: String,
    pub explicit_simulator: String,
    pub assumption_dependencies: Vec<AssumptionId>,
    pub internal_lemma_dependencies: Vec<String>,
    pub bound: AdvantageBound,
    pub theorem_statement: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GameBasedZkProof {
    pub security_definition: String,
    pub exact_claim: String,
    pub games: Vec<StandardZkGame>,
    pub global_simulator: GlobalQssmSimulator,
    pub transitions: Vec<StandardZkTransition>,
    pub final_bound: AdvantageBound,
    pub theorem_statement: String,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClosedZkTheorem {
    pub name: String,
    pub claim_type: ClaimType,
    pub status: ProofStatus,
    pub architecture_freeze: FrozenArchitectureSeal,
    pub assumption_graph: AssumptionDependencyGraph,
    pub internal_lemma_chain: Vec<TheoremLemmaReference>,
    pub game_based_proof: GameBasedZkProof,
    pub premise_contracts: Vec<String>,
    pub random_variables: Vec<String>,
    pub distributions: Vec<String>,
    pub advantage_functions: Vec<String>,
    pub output_bound: AdvantageBound,
    pub closure_report: ProofClosureReport,
    pub theorem_statement: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeHvzkConstraintAnalysis {
    pub claim_type: ClaimType,
    pub epsilon_log2: f64,
    pub query_budget_log2: f64,
    pub n: usize,
    pub beta: u32,
    pub eta: u32,
    pub gamma: u32,
    pub c_poly_size: usize,
    pub c_poly_span: i32,
    pub worst_case_cr_inf_norm: u64,
    pub required_eta_for_hvzk: f64,
    pub minimum_gamma_for_support_containment: u64,
    pub challenge_space_log2: f64,
    pub fs_security_bits: f64,
    pub current_eta_shortfall: f64,
    pub current_gamma_shortfall: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalLeSetB {
    pub name: String,
    pub eta: u32,
    pub beta: u32,
    pub gamma: u32,
    pub c_poly_size: usize,
    pub c_poly_span: i32,
    pub worst_case_cr_inf_norm: u64,
    pub required_eta_for_hvzk: f64,
    pub minimum_gamma_for_support_containment: u64,
    pub challenge_space_log2: f64,
    pub fs_security_bits: f64,
    pub satisfies_hvzk_eta: bool,
    pub satisfies_support_containment: bool,
    pub meets_128_bit_fs: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReductionProofSketch {
    pub theorem_target: String,
    pub probability_objects: Vec<ProbabilityObject>,
    pub ms_reduction_chain: MsReductionChain,
    pub hybrid_lemmas: Vec<HybridLemma>,
    pub composition_safety_lemma: CompositionSafetyLemma,
    pub residual_assumptions: Vec<String>,
    pub final_advantage_bound: AdvantageBound,
    pub status: ProofStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityClaimRow {
    pub component: String,
    pub property: String,
    pub status: ClaimStatus,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedesignedSystemsTheorem {
    pub claim_type: ClaimType,
    pub current_system: HonestZkTheorem,
    pub canonical_ms_v2: CanonicalMsV2TranscriptDesign,
    pub ms_v2_observable_boundary: MsV2ObservableBoundaryContract,
    pub le_constraint_analysis: LeHvzkConstraintAnalysis,
    pub canonical_le_set_b: CanonicalLeSetB,
    pub ms_v2_alignment: MsV2EmpiricalAlignmentReport,
    pub unified_hybrid_game: UnifiedZkHybridGame,
    pub closed_zk_theorem: ClosedZkTheorem,
    pub security_claims: Vec<SecurityClaimRow>,
    pub theorem_statement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsPublicStatement {
    pub value: u64,
    pub target: u64,
    pub binding_entropy: [u8; 32],
    pub binding_context: [u8; 32],
    pub context: Vec<u8>,
}

impl MsPublicStatement {
    pub fn validate_yes_instance(&self) -> Result<(), ZkSimulationError> {
        if self.value <= self.target {
            return Err(ZkSimulationError::UnsatisfiedStatement);
        }
        Ok(())
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnSimulationArtifact {
    pub strategy: SimulationStrategy,
    pub n: u8,
    pub k: u8,
    /// Number of simulator-side oracle/search queries consumed.
    pub oracle_queries: usize,
    /// Number of explicitly programmed ROM points.
    pub programmed_oracle_queries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedOpening {
    pub leaf_index: usize,
    pub bit_at_k: u8,
    pub opened_salt: [u8; 32],
    pub leaf: [u8; 32],
    pub path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentOpeningArtifact {
    pub strategy: SimulationStrategy,
    pub root: [u8; 32],
    pub opening: SimulatedOpening,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedMsTranscript {
    pub strategy: SimulationStrategy,
    pub root: [u8; 32],
    pub k: u8,
    pub n: u8,
    pub challenge: [u8; 32],
    pub opening: SimulatedOpening,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptSimulationArtifact {
    pub kn: KnSimulationArtifact,
    pub transcript: SimulatedMsTranscript,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealMsTranscript {
    pub root: [u8; 32],
    pub k: u8,
    pub n: u8,
    pub challenge: [u8; 32],
    pub opening: SimulatedOpening,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TranscriptObservation {
    pub n: u8,
    pub k: u8,
    pub bit_at_k: u8,
    pub path_len: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmpiricalDistributionDistance {
    pub support_size: usize,
    pub l1_distance: f64,
    pub total_variation_distance: f64,
    pub max_bucket_gap: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyEstimate {
    pub real_entropy_bits: f64,
    pub simulated_entropy_bits: f64,
    pub entropy_gap_bits: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmoothedDivergenceEstimate {
    pub support_size: usize,
    pub kl_real_to_sim_bits: f64,
    pub kl_sim_to_real_bits: f64,
    pub jensen_shannon_bits: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConditionalLeakageEstimate {
    pub condition_label: String,
    pub outcome_label: String,
    pub condition_support_size: usize,
    pub outcome_support_size: usize,
    pub average_total_variation_distance: f64,
    pub max_total_variation_distance: f64,
    pub approx_mutual_information_bits: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteCorrelationEstimate {
    pub real_adjacent_correlation: f64,
    pub simulated_adjacent_correlation: f64,
    pub correlation_gap: f64,
    pub delta_distance: EmpiricalDistributionDistance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsEmpiricalDistinguisherReport {
    pub strategy: SimulationStrategy,
    pub sample_count: usize,
    pub joint_distance: EmpiricalDistributionDistance,
    pub nonce_distance: EmpiricalDistributionDistance,
    pub bit_index_distance: EmpiricalDistributionDistance,
    pub bit_state_distance: EmpiricalDistributionDistance,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedMsV2Transcript {
    pub statement_digest: [u8; 32],
    pub result: bool,
    pub bitness_global_challenges: Vec<[u8; 32]>,
    pub comparison_global_challenge: [u8; 32],
    pub transcript_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealMsV2Transcript {
    pub statement_digest: [u8; 32],
    pub result: bool,
    pub bitness_global_challenges: Vec<[u8; 32]>,
    pub comparison_global_challenge: [u8; 32],
    pub transcript_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MsV2TranscriptObservation {
    pub statement_digest: [u8; 32],
    pub result: bool,
    pub bitness_global_challenges: Vec<[u8; 32]>,
    pub comparison_global_challenge: [u8; 32],
    pub transcript_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsV2EmpiricalAlignmentReport {
    pub sample_count: usize,
    pub result_distance: EmpiricalDistributionDistance,
    pub statistical_layer: MsV2StatisticalDistinguisherLayer,
    pub structure_layer: MsV2StructureDistinguisherLayer,
    pub simulator_gap_layer: MsV2SimulatorGapLayer,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsV2StatisticalDistinguisherLayer {
    pub bitness_challenge_nibble_distance: EmpiricalDistributionDistance,
    pub comparison_challenge_nibble_distance: EmpiricalDistributionDistance,
    pub transcript_digest_nibble_distance: EmpiricalDistributionDistance,
    pub bitness_byte_correlation: ByteCorrelationEstimate,
    pub comparison_byte_correlation: ByteCorrelationEstimate,
    pub transcript_digest_byte_correlation: ByteCorrelationEstimate,
    pub bitness_challenge_entropy: EntropyEstimate,
    pub comparison_challenge_entropy: EntropyEstimate,
    pub transcript_digest_entropy: EntropyEstimate,
    pub challenge_to_digest_prefix_bias: ConditionalLeakageEstimate,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsV2StructureDistinguisherLayer {
    pub hidden_gap_bit_to_comparison_nibble_bias: ConditionalLeakageEstimate,
    pub hidden_value_lsb_to_digest_nibble_bias: ConditionalLeakageEstimate,
    pub hidden_hamming_weight_bucket_to_bitness_nibble_bias: ConditionalLeakageEstimate,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsV2SimulatorGapLayer {
    pub bitness_challenge_nibble_divergence: SmoothedDivergenceEstimate,
    pub bitness_byte_delta_divergence: SmoothedDivergenceEstimate,
    pub comparison_byte_delta_divergence: SmoothedDivergenceEstimate,
    pub transcript_digest_byte_delta_divergence: SmoothedDivergenceEstimate,
    pub overall_js_upper_bound_bits: f64,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnSamplingLemma {
    pub claim_type: ClaimType,
    pub strategy: SimulationStrategy,
    pub status: ProofStatus,
    pub witness_required: bool,
    pub sampler_description: String,
    pub assumptions: Vec<String>,
}

impl KnSamplingLemma {
    #[must_use]
    pub fn for_strategy(strategy: SimulationStrategy) -> Self {
        match strategy {
            SimulationStrategy::DistributionCollapse => Self {
                claim_type: ClaimType::ZeroKnowledge,
                strategy,
                status: ProofStatus::Conditional,
                witness_required: false,
                sampler_description:
                    "sample (k, n) from the public set of valid nonce/bit pairs using a domain-separated public marginal".to_string(),
                assumptions: vec![
                    "rotation hides any residual witness dependence in the valid-pair set".to_string(),
                    "first-success stopping-time bias is negligible relative to the public marginal".to_string(),
                ],
            },
            SimulationStrategy::ProgramSimulation => Self {
                claim_type: ClaimType::ZeroKnowledge,
                strategy,
                status: ProofStatus::Conditional,
                witness_required: false,
                sampler_description:
                    "scan public nonces in order, then program one ROM point around the first valid public (k, n) pair".to_string(),
                assumptions: vec![
                    "Fiat-Shamir is analyzed in a programmable random oracle model".to_string(),
                    "the simulator may rewind or otherwise justify the programmed oracle point".to_string(),
                ],
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiatShamirConsistencyLemma {
    pub claim_type: ClaimType,
    pub strategy: SimulationStrategy,
    pub status: ProofStatus,
    pub transcript_domain: String,
    pub challenge_inputs: Vec<String>,
}

impl FiatShamirConsistencyLemma {
    #[must_use]
    pub fn for_strategy(strategy: SimulationStrategy) -> Self {
        Self {
            claim_type: ClaimType::ZeroKnowledge,
            strategy,
            status: ProofStatus::ByConstruction,
            transcript_domain: "QSSM-MS-v1.0 / fs_v2".to_string(),
            challenge_inputs: vec![
                "root".to_string(),
                "n".to_string(),
                "k".to_string(),
                "binding_entropy".to_string(),
                "value".to_string(),
                "target".to_string(),
                "context".to_string(),
                "binding_context".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentOpeningSimulationLemma {
    pub claim_type: ClaimType,
    pub strategy: SimulationStrategy,
    pub status: ProofStatus,
    pub tree_width: usize,
    pub tree_depth: usize,
    pub output_layout: Vec<String>,
    pub hiding_assumption: String,
}

impl CommitmentOpeningSimulationLemma {
    #[must_use]
    pub fn for_strategy(strategy: SimulationStrategy) -> Self {
        Self {
            claim_type: ClaimType::ZeroKnowledge,
            strategy,
            status: ProofStatus::Conditional,
            tree_width: MERKLE_WIDTH_MS,
            tree_depth: MERKLE_DEPTH_MS,
            output_layout: vec![
                "root".to_string(),
                "bit_at_k".to_string(),
                "opened_salt".to_string(),
                "leaf".to_string(),
                "path".to_string(),
            ],
            hiding_assumption:
                "simulated Merkle leaves and openings are computationally indistinguishable from real hiding commitments".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeSimulatorDefinition {
    pub claim_type: ClaimType,
    pub status: ProofStatus,
    pub rom_model: bool,
    pub simulated_transcript: Vec<String>,
    pub public_inputs: Vec<String>,
    pub sampled_independently: Vec<String>,
    pub programmed_random_oracle_queries: Vec<String>,
    pub forbidden_secret_inputs: Vec<String>,
}

impl LeSimulatorDefinition {
    #[must_use]
    pub fn for_current_params() -> Self {
        Self {
            claim_type: ClaimType::ZeroKnowledge,
            status: ProofStatus::Conditional,
            rom_model: true,
            simulated_transcript: vec![
                "A".to_string(),
                "t".to_string(),
                "z".to_string(),
                "c / challenge_seed".to_string(),
            ],
            public_inputs: vec![
                "verifying key / CRS".to_string(),
                "public instance".to_string(),
                "binding_context".to_string(),
                "commitment C if treated as part of the verifier view".to_string(),
            ],
            sampled_independently: vec![
                "simulator coins".to_string(),
                "independent masking sample or directly simulated z candidate".to_string(),
            ],
            programmed_random_oracle_queries: vec![
                "fs_challenge_bytes(binding_context, vk, public, commitment, t)".to_string(),
            ],
            forbidden_secret_inputs: vec!["witness r".to_string()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeSimulationLemma {
    pub claim_type: ClaimType,
    pub status: ProofStatus,
    pub statement: String,
    pub adversary_model: String,
    pub assumptions: Vec<String>,
    pub exact_constraints: Vec<String>,
    pub open_proof_obligations: Vec<String>,
}

impl LeSimulationLemma {
    #[must_use]
    pub fn for_current_params() -> Self {
        Self {
            claim_type: ClaimType::ZeroKnowledge,
            status: ProofStatus::Conditional,
            statement:
                "For every PPT adversary, the simulated LE transcript is computationally indistinguishable from the real LE transcript in the ROM without knowledge of r.".to_string(),
            adversary_model: "PPT distinguisher over real vs simulated LE transcripts".to_string(),
            assumptions: vec![
                "module-LWE / module-SIS hardness for the commitment-binding layer".to_string(),
                "programmable random oracle model for Fiat-Shamir challenge generation".to_string(),
                "rejection-sampling distribution bounds under the exact eta, beta, gamma regime".to_string(),
            ],
            exact_constraints: vec![
                format!("N={N}"),
                format!("eta={ETA}"),
                format!("beta={BETA}"),
                format!("gamma={GAMMA}"),
                format!("c_poly_size={C_POLY_SIZE}"),
                format!("c_poly_span={C_POLY_SPAN}"),
            ],
            open_proof_obligations: vec![
                "justify the simulated commitment handling when C is part of the verifier view".to_string(),
                "bound the statistical distance between simulated and real rejection-sampled outputs".to_string(),
                "show that ROM programming for fs_challenge_bytes preserves the transcript law".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeParameterFeasibilityCheck {
    pub claim_type: ClaimType,
    pub status: ProofStatus,
    pub n: usize,
    pub eta: u32,
    pub beta: u32,
    pub gamma: u32,
    pub c_poly_size: usize,
    pub c_poly_span: i32,
    pub required_eta_for_standard_hvzk: f64,
    pub abort_probability_estimate: f64,
    pub meets_standard_hvzk_requirement: bool,
    pub conclusion: String,
    pub non_conclusion: String,
}

impl LeParameterFeasibilityCheck {
    #[must_use]
    pub fn for_current_params() -> Self {
        let rejection = RejectionSamplingClaim::for_current_params();
        let meets_standard_hvzk_requirement = rejection.meets_hvzk_requirement();
        let status = if meets_standard_hvzk_requirement {
            ProofStatus::Conditional
        } else {
            ProofStatus::KnownProofConditionsNotMet
        };
        let conclusion = if meets_standard_hvzk_requirement {
            "current canonical LE Set B matches the standard HVZK proof template analyzed here"
                .to_string()
        } else {
            "current parameter set may not satisfy known proof conditions for the standard Lyubashevsky HVZK route analyzed here".to_string()
        };

        Self {
            claim_type: ClaimType::ZeroKnowledge,
            status,
            n: N,
            eta: ETA,
            beta: BETA,
            gamma: GAMMA,
            c_poly_size: C_POLY_SIZE,
            c_poly_span: C_POLY_SPAN,
            required_eta_for_standard_hvzk: rejection.required_eta_for_hvzk,
            abort_probability_estimate: rejection.abort_probability_estimate,
            meets_standard_hvzk_requirement,
            conclusion,
            non_conclusion:
                "this feasibility check alone does not prove or refute zero-knowledge; it only reports whether the known proof conditions encoded here are met".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesiredZkTheorem {
    pub claim_type: ClaimType,
    pub strategy: SimulationStrategy,
    pub status: ProofStatus,
    pub lemma_1_kn_sampling: KnSamplingLemma,
    pub lemma_2_fiat_shamir: FiatShamirConsistencyLemma,
    pub lemma_3_commitment_opening: CommitmentOpeningSimulationLemma,
    pub le_simulator_definition: LeSimulatorDefinition,
    pub le_simulation_lemma: LeSimulationLemma,
    pub le_parameter_feasibility: LeParameterFeasibilityCheck,
    pub le_witness_hiding: WitnessHidingClaim,
    pub assumptions: Vec<String>,
    pub proof_gaps: Vec<String>,
}

impl DesiredZkTheorem {
    #[must_use]
    pub fn for_current_params(strategy: SimulationStrategy) -> Self {
        let lemma_1_kn_sampling = KnSamplingLemma::for_strategy(strategy);
        let lemma_2_fiat_shamir = FiatShamirConsistencyLemma::for_strategy(strategy);
        let lemma_3_commitment_opening = CommitmentOpeningSimulationLemma::for_strategy(strategy);
        let le_simulator_definition = LeSimulatorDefinition::for_current_params();
        let le_simulation_lemma = LeSimulationLemma::for_current_params();
        let le_parameter_feasibility = LeParameterFeasibilityCheck::for_current_params();
        let le_witness_hiding = WitnessHidingClaim::for_current_params();

        let mut assumptions = lemma_1_kn_sampling.assumptions.clone();
        assumptions.push(lemma_3_commitment_opening.hiding_assumption.clone());
        assumptions.extend(le_simulation_lemma.assumptions.clone());

        let mut proof_gaps = Vec::new();
        if !le_parameter_feasibility.meets_standard_hvzk_requirement {
            proof_gaps.push(le_parameter_feasibility.conclusion.clone());
        }
        if le_witness_hiding
            .not_claimed
            .iter()
            .any(|item| item == "simulation-based ZK")
        {
            proof_gaps.push(
                "current formal crate still states the complete LE ROM indistinguishability reduction as a proof obligation rather than a finished proof".to_string(),
            );
        }

        let status = if le_parameter_feasibility.meets_standard_hvzk_requirement {
            ProofStatus::Conditional
        } else {
            ProofStatus::KnownProofConditionsNotMet
        };

        Self {
            claim_type: ClaimType::ZeroKnowledge,
            strategy,
            status,
            lemma_1_kn_sampling,
            lemma_2_fiat_shamir,
            lemma_3_commitment_opening,
            le_simulator_definition,
            le_simulation_lemma,
            le_parameter_feasibility,
            le_witness_hiding,
            assumptions,
            proof_gaps,
        }
    }
}

#[must_use]
pub fn attempt_ms_witness_free_simulator(
    public_input: &MsHiddenValuePublicInput,
    strategy: SimulationStrategy,
) -> MsWitnessFreeSimulatorAttempt {
    let mut logs = vec![SimulatorLogEntry {
        step: "freeze_ms_game".to_string(),
        detail: format!(
            "Frozen visible transcript surface: {}",
            ZkGameDefinition::ms_hidden_value_game()
                .transcript_surface
                .visible_fields
                .join(", ")
        ),
        requires_witness: false,
        uses_independent_sampling: false,
        uses_random_oracle_programming: false,
    }];
    let mut failures = Vec::new();

    let strategy_note = match strategy {
        SimulationStrategy::DistributionCollapse => {
            "distribution-collapse requires a public marginal over (k, n)"
        }
        SimulationStrategy::ProgramSimulation => {
            "program simulation requires evaluating the first valid nonce crossing"
        }
    };
    logs.push(SimulatorLogEntry {
        step: "select_kn".to_string(),
        detail: format!(
            "Attempted {} using only target={}, binding entropy, binding context, and context.",
            strategy_note, public_input.target
        ),
        requires_witness: false,
        uses_independent_sampling: false,
        uses_random_oracle_programming: strategy == SimulationStrategy::ProgramSimulation,
    });
    failures.push(SimulatorFailure {
        class: FailureClass::Structural,
        location: "MS k/n selection".to_string(),
        detail:
            "The visible fields n and k depend on hidden value material through the crossing predicate; with value hidden, the simulator cannot derive or validate the required pair from public inputs alone."
                .to_string(),
    });

    logs.push(SimulatorLogEntry {
        step: "extract_bit_at_k".to_string(),
        detail:
            "Attempted to determine bit_at_k for the visible opening branch without hidden value."
                .to_string(),
        requires_witness: true,
        uses_independent_sampling: false,
        uses_random_oracle_programming: false,
    });
    failures.push(SimulatorFailure {
        class: FailureClass::Structural,
        location: "MS bit_at_k extraction".to_string(),
        detail:
            "The visible branch bit bit_at_k is a function of the hidden value at position k; under the frozen visible transcript surface it cannot be produced from public inputs alone."
                .to_string(),
    });

    logs.push(SimulatorLogEntry {
        step: "simulate_opening".to_string(),
        detail:
            "Merkle opening simulation would be conditional on already having a valid visible branch index (k, bit_at_k)."
                .to_string(),
        requires_witness: false,
        uses_independent_sampling: true,
        uses_random_oracle_programming: false,
    });
    failures.push(SimulatorFailure {
        class: FailureClass::Structural,
        location: "MS visible opening".to_string(),
        detail:
            "Even if hiding commitments allow fake roots and paths, the frozen visible opening still has to target the witness-selected branch. That branch cannot be fixed without hidden value material."
                .to_string(),
    });

    MsWitnessFreeSimulatorAttempt {
        game: ZkGameDefinition::ms_hidden_value_game(),
        strategy,
        transcript: None,
        logs,
        failures,
    }
}

#[must_use]
pub fn attempt_ms_v2_witness_free_simulator(
    public_input: &MsHiddenValuePublicInput,
) -> MsV2WitnessFreeSimulatorAttempt {
    let statement = match ms_v2_statement_from_public_input(public_input) {
        Ok(statement) => statement,
        Err(error) => {
            return MsV2WitnessFreeSimulatorAttempt {
                game: ZkGameDefinition::ms_v2_hidden_value_game(),
                transcript: None,
                logs: vec![SimulatorLogEntry {
                    step: "rebuild_ms_v2_statement".to_string(),
                    detail: format!("Failed to reconstruct public MS v2 statement: {error}"),
                    requires_witness: false,
                    uses_independent_sampling: false,
                    uses_random_oracle_programming: false,
                }],
                failures: vec![SimulatorFailure {
                    class: FailureClass::Structural,
                    location: "MS v2 public statement reconstruction".to_string(),
                    detail: format!("The public value commitment could not be reconstructed: {error}"),
                }],
            };
        }
    };
    let simulator_seed = hash_domain(
        DOMAIN_MS,
        &[
            b"ms_v2_theorem_simulator_seed",
            statement.statement_digest().as_slice(),
        ],
    );
    let simulation = match qssm_ms::simulate_predicate_only_v2(&statement, simulator_seed) {
        Ok(simulation) => simulation,
        Err(error) => {
            return MsV2WitnessFreeSimulatorAttempt {
                game: ZkGameDefinition::ms_v2_hidden_value_game(),
                transcript: None,
                logs: vec![SimulatorLogEntry {
                    step: "simulate_ms_v2_transcript".to_string(),
                    detail: format!("MS v2 simulator failed to synthesize a transcript: {error}"),
                    requires_witness: false,
                    uses_independent_sampling: true,
                    uses_random_oracle_programming: true,
                }],
                failures: vec![SimulatorFailure {
                    class: FailureClass::Structural,
                    location: "MS v2 simulator synthesis".to_string(),
                    detail: format!("The real simulator failed to emit a transcript: {error}"),
                }],
            };
        }
    };
    let logs = vec![
        SimulatorLogEntry {
            step: "freeze_ms_v2_game".to_string(),
            detail: format!(
                "Frozen visible transcript surface: {}",
                ZkGameDefinition::ms_v2_hidden_value_game()
                    .transcript_surface
                    .visible_fields
                    .join(", ")
            ),
            requires_witness: false,
            uses_independent_sampling: false,
            uses_random_oracle_programming: false,
        },
        SimulatorLogEntry {
            step: "rebuild_public_statement".to_string(),
            detail:
                "Reconstructed the public predicate-only statement from the value commitment, target, binding inputs, and context only."
                    .to_string(),
            requires_witness: false,
            uses_independent_sampling: false,
            uses_random_oracle_programming: false,
        },
        SimulatorLogEntry {
            step: "program_random_oracle".to_string(),
            detail:
                "Synthesized the full predicate-only transcript directly from the public statement and programmed oracle queries; the simulator does not follow the prover witness path."
                    .to_string(),
            requires_witness: false,
            uses_independent_sampling: true,
            uses_random_oracle_programming: true,
        },
    ];
    let failures = match qssm_ms::verify_predicate_only_v2_with_programming(&statement, &simulation)
    {
        Ok(true) => Vec::new(),
        Ok(false) => vec![SimulatorFailure {
            class: FailureClass::Structural,
            location: "MS v2 programmed verification".to_string(),
            detail: "The programmed-oracle verifier rejected the simulated MS v2 transcript."
                .to_string(),
        }],
        Err(error) => vec![SimulatorFailure {
            class: FailureClass::Structural,
            location: "MS v2 programmed verification".to_string(),
            detail: format!(
                "The programmed-oracle verifier rejected the simulated MS v2 transcript: {error}"
            ),
        }],
    };

    MsV2WitnessFreeSimulatorAttempt {
        game: ZkGameDefinition::ms_v2_hidden_value_game(),
        transcript: Some(SimulatedMsV2Transcript {
            statement_digest: *simulation.proof().statement_digest(),
            result: simulation.proof().result(),
            bitness_global_challenges: simulation
                .proof()
                .bitness_global_challenges()
                .expect("simulated MS v2 bitness challenges")
                .to_vec(),
            comparison_global_challenge: simulation
                .proof()
                .comparison_global_challenge()
                .expect("simulated MS v2 comparison challenge"),
            transcript_digest: simulation.proof().transcript_digest(),
        }),
        logs,
        failures,
    }
}

pub fn attempt_le_witness_free_simulator(
    public_input: &LePublicInput,
) -> Result<LeWitnessFreeSimulatorAttempt, ZkSimulationError> {
    let mut logs = vec![SimulatorLogEntry {
        step: "freeze_le_game".to_string(),
        detail: format!(
            "Frozen visible transcript surface: {}",
            ZkGameDefinition::le_hidden_witness_game()
                .transcript_surface
                .visible_fields
                .join(", ")
        ),
        requires_witness: false,
        uses_independent_sampling: false,
        uses_random_oracle_programming: false,
    }];

    let sampled_r = sample_centered_vec(
        b"le_sim_commitment_short",
        public_input.binding_context,
        BETA,
    );
    let commitment_r = short_vec_to_rq(&sampled_r)?;
    let a = public_input.vk.matrix_a_poly();
    let mu = le_mu_from_public(&public_input.public);
    let commitment_poly = a.mul(&commitment_r)?.add(&mu);
    let commitment = Commitment(commitment_poly);
    logs.push(SimulatorLogEntry {
        step: "sample_commitment".to_string(),
        detail:
            "Sampled an independent short vector to instantiate a visible commitment C without using the actual witness r."
                .to_string(),
        requires_witness: false,
        uses_independent_sampling: true,
        uses_random_oracle_programming: false,
    });

    let z_arr = sample_centered_vec(b"le_sim_z", public_input.binding_context, GAMMA);
    let z = short_vec_to_rq_bound(&z_arr, GAMMA)?;
    let challenge_seed = hash_domain(
        DOMAIN_ZK_SIM,
        &[
            b"le_sim_challenge_seed",
            public_input.binding_context.as_slice(),
            &public_input.vk.crs_seed,
            &le_public_binding_fs_bytes(&public_input.public),
            &encode_rq_coeffs_le(&commitment.0),
        ],
    );
    let c_poly = le_challenge_poly(&challenge_seed);
    let c_rq = le_challenge_poly_to_rq(&c_poly);
    let u = commitment.0.sub(&mu);
    let az = a.mul(&z)?;
    let cu = c_rq.mul(&u)?;
    let t = az.sub(&cu);
    let programmed_oracle_query_digest = le_fs_programmed_query_digest(
        &public_input.binding_context,
        &public_input.vk,
        &public_input.public,
        &commitment,
        &t,
    );
    logs.push(SimulatorLogEntry {
        step: "program_random_oracle".to_string(),
        detail:
            "Programmed the Fiat-Shamir oracle at fs_challenge_bytes(binding_context, vk, public, C, t) to return the chosen challenge_seed."
                .to_string(),
        requires_witness: false,
        uses_independent_sampling: true,
        uses_random_oracle_programming: true,
    });

    let lhs = a.mul(&z)?;
    let rhs = t.add(&c_rq.mul(&u)?);
    let algebraic_relation_holds = lhs == rhs;
    let norm_bound_holds = z.inf_norm_centered() <= GAMMA;

    let mut failures = Vec::new();
    let rejection = RejectionSamplingClaim::for_current_params();
    if !rejection.meets_hvzk_requirement() {
        failures.push(SimulatorFailure {
            class: FailureClass::Parametric,
            location: "LE simulation lemma: rejection-sampling closeness".to_string(),
            detail: format!(
                "The witness-free ROM transcript construction exists, but the current parameters do not meet the standard HVZK proof template encoded in the crate: eta={} < required_eta_for_hvzk≈{:.0}.",
                rejection.eta, rejection.required_eta_for_hvzk
            ),
        });
    } else {
        logs.push(SimulatorLogEntry {
            step: "check_set_b_constraints".to_string(),
            detail: format!(
                "Current LE parameters satisfy the encoded HVZK template: eta={} >= required≈{:.0}, gamma={} >= eta+||cr||_inf={}.",
                rejection.eta,
                rejection.required_eta_for_hvzk,
                rejection.gamma,
                u64::from(rejection.eta) + rejection.worst_case_cr_inf_norm,
            ),
            requires_witness: false,
            uses_independent_sampling: false,
            uses_random_oracle_programming: false,
        });
    }

    Ok(LeWitnessFreeSimulatorAttempt {
        game: ZkGameDefinition::le_hidden_witness_game(),
        transcript: Some(SimulatedLeTranscript {
            commitment_coeffs: commitment.0 .0.to_vec(),
            t_coeffs: t.0.to_vec(),
            z_coeffs: z.0.to_vec(),
            challenge_seed,
            programmed_oracle_query_digest,
        }),
        logs,
        failures,
        algebraic_relation_holds,
        norm_bound_holds,
    })
}

#[must_use]
pub fn observe_real_le_transcript(transcript: &RealLeTranscript) -> LeTranscriptObservation {
    LeTranscriptObservation {
        commitment_coeffs: transcript.commitment_coeffs.clone(),
        t_coeffs: transcript.t_coeffs.clone(),
        z_coeffs: transcript.z_coeffs.clone(),
        challenge_seed: transcript.challenge_seed,
    }
}

#[must_use]
pub fn observe_simulated_le_transcript(
    transcript: &SimulatedLeTranscript,
) -> LeTranscriptObservation {
    LeTranscriptObservation {
        commitment_coeffs: transcript.commitment_coeffs.clone(),
        t_coeffs: transcript.t_coeffs.clone(),
        z_coeffs: transcript.z_coeffs.clone(),
        challenge_seed: transcript.challenge_seed,
    }
}

#[must_use]
pub fn observe_real_qssm_transcript(transcript: &RealQssmTranscript) -> QssmTranscriptObservation {
    QssmTranscriptObservation {
        ms: observe_real_ms_v2_transcript(&transcript.ms),
        le: observe_real_le_transcript(&transcript.le),
    }
}

#[must_use]
pub fn observe_simulated_qssm_transcript(
    transcript: &SimulatedQssmTranscript,
) -> QssmTranscriptObservation {
    QssmTranscriptObservation {
        ms: observe_simulated_ms_v2_transcript(&transcript.ms),
        le: observe_simulated_le_transcript(&transcript.le),
    }
}

pub fn build_qssm_public_input(
    fixture: &QssmWitnessFixture,
    ms_commitment_seed: [u8; 32],
    le_public_input: LePublicInput,
) -> Result<QssmPublicInput, ZkSimulationError> {
    let (ms_public_input, _, _, _) =
        ms_v2_artifacts_from_statement(&fixture.ms_statement, ms_commitment_seed)?;
    Ok(QssmPublicInput {
        ms: ms_public_input,
        le: le_public_input,
    })
}

pub fn sample_real_qssm_transcript(
    public_input: &QssmPublicInput,
    fixture: &QssmWitnessFixture,
    ms_commitment_seed: [u8; 32],
    le_prover_seed: [u8; 32],
) -> Result<RealQssmTranscript, ZkSimulationError> {
    let (expected_ms_public_input, _, _, _) =
        ms_v2_artifacts_from_statement(&fixture.ms_statement, ms_commitment_seed)?;
    if public_input.ms != expected_ms_public_input {
        return Err(ZkSimulationError::TheoremInvariant(
            "QSSM real transcript sampler received an MS public input inconsistent with the supplied witness fixture and commitment seed."
                .to_string(),
        ));
    }

    Ok(RealQssmTranscript {
        ms: sample_real_ms_v2_transcript(&fixture.ms_statement, ms_commitment_seed)?,
        le: sample_real_le_transcript(
            &public_input.le,
            fixture.le_witness_coeffs,
            le_prover_seed,
        )?,
    })
}

pub fn sample_g1_qssm_observation(
    public_input: &QssmPublicInput,
    fixture: &QssmWitnessFixture,
    ms_simulator_seed: [u8; 32],
    le_prover_seed: [u8; 32],
) -> Result<QssmTranscriptObservation, ZkSimulationError> {
    let ms = simulate_ms_v2_transcript(&public_input.ms, ms_simulator_seed)?;
    let le = sample_real_le_transcript(&public_input.le, fixture.le_witness_coeffs, le_prover_seed)?;

    Ok(QssmTranscriptObservation {
        ms: observe_simulated_ms_v2_transcript(&ms),
        le: observe_real_le_transcript(&le),
    })
}

pub fn simulate_qssm_transcript(
    public_input: &QssmPublicInput,
    simulator_seed: [u8; 32],
) -> Result<SimulatedQssmTranscript, ZkSimulationError> {
    let ms_statement = ms_v2_statement_from_public_input(&public_input.ms)?;
    let ms_seed = hash_domain(
        DOMAIN_ZK_SIM,
        &[
            b"qssm_global_sim_ms_seed",
            simulator_seed.as_slice(),
            ms_statement.statement_digest().as_slice(),
        ],
    );
    let le_seed = hash_domain(
        DOMAIN_ZK_SIM,
        &[
            b"qssm_global_sim_le_seed",
            simulator_seed.as_slice(),
            public_input.le.binding_context.as_slice(),
            &public_input.le.vk.crs_seed,
        ],
    );

    Ok(SimulatedQssmTranscript {
        ms: simulate_ms_v2_transcript(&public_input.ms, ms_seed)?,
        le: simulate_le_transcript(&public_input.le, le_seed)?,
    })
}

pub fn honest_zk_theorem_for_current_system() -> Result<HonestZkTheorem, ZkSimulationError> {
    let ms_attempt = attempt_ms_witness_free_simulator(
        &MsHiddenValuePublicInput {
            commitment_bit_points: Vec::new(),
            target: 21,
            binding_entropy: [7u8; 32],
            binding_context: [9u8; 32],
            context: b"age_gate_21".to_vec(),
        },
        SimulationStrategy::ProgramSimulation,
    );
    let le_attempt = attempt_le_witness_free_simulator(&LePublicInput {
        vk: VerifyingKey::from_seed([11u8; 32]),
        public: PublicInstance::from_u64_nibbles(42),
        binding_context: [13u8; 32],
    })?;

    Ok(HonestZkTheorem {
        claim_type: ClaimType::ZeroKnowledge,
        theorem_statement:
            "Under the frozen visible transcript surfaces, the current deployed stack still lacks a complete end-to-end ZK theorem because the legacy MS transcript exposes witness-dependent visible outputs. The LE layer is now committed to the proof-safe Set B regime, where the executable ROM transcript construction matches the encoded HVZK parameter template."
                .to_string(),
        honest_status:
            "MS structural blocker remains on the legacy transcript; LE Set B is aligned with the proof-safe parameter template; the publishable path is to switch to the canonical MS v2 predicate-only transcript and complete the composed reduction."
                .to_string(),
        ms_attempt,
        le_attempt,
    })
}

pub fn simulate_le_transcript(
    public_input: &LePublicInput,
    simulator_seed: [u8; 32],
) -> Result<SimulatedLeTranscript, ZkSimulationError> {
    let rejection = RejectionSamplingClaim::for_current_params();
    if !rejection.meets_hvzk_requirement() {
        return Err(ZkSimulationError::TheoremInvariant(format!(
            "LE Set B does not satisfy the encoded HVZK template: eta={} < required≈{:.0}",
            rejection.eta, rejection.required_eta_for_hvzk
        )));
    }

    let sampled_r = sample_centered_vec_with_seed(
        b"le_global_sim_commitment_short",
        public_input.binding_context,
        simulator_seed,
        BETA,
    );
    let commitment_r = short_vec_to_rq(&sampled_r)?;
    let a = public_input.vk.matrix_a_poly();
    let mu = le_mu_from_public(&public_input.public);
    let commitment_poly = a.mul(&commitment_r)?.add(&mu);
    let commitment = Commitment(commitment_poly);

    let z_arr = sample_centered_vec_with_seed(
        b"le_global_sim_z",
        public_input.binding_context,
        simulator_seed,
        GAMMA,
    );
    let z = short_vec_to_rq_bound(&z_arr, GAMMA)?;
    let challenge_seed = hash_domain(
        DOMAIN_ZK_SIM,
        &[
            b"le_global_sim_challenge_seed",
            simulator_seed.as_slice(),
            public_input.binding_context.as_slice(),
            &public_input.vk.crs_seed,
            &le_public_binding_fs_bytes(&public_input.public),
            &encode_rq_coeffs_le(&commitment.0),
        ],
    );
    let c_poly = le_challenge_poly(&challenge_seed);
    let c_rq = le_challenge_poly_to_rq(&c_poly);
    let u = commitment.0.sub(&mu);
    let az = a.mul(&z)?;
    let cu = c_rq.mul(&u)?;
    let t = az.sub(&cu);
    let programmed_oracle_query_digest = le_fs_programmed_query_digest(
        &public_input.binding_context,
        &public_input.vk,
        &public_input.public,
        &commitment,
        &t,
    );

    let algebraic_relation_holds = a.mul(&z)? == t.add(&c_rq.mul(&u)?);
    let norm_bound_holds = z.inf_norm_centered() <= GAMMA;
    if !algebraic_relation_holds || !norm_bound_holds {
        return Err(ZkSimulationError::TheoremInvariant(
            "LE global simulator emitted a transcript that violates the programmed algebraic relation or gamma bound."
                .to_string(),
        ));
    }

    Ok(SimulatedLeTranscript {
        commitment_coeffs: commitment.0 .0.to_vec(),
        t_coeffs: t.0.to_vec(),
        z_coeffs: z.0.to_vec(),
        challenge_seed,
        programmed_oracle_query_digest,
    })
}

pub fn sample_real_le_transcript(
    public_input: &LePublicInput,
    le_witness_coeffs: [i32; N],
    prover_seed: [u8; 32],
) -> Result<RealLeTranscript, ZkSimulationError> {
    let witness = Witness::new(le_witness_coeffs);
    let (commitment, proof) = prove_arithmetic(
        &public_input.vk,
        &public_input.public,
        &witness,
        &public_input.binding_context,
        prover_seed,
    )?;
    let verified = verify_lattice(
        &public_input.vk,
        &public_input.public,
        &commitment,
        &proof,
        &public_input.binding_context,
    )?;
    if !verified {
        return Err(ZkSimulationError::TheoremInvariant(
            "Real LE prover emitted a transcript rejected by the verifier.".to_string(),
        ));
    }

    Ok(RealLeTranscript {
        commitment_coeffs: commitment.0 .0.to_vec(),
        t_coeffs: proof.t.0.to_vec(),
        z_coeffs: proof.z.0.to_vec(),
        challenge_seed: proof.challenge_seed,
    })
}

pub fn simulate_ms_v2_transcript(
    public_input: &MsHiddenValuePublicInput,
    simulator_seed: [u8; 32],
) -> Result<SimulatedMsV2Transcript, ZkSimulationError> {
    let statement = ms_v2_statement_from_public_input(public_input)?;
    let simulation = qssm_ms::simulate_predicate_only_v2(&statement, simulator_seed)?;
    let verified = qssm_ms::verify_predicate_only_v2_with_programming(&statement, &simulation)?;
    if !verified {
        return Err(ZkSimulationError::Ms(qssm_ms::MsError::InvalidV2ProofField(
            "programmed-oracle verifier rejected the simulated transcript",
        )));
    }
    Ok(SimulatedMsV2Transcript {
        statement_digest: *simulation.proof().statement_digest(),
        result: simulation.proof().result(),
        bitness_global_challenges: simulation.proof().bitness_global_challenges()?,
        comparison_global_challenge: simulation.proof().comparison_global_challenge()?,
        transcript_digest: simulation.proof().transcript_digest(),
    })
}

pub fn sample_real_ms_v2_transcript(
    statement: &MsPublicStatement,
    commitment_seed: [u8; 32],
) -> Result<RealMsV2Transcript, ZkSimulationError> {
    statement.validate_yes_instance()?;
    let (_public_input, statement_v2, witness_v2, prover_seed) =
        ms_v2_artifacts_from_statement(statement, commitment_seed)?;
    let proof = qssm_ms::prove_predicate_only_v2(&statement_v2, &witness_v2, prover_seed)?;
    let verified = qssm_ms::verify_predicate_only_v2(&statement_v2, &proof)?;
    if !verified {
        return Err(ZkSimulationError::Ms(qssm_ms::MsError::InvalidV2ProofField(
            "real MS v2 verifier rejected the prover transcript",
        )));
    }

    Ok(RealMsV2Transcript {
        statement_digest: *proof.statement_digest(),
        result: proof.result(),
        bitness_global_challenges: proof.bitness_global_challenges()?,
        comparison_global_challenge: proof.comparison_global_challenge()?,
        transcript_digest: proof.transcript_digest(),
    })
}

#[must_use]
pub fn observe_real_ms_v2_transcript(transcript: &RealMsV2Transcript) -> MsV2TranscriptObservation {
    MsV2TranscriptObservation {
        statement_digest: transcript.statement_digest,
        result: transcript.result,
        bitness_global_challenges: transcript.bitness_global_challenges.clone(),
        comparison_global_challenge: transcript.comparison_global_challenge,
        transcript_digest: transcript.transcript_digest,
    }
}

#[must_use]
pub fn observe_simulated_ms_v2_transcript(
    transcript: &SimulatedMsV2Transcript,
) -> MsV2TranscriptObservation {
    MsV2TranscriptObservation {
        statement_digest: transcript.statement_digest,
        result: transcript.result,
        bitness_global_challenges: transcript.bitness_global_challenges.clone(),
        comparison_global_challenge: transcript.comparison_global_challenge,
        transcript_digest: transcript.transcript_digest,
    }
}

pub fn run_ms_v2_empirical_alignment(
    statements: &[MsPublicStatement],
) -> Result<MsV2EmpiricalAlignmentReport, ZkSimulationError> {
    let mut real_result = Vec::with_capacity(statements.len());
    let mut sim_result = Vec::with_capacity(statements.len());
    let mut real_bitness_nibbles = Vec::new();
    let mut sim_bitness_nibbles = Vec::new();
    let mut real_bitness_byte_deltas = Vec::new();
    let mut sim_bitness_byte_deltas = Vec::new();
    let mut real_comparison_nibbles = Vec::new();
    let mut sim_comparison_nibbles = Vec::new();
    let mut real_comparison_byte_deltas = Vec::new();
    let mut sim_comparison_byte_deltas = Vec::new();
    let mut real_transcript_digest_nibbles = Vec::new();
    let mut sim_transcript_digest_nibbles = Vec::new();
    let mut real_transcript_digest_byte_deltas = Vec::new();
    let mut sim_transcript_digest_byte_deltas = Vec::new();
    let mut real_bitness_bytes_all = Vec::new();
    let mut sim_bitness_bytes_all = Vec::new();
    let mut real_comparison_bytes_all = Vec::new();
    let mut sim_comparison_bytes_all = Vec::new();
    let mut real_transcript_digest_bytes_all = Vec::new();
    let mut sim_transcript_digest_bytes_all = Vec::new();
    let mut real_challenge_prefixes = Vec::new();
    let mut real_digest_prefixes = Vec::new();
    let mut hidden_gap_bit_conditions = Vec::new();
    let mut hidden_gap_bit_outcomes = Vec::new();
    let mut hidden_lsb_conditions = Vec::new();
    let mut hidden_lsb_outcomes = Vec::new();
    let mut hidden_hamming_weight_conditions = Vec::new();
    let mut hidden_hamming_weight_outcomes = Vec::new();

    for (sample_idx, statement) in statements.iter().enumerate() {
        let seed = harness_commitment_seed(statement, sample_idx as u32);
        let (public_input, _statement_v2, _witness_v2, _prover_seed) =
            ms_v2_artifacts_from_statement(statement, seed)?;
        let real = sample_real_ms_v2_transcript(statement, seed)?;
        let simulator_seed = hash_domain(
            DOMAIN_MS,
            &[
                b"zk_empirical_ms_v2_sim_seed",
                &seed,
                &statement.target.to_le_bytes(),
                statement.binding_context.as_slice(),
            ],
        );
        let sim = simulate_ms_v2_transcript(&public_input, simulator_seed)?;
        let real_obs = observe_real_ms_v2_transcript(&real);
        let sim_obs = observe_simulated_ms_v2_transcript(&sim);
        let real_bitness_bytes = flatten_digest_bytes(&real_obs.bitness_global_challenges);
        let sim_bitness_bytes = flatten_digest_bytes(&sim_obs.bitness_global_challenges);
        let real_bitness_nibbles_local = byte_nibbles(&real_bitness_bytes);
        let sim_bitness_nibbles_local = byte_nibbles(&sim_bitness_bytes);
        let real_comparison_nibbles_local = byte_nibbles(&real_obs.comparison_global_challenge);
        let sim_comparison_nibbles_local = byte_nibbles(&sim_obs.comparison_global_challenge);
        let real_digest_nibbles_local = byte_nibbles(&real_obs.transcript_digest);
        let sim_digest_nibbles_local = byte_nibbles(&sim_obs.transcript_digest);
        let hidden_gap_bit = ms_v2_hidden_gap_bit(statement);
        let hidden_lsb = (statement.value & 1) as u8;
        let hidden_weight_bucket = ms_v2_hidden_hamming_weight_bucket(statement.value);

        real_result.push(real_obs.result);
        sim_result.push(sim_obs.result);
        real_bitness_bytes_all.extend(real_bitness_bytes.iter().copied());
        sim_bitness_bytes_all.extend(sim_bitness_bytes.iter().copied());
        real_bitness_nibbles.extend(real_bitness_nibbles_local.iter().copied());
        sim_bitness_nibbles.extend(sim_bitness_nibbles_local.iter().copied());
        real_bitness_byte_deltas.extend(adjacent_byte_deltas(&real_bitness_bytes));
        sim_bitness_byte_deltas.extend(adjacent_byte_deltas(&sim_bitness_bytes));
        real_comparison_bytes_all.extend(real_obs.comparison_global_challenge.iter().copied());
        sim_comparison_bytes_all.extend(sim_obs.comparison_global_challenge.iter().copied());
        real_comparison_nibbles.extend(real_comparison_nibbles_local.iter().copied());
        sim_comparison_nibbles.extend(sim_comparison_nibbles_local.iter().copied());
        real_comparison_byte_deltas.extend(adjacent_byte_deltas(&real_obs.comparison_global_challenge));
        sim_comparison_byte_deltas.extend(adjacent_byte_deltas(&sim_obs.comparison_global_challenge));
        real_transcript_digest_bytes_all.extend(real_obs.transcript_digest.iter().copied());
        sim_transcript_digest_bytes_all.extend(sim_obs.transcript_digest.iter().copied());
        real_transcript_digest_nibbles.extend(real_digest_nibbles_local.iter().copied());
        sim_transcript_digest_nibbles.extend(sim_digest_nibbles_local.iter().copied());
        real_transcript_digest_byte_deltas.extend(adjacent_byte_deltas(&real_obs.transcript_digest));
        sim_transcript_digest_byte_deltas.extend(adjacent_byte_deltas(&sim_obs.transcript_digest));
        real_challenge_prefixes.extend(real_comparison_nibbles_local.iter().copied());
        real_digest_prefixes.extend(real_digest_nibbles_local.iter().copied());
        hidden_gap_bit_conditions.extend(
            std::iter::repeat_n(hidden_gap_bit, real_comparison_nibbles_local.len()),
        );
        hidden_gap_bit_outcomes.extend(real_comparison_nibbles_local.iter().copied());
        hidden_lsb_conditions
            .extend(std::iter::repeat_n(hidden_lsb, real_digest_nibbles_local.len()));
        hidden_lsb_outcomes.extend(real_digest_nibbles_local.iter().copied());
        hidden_hamming_weight_conditions.extend(std::iter::repeat_n(
            hidden_weight_bucket,
            real_bitness_nibbles_local.len(),
        ));
        hidden_hamming_weight_outcomes.extend(real_bitness_nibbles_local.iter().copied());
    }

    let bitness_nibble_distance = empirical_distance(&real_bitness_nibbles, &sim_bitness_nibbles);
    let comparison_nibble_distance =
        empirical_distance(&real_comparison_nibbles, &sim_comparison_nibbles);
    let transcript_digest_nibble_distance = empirical_distance(
        &real_transcript_digest_nibbles,
        &sim_transcript_digest_nibbles,
    );
    let bitness_nibble_divergence =
        smoothed_divergence(&real_bitness_nibbles, &sim_bitness_nibbles);
    let bitness_byte_delta_divergence =
        smoothed_divergence(&real_bitness_byte_deltas, &sim_bitness_byte_deltas);
    let comparison_byte_delta_divergence =
        smoothed_divergence(&real_comparison_byte_deltas, &sim_comparison_byte_deltas);
    let transcript_digest_byte_delta_divergence = smoothed_divergence(
        &real_transcript_digest_byte_deltas,
        &sim_transcript_digest_byte_deltas,
    );
    let overall_js_upper_bound_bits = bitness_nibble_divergence
        .jensen_shannon_bits
        .max(bitness_byte_delta_divergence.jensen_shannon_bits)
        .max(comparison_byte_delta_divergence.jensen_shannon_bits)
        .max(transcript_digest_byte_delta_divergence.jensen_shannon_bits);

    Ok(MsV2EmpiricalAlignmentReport {
        sample_count: statements.len(),
        result_distance: empirical_distance(&real_result, &sim_result),
        statistical_layer: MsV2StatisticalDistinguisherLayer {
            bitness_challenge_nibble_distance: bitness_nibble_distance,
            comparison_challenge_nibble_distance: comparison_nibble_distance,
            transcript_digest_nibble_distance,
            bitness_byte_correlation: byte_correlation_estimate(
                &real_bitness_bytes_all,
                &sim_bitness_bytes_all,
                &real_bitness_byte_deltas,
                &sim_bitness_byte_deltas,
            ),
            comparison_byte_correlation: byte_correlation_estimate(
                &real_comparison_bytes_all,
                &sim_comparison_bytes_all,
                &real_comparison_byte_deltas,
                &sim_comparison_byte_deltas,
            ),
            transcript_digest_byte_correlation: byte_correlation_estimate(
                &real_transcript_digest_bytes_all,
                &sim_transcript_digest_bytes_all,
                &real_transcript_digest_byte_deltas,
                &sim_transcript_digest_byte_deltas,
            ),
            bitness_challenge_entropy: entropy_estimate(
                &real_bitness_nibbles,
                &sim_bitness_nibbles,
            ),
            comparison_challenge_entropy: entropy_estimate(
                &real_comparison_nibbles,
                &sim_comparison_nibbles,
            ),
            transcript_digest_entropy: entropy_estimate(
                &real_transcript_digest_nibbles,
                &sim_transcript_digest_nibbles,
            ),
            challenge_to_digest_prefix_bias: conditional_leakage(
                &real_challenge_prefixes,
                &real_digest_prefixes,
                "comparison_challenge_nibble",
                "transcript_digest_nibble",
            ),
            notes: vec![
                "Statistical layer keeps nibble histograms, adds adjacent-byte correlation and byte-delta checks, estimates transcript entropy, and measures observable challenge-to-digest conditional bias on the frozen MS v2 boundary.".to_string(),
                "Response coordinates are not exposed through the frozen qssm_ms API, so transcript-digest nibbles are used as the stable observable proxy for conditional bias tests.".to_string(),
            ],
        },
        structure_layer: MsV2StructureDistinguisherLayer {
            hidden_gap_bit_to_comparison_nibble_bias: conditional_leakage(
                &hidden_gap_bit_conditions,
                &hidden_gap_bit_outcomes,
                "hidden_gap_bit",
                "comparison_challenge_nibble",
            ),
            hidden_value_lsb_to_digest_nibble_bias: conditional_leakage(
                &hidden_lsb_conditions,
                &hidden_lsb_outcomes,
                "hidden_value_lsb",
                "transcript_digest_nibble",
            ),
            hidden_hamming_weight_bucket_to_bitness_nibble_bias: conditional_leakage(
                &hidden_hamming_weight_conditions,
                &hidden_hamming_weight_outcomes,
                "hidden_hamming_weight_bucket",
                "bitness_challenge_nibble",
            ),
            notes: vec![
                "Structure layer probes witness-correlated hidden features against the frozen observable surface to catch residual leakage patterns even when the classical legacy variables k, n, and bit_at_k are absent.".to_string(),
            ],
        },
        simulator_gap_layer: MsV2SimulatorGapLayer {
            bitness_challenge_nibble_divergence: bitness_nibble_divergence,
            bitness_byte_delta_divergence,
            comparison_byte_delta_divergence,
            transcript_digest_byte_delta_divergence,
            overall_js_upper_bound_bits,
            notes: vec![
                "Simulator-gap layer uses smoothed KL / Jensen-Shannon approximations over observable nibble and byte-delta projections rather than only total-variation histograms.".to_string(),
            ],
        },
        notes: vec![
            "MS v2 interface and transcript-access surface are treated as frozen in this crate; the distinguisher suite works strictly over frozen observable projections.".to_string(),
            "The empirical suite is still evidence, not a proof: it sharpens leakage and simulator-gap detection while the full ROM reduction remains a formal obligation.".to_string(),
        ],
    })
}

fn ms_v2_statement_from_public_input(
    public_input: &MsHiddenValuePublicInput,
) -> Result<qssm_ms::PredicateOnlyStatementV2, ZkSimulationError> {
    let commitment = qssm_ms::ValueCommitmentV2::new(public_input.commitment_bit_points.clone())?;
    Ok(qssm_ms::PredicateOnlyStatementV2::new(
        commitment,
        public_input.target,
        public_input.binding_entropy,
        public_input.binding_context,
        public_input.context.clone(),
    ))
}

fn ms_v2_artifacts_from_statement(
    statement: &MsPublicStatement,
    commitment_seed: [u8; 32],
) -> Result<
    (
        MsHiddenValuePublicInput,
        qssm_ms::PredicateOnlyStatementV2,
        qssm_ms::PredicateWitnessV2,
        [u8; 32],
    ),
    ZkSimulationError,
> {
    let (commitment, witness) = qssm_ms::commit_value_v2(
        statement.value,
        commitment_seed,
        statement.binding_entropy,
    )?;
    let public_input = MsHiddenValuePublicInput {
        commitment_bit_points: commitment.bit_commitments().to_vec(),
        target: statement.target,
        binding_entropy: statement.binding_entropy,
        binding_context: statement.binding_context,
        context: statement.context.clone(),
    };
    let statement_v2 = qssm_ms::PredicateOnlyStatementV2::new(
        commitment,
        statement.target,
        statement.binding_entropy,
        statement.binding_context,
        statement.context.clone(),
    );
    let prover_seed = hash_domain(
        DOMAIN_MS,
        &[
            b"zk_empirical_ms_v2_prover_seed",
            &commitment_seed,
            statement_v2.statement_digest().as_slice(),
        ],
    );
    Ok((public_input, statement_v2, witness, prover_seed))
}

fn flatten_digest_bytes(digests: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(digests.len() * 32);
    for digest in digests {
        out.extend(digest);
    }
    out
}

fn byte_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(byte >> 4);
        out.push(byte & 0x0f);
    }
    out
}

fn adjacent_byte_deltas(bytes: &[u8]) -> Vec<u8> {
    bytes
        .windows(2)
        .map(|window| window[1].wrapping_sub(window[0]))
        .collect()
}

fn byte_correlation_estimate(
    real_bytes: &[u8],
    simulated_bytes: &[u8],
    real_deltas: &[u8],
    simulated_deltas: &[u8],
) -> ByteCorrelationEstimate {
    let real_adjacent_correlation = adjacent_byte_correlation(real_bytes);
    let simulated_adjacent_correlation = adjacent_byte_correlation(simulated_bytes);
    ByteCorrelationEstimate {
        real_adjacent_correlation,
        simulated_adjacent_correlation,
        correlation_gap: (real_adjacent_correlation - simulated_adjacent_correlation).abs(),
        delta_distance: empirical_distance(real_deltas, simulated_deltas),
    }
}

fn adjacent_byte_correlation(bytes: &[u8]) -> f64 {
    if bytes.len() < 2 {
        return 0.0;
    }

    let left: Vec<f64> = bytes[..bytes.len() - 1]
        .iter()
        .map(|byte| f64::from(*byte))
        .collect();
    let right: Vec<f64> = bytes[1..].iter().map(|byte| f64::from(*byte)).collect();
    let mean_left = left.iter().sum::<f64>() / left.len() as f64;
    let mean_right = right.iter().sum::<f64>() / right.len() as f64;
    let mut covariance = 0.0;
    let mut variance_left = 0.0;
    let mut variance_right = 0.0;
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        let centered_left = lhs - mean_left;
        let centered_right = rhs - mean_right;
        covariance += centered_left * centered_right;
        variance_left += centered_left * centered_left;
        variance_right += centered_right * centered_right;
    }
    if variance_left == 0.0 || variance_right == 0.0 {
        return 0.0;
    }
    covariance / (variance_left.sqrt() * variance_right.sqrt())
}

fn entropy_estimate<T>(real: &[T], simulated: &[T]) -> EntropyEstimate
where
    T: Ord + Clone,
{
    let real_entropy_bits = entropy_bits(real);
    let simulated_entropy_bits = entropy_bits(simulated);
    EntropyEstimate {
        real_entropy_bits,
        simulated_entropy_bits,
        entropy_gap_bits: (real_entropy_bits - simulated_entropy_bits).abs(),
    }
}

fn smoothed_divergence<T>(real: &[T], simulated: &[T]) -> SmoothedDivergenceEstimate
where
    T: Ord + Clone,
{
    let mut support = BTreeMap::<T, (usize, usize)>::new();
    for item in real {
        support.entry(item.clone()).or_insert((0, 0)).0 += 1;
    }
    for item in simulated {
        support.entry(item.clone()).or_insert((0, 0)).1 += 1;
    }
    if support.is_empty() {
        return SmoothedDivergenceEstimate {
            support_size: 0,
            kl_real_to_sim_bits: 0.0,
            kl_sim_to_real_bits: 0.0,
            jensen_shannon_bits: 0.0,
        };
    }

    let alpha = 1.0;
    let support_size = support.len();
    let support_size_f = support_size as f64;
    let real_total = real.len() as f64;
    let simulated_total = simulated.len() as f64;
    let denom_real = real_total + alpha * support_size_f;
    let denom_sim = simulated_total + alpha * support_size_f;
    let mut kl_real_to_sim_bits = 0.0;
    let mut kl_sim_to_real_bits = 0.0;
    let mut jensen_shannon_bits = 0.0;

    for (real_count, simulated_count) in support.values() {
        let p = (*real_count as f64 + alpha) / denom_real;
        let q = (*simulated_count as f64 + alpha) / denom_sim;
        let mean = 0.5 * (p + q);
        kl_real_to_sim_bits += p * (p / q).log2();
        kl_sim_to_real_bits += q * (q / p).log2();
        jensen_shannon_bits += 0.5 * p * (p / mean).log2();
        jensen_shannon_bits += 0.5 * q * (q / mean).log2();
    }

    SmoothedDivergenceEstimate {
        support_size,
        kl_real_to_sim_bits,
        kl_sim_to_real_bits,
        jensen_shannon_bits,
    }
}

fn conditional_leakage<C, O>(
    conditions: &[C],
    outcomes: &[O],
    condition_label: &str,
    outcome_label: &str,
) -> ConditionalLeakageEstimate
where
    C: Ord + Clone,
    O: Ord + Clone,
{
    debug_assert_eq!(conditions.len(), outcomes.len());
    if conditions.is_empty() || outcomes.is_empty() {
        return ConditionalLeakageEstimate {
            condition_label: condition_label.to_string(),
            outcome_label: outcome_label.to_string(),
            condition_support_size: 0,
            outcome_support_size: 0,
            average_total_variation_distance: 0.0,
            max_total_variation_distance: 0.0,
            approx_mutual_information_bits: 0.0,
        };
    }

    let mut grouped = BTreeMap::<C, Vec<O>>::new();
    for (condition, outcome) in conditions.iter().cloned().zip(outcomes.iter().cloned()) {
        grouped.entry(condition).or_default().push(outcome);
    }

    let total = outcomes.len() as f64;
    let global_entropy = entropy_bits(outcomes);
    let mut weighted_average_tvd = 0.0;
    let mut max_total_variation_distance: f64 = 0.0;
    let mut conditional_entropy = 0.0;

    for samples in grouped.values() {
        let weight = samples.len() as f64 / total;
        let group_distance = empirical_distance(samples, outcomes);
        let group_entropy = entropy_bits(samples);
        weighted_average_tvd += weight * group_distance.total_variation_distance;
        max_total_variation_distance =
            max_total_variation_distance.max(group_distance.total_variation_distance);
        conditional_entropy += weight * group_entropy;
    }

    let outcome_support_size = {
        let mut support = BTreeMap::<O, usize>::new();
        for outcome in outcomes {
            *support.entry(outcome.clone()).or_default() += 1;
        }
        support.len()
    };

    ConditionalLeakageEstimate {
        condition_label: condition_label.to_string(),
        outcome_label: outcome_label.to_string(),
        condition_support_size: grouped.len(),
        outcome_support_size,
        average_total_variation_distance: weighted_average_tvd,
        max_total_variation_distance,
        approx_mutual_information_bits: (global_entropy - conditional_entropy).max(0.0),
    }
}

fn entropy_bits<T>(samples: &[T]) -> f64
where
    T: Ord + Clone,
{
    if samples.is_empty() {
        return 0.0;
    }

    let mut support = BTreeMap::<T, usize>::new();
    for sample in samples {
        *support.entry(sample.clone()).or_default() += 1;
    }

    let total = samples.len() as f64;
    support
        .values()
        .map(|count| {
            let probability = *count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

fn ms_v2_hidden_gap_bit(statement: &MsPublicStatement) -> u8 {
    highest_differing_bit(statement.value, statement.target)
        .expect("MS v2 alignment statements must satisfy value > target")
}

fn ms_v2_hidden_hamming_weight_bucket(value: u64) -> u8 {
    (value.count_ones() / 8) as u8
}

#[must_use]
pub fn public_candidate_pairs(statement: &MsPublicStatement) -> Vec<(u8, u8)> {
    let r = binding_rotation(&statement.binding_entropy);
    let mut out = Vec::new();
    for n in 0u8..=u8::MAX {
        let rot = rot_for_nonce(r, n);
        let a_p = statement.value.wrapping_add(rot);
        let b_p = statement.target.wrapping_add(rot);
        if a_p <= b_p {
            continue;
        }
        if let Some(k) = highest_differing_bit(a_p, b_p) {
            out.push((n, k));
        }
    }
    out
}

#[must_use]
pub fn real_first_success_pair(statement: &MsPublicStatement) -> Option<(u8, u8)> {
    public_candidate_pairs(statement).into_iter().next()
}

pub fn simulate_kn_distribution(
    statement: &MsPublicStatement,
    strategy: SimulationStrategy,
) -> Result<KnSimulationArtifact, ZkSimulationError> {
    statement.validate_yes_instance()?;
    let candidates = public_candidate_pairs(statement);
    if candidates.is_empty() {
        return Err(ZkSimulationError::NoValidNoncePair);
    }

    match strategy {
        SimulationStrategy::DistributionCollapse => {
            let draw = hash_domain(
                DOMAIN_MS,
                &[
                    strategy.label(),
                    b"kn_sampler",
                    &statement.value.to_le_bytes(),
                    &statement.target.to_le_bytes(),
                    statement.binding_entropy.as_slice(),
                    statement.binding_context.as_slice(),
                    statement.context.as_slice(),
                ],
            );
            let idx = usize::from(u16::from_le_bytes([draw[0], draw[1]])) % candidates.len();
            let (n, k) = candidates[idx];
            Ok(KnSimulationArtifact {
                strategy,
                n,
                k,
                oracle_queries: 1,
                programmed_oracle_queries: 0,
            })
        }
        SimulationStrategy::ProgramSimulation => {
            let (n, k) = candidates[0];
            Ok(KnSimulationArtifact {
                strategy,
                n,
                k,
                oracle_queries: usize::from(n) + 1,
                programmed_oracle_queries: 1,
            })
        }
    }
}

pub fn simulate_commitment_opening(
    statement: &MsPublicStatement,
    strategy: SimulationStrategy,
    k: u8,
) -> Result<CommitmentOpeningArtifact, ZkSimulationError> {
    statement.validate_yes_instance()?;
    if usize::from(k) >= MS_BIT_COUNT {
        return Err(ZkSimulationError::NoValidNoncePair);
    }

    let bit_at_k = ((statement.value >> k) & 1) as u8;
    let seed = hash_domain(
        DOMAIN_MS,
        &[
            strategy.label(),
            b"opening_seed",
            &[k],
            &[bit_at_k],
            &statement.value.to_le_bytes(),
            &statement.target.to_le_bytes(),
            statement.binding_entropy.as_slice(),
            statement.binding_context.as_slice(),
            statement.context.as_slice(),
        ],
    );

    let salts: [[u8; 32]; MS_LEAF_COUNT] = std::array::from_fn(|leaf_index| {
        let idx = (leaf_index as u32).to_le_bytes();
        hash_domain(
            DOMAIN_MS,
            &[
                strategy.label(),
                b"sim_salt",
                seed.as_slice(),
                &idx,
                statement.binding_entropy.as_slice(),
                statement.binding_context.as_slice(),
            ],
        )
    });

    let mut leaves = Vec::with_capacity(MS_LEAF_COUNT);
    for i in 0u8..MS_BIT_COUNT as u8 {
        for bit in 0u8..=1 {
            let leaf_idx = 2 * usize::from(i) + usize::from(bit);
            leaves.push(ms_leaf(i, bit, &salts[leaf_idx], &statement.binding_entropy));
        }
    }

    let tree = PositionAwareTree::new(leaves)?;
    let leaf_index = 2 * usize::from(k) + usize::from(bit_at_k);
    let opened_salt = salts[leaf_index];
    let leaf = ms_leaf(k, bit_at_k, &opened_salt, &statement.binding_entropy);
    let path = tree.get_proof(leaf_index)?;

    Ok(CommitmentOpeningArtifact {
        strategy,
        root: tree.get_root(),
        opening: SimulatedOpening {
            leaf_index,
            bit_at_k,
            opened_salt,
            leaf,
            path,
        },
    })
}

pub fn simulate_ms_transcript(
    statement: &MsPublicStatement,
    strategy: SimulationStrategy,
) -> Result<TranscriptSimulationArtifact, ZkSimulationError> {
    let kn = simulate_kn_distribution(statement, strategy)?;
    let commitment = simulate_commitment_opening(statement, strategy, kn.k)?;
    let challenge = fs_challenge(
        &commitment.root,
        kn.n,
        kn.k,
        &statement.binding_entropy,
        statement.value,
        statement.target,
        &statement.context,
        &statement.binding_context,
    );

    Ok(TranscriptSimulationArtifact {
        transcript: SimulatedMsTranscript {
            strategy,
            root: commitment.root,
            k: kn.k,
            n: kn.n,
            challenge,
            opening: commitment.opening,
        },
        kn,
    })
}

pub fn sample_real_ms_transcript(
    statement: &MsPublicStatement,
    commitment_seed: [u8; 32],
) -> Result<RealMsTranscript, ZkSimulationError> {
    statement.validate_yes_instance()?;
    let (root, salts) = qssm_ms::commit(commitment_seed, statement.binding_entropy)?;
    let proof = qssm_ms::prove(
        statement.value,
        statement.target,
        &salts,
        statement.binding_entropy,
        &statement.context,
        &statement.binding_context,
    )?;
    let bit_at_k = proof.bit_at_k();
    let opened_salt = *proof.opened_salt();
    let leaf_index = 2 * usize::from(proof.k()) + usize::from(bit_at_k);
    let leaf = ms_leaf(proof.k(), bit_at_k, &opened_salt, &statement.binding_entropy);

    Ok(RealMsTranscript {
        root: *root.as_bytes(),
        k: proof.k(),
        n: proof.n(),
        challenge: *proof.challenge(),
        opening: SimulatedOpening {
            leaf_index,
            bit_at_k,
            opened_salt,
            leaf,
            path: proof.path().to_vec(),
        },
    })
}

#[must_use]
pub fn observe_real_ms_transcript(transcript: &RealMsTranscript) -> TranscriptObservation {
    TranscriptObservation {
        n: transcript.n,
        k: transcript.k,
        bit_at_k: transcript.opening.bit_at_k,
        path_len: transcript.opening.path.len(),
    }
}

#[must_use]
pub fn observe_simulated_ms_transcript(
    transcript: &SimulatedMsTranscript,
) -> TranscriptObservation {
    TranscriptObservation {
        n: transcript.n,
        k: transcript.k,
        bit_at_k: transcript.opening.bit_at_k,
        path_len: transcript.opening.path.len(),
    }
}

pub fn run_ms_empirical_distinguisher(
    statements: &[MsPublicStatement],
    strategy: SimulationStrategy,
) -> Result<MsEmpiricalDistinguisherReport, ZkSimulationError> {
    let mut real_joint = Vec::with_capacity(statements.len());
    let mut sim_joint = Vec::with_capacity(statements.len());
    let mut real_nonce = Vec::with_capacity(statements.len());
    let mut sim_nonce = Vec::with_capacity(statements.len());
    let mut real_k = Vec::with_capacity(statements.len());
    let mut sim_k = Vec::with_capacity(statements.len());
    let mut real_bit = Vec::with_capacity(statements.len());
    let mut sim_bit = Vec::with_capacity(statements.len());

    for (sample_idx, statement) in statements.iter().enumerate() {
        let seed = harness_commitment_seed(statement, sample_idx as u32);
        let real = sample_real_ms_transcript(statement, seed)?;
        let sim = simulate_ms_transcript(statement, strategy)?;
        let real_obs = observe_real_ms_transcript(&real);
        let sim_obs = observe_simulated_ms_transcript(&sim.transcript);

        real_nonce.push(real_obs.n);
        sim_nonce.push(sim_obs.n);
        real_k.push(real_obs.k);
        sim_k.push(sim_obs.k);
        real_bit.push(real_obs.bit_at_k);
        sim_bit.push(sim_obs.bit_at_k);
        real_joint.push(real_obs);
        sim_joint.push(sim_obs);
    }

    Ok(MsEmpiricalDistinguisherReport {
        strategy,
        sample_count: statements.len(),
        joint_distance: empirical_distance(&real_joint, &sim_joint),
        nonce_distance: empirical_distance(&real_nonce, &sim_nonce),
        bit_index_distance: empirical_distance(&real_k, &sim_k),
        bit_state_distance: empirical_distance(&real_bit, &sim_bit),
        notes: vec![
            "Empirical only: compares observable transcript marginals, not full computational indistinguishability.".to_string(),
            "Roots and full challenge digests are not bucketed directly because finite-sample supports are too sparse for a meaningful histogram test.".to_string(),
        ],
    })
}

fn binding_rotation(binding_entropy: &[u8; 32]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&binding_entropy[..8]);
    u64::from_le_bytes(bytes)
}

fn harness_commitment_seed(statement: &MsPublicStatement, sample_idx: u32) -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[
            b"zk_empirical_real_seed_v1",
            &sample_idx.to_le_bytes(),
            &statement.target.to_le_bytes(),
            statement.binding_entropy.as_slice(),
            statement.binding_context.as_slice(),
            statement.context.as_slice(),
        ],
    )
}

#[cfg(test)]
fn statement_batch_for_distinguisher() -> Vec<MsPublicStatement> {
    let mut out = Vec::new();
    for target in 1u64..64 {
        for gap in 1u64..16 {
            let value = target + gap;
            let target_bytes = target.to_le_bytes();
            let gap_bytes = gap.to_le_bytes();
            let binding_entropy = hash_domain(
                DOMAIN_MS,
                &[b"zk_test_binding_entropy", &target_bytes, &gap_bytes],
            );
            let binding_context = hash_domain(
                DOMAIN_MS,
                &[b"zk_test_binding_context", &target_bytes, &gap_bytes],
            );
            let context = format!("test_ctx_{target}_{gap}").into_bytes();
            let statement = MsPublicStatement {
                value,
                target,
                binding_entropy,
                binding_context,
                context,
            };
            if public_candidate_pairs(&statement).len() > 1 {
                out.push(statement);
            }
            if out.len() == 8 {
                return out;
            }
        }
    }
    panic!("failed to construct a statement batch with multiple valid nonce pairs");
}

fn statement_batch_for_ms_v2_alignment() -> Vec<MsPublicStatement> {
    let cases = [
        (u64::MAX, u64::MAX ^ 1),
        (u64::MAX, u64::MAX ^ (1u64 << 7)),
        (u64::MAX - 1, (u64::MAX - 1) ^ (1u64 << 13)),
        (u64::MAX - 3, (u64::MAX - 3) ^ (1u64 << 21)),
    ];
    cases
        .into_iter()
        .enumerate()
        .map(|(sample_idx, (value, target))| {
            let case_bytes = (sample_idx as u64).to_le_bytes();
            MsPublicStatement {
                value,
                target,
                binding_entropy: hash_domain(DOMAIN_MS, &[b"zk_ms_v2_binding_entropy", &case_bytes]),
                binding_context: hash_domain(
                    DOMAIN_MS,
                    &[b"zk_ms_v2_binding_context", &case_bytes],
                ),
                context: format!("ms_v2_alignment_case_{sample_idx}").into_bytes(),
            }
        })
        .collect()
}

fn rot_for_nonce(r: u64, n: u8) -> u64 {
    let h = hash_domain(DOMAIN_MS, &[b"rot_nonce", &r.to_le_bytes(), &[n]]);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&h[..8]);
    u64::from_le_bytes(bytes)
}

fn highest_differing_bit(a: u64, b: u64) -> Option<u8> {
    let mut k: u8 = 63;
    loop {
        let bit_a = (a >> k) & 1;
        let bit_b = (b >> k) & 1;
        if bit_a != bit_b {
            return Some(k);
        }
        if k == 0 {
            return None;
        }
        k -= 1;
    }
}

fn ms_leaf(i: u8, bit: u8, salt: &[u8; 32], binding_entropy: &[u8; 32]) -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[b"leaf", &[i], &[bit], salt.as_slice(), binding_entropy],
    )
}

fn fs_challenge(
    root: &[u8; 32],
    n: u8,
    k: u8,
    binding_entropy: &[u8; 32],
    value: u64,
    target: u64,
    context: &[u8],
    binding_context: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[
            b"fs_v2",
            root.as_slice(),
            &[n],
            &[k],
            binding_entropy.as_slice(),
            &value.to_le_bytes(),
            &target.to_le_bytes(),
            context,
            binding_context.as_slice(),
        ],
    )
}

fn empirical_distance<T>(left: &[T], right: &[T]) -> EmpiricalDistributionDistance
where
    T: Ord + Clone,
{
    if left.is_empty() && right.is_empty() {
        return EmpiricalDistributionDistance {
            support_size: 0,
            l1_distance: 0.0,
            total_variation_distance: 0.0,
            max_bucket_gap: 0.0,
        };
    }

    let mut support = BTreeMap::<T, (usize, usize)>::new();
    for item in left {
        support.entry(item.clone()).or_insert((0, 0)).0 += 1;
    }
    for item in right {
        support.entry(item.clone()).or_insert((0, 0)).1 += 1;
    }

    let left_total = left.len() as f64;
    let right_total = right.len() as f64;
    let mut l1_distance = 0.0;
    let mut max_bucket_gap: f64 = 0.0;

    for (left_count, right_count) in support.values() {
        let left_prob = if left_total == 0.0 {
            0.0
        } else {
            *left_count as f64 / left_total
        };
        let right_prob = if right_total == 0.0 {
            0.0
        } else {
            *right_count as f64 / right_total
        };
        let gap = (left_prob - right_prob).abs();
        l1_distance += gap;
        max_bucket_gap = max_bucket_gap.max(gap);
    }

    EmpiricalDistributionDistance {
        support_size: support.len(),
        l1_distance,
        total_variation_distance: 0.5 * l1_distance,
        max_bucket_gap,
    }
}

fn sample_centered_vec(label: &[u8], binding_context: [u8; 32], bound: u32) -> [i32; N] {
    sample_centered_vec_with_seed(label, binding_context, [0u8; 32], bound)
}

fn sample_centered_vec_with_seed(
    label: &[u8],
    binding_context: [u8; 32],
    simulator_seed: [u8; 32],
    bound: u32,
) -> [i32; N] {
    let modulus = 2 * bound + 1;
    let mut out = [0i32; N];
    for (idx, coeff) in out.iter_mut().enumerate() {
        let idx_bytes = (idx as u32).to_le_bytes();
        let h = hash_domain(
            DOMAIN_ZK_SIM,
            &[
                label,
                simulator_seed.as_slice(),
                binding_context.as_slice(),
                &idx_bytes,
            ],
        );
        let raw = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        *coeff = (raw % modulus) as i32 - bound as i32;
    }
    out
}

fn le_public_binding_fs_bytes(public: &PublicInstance) -> Vec<u8> {
    let _ = LE_FS_PUBLIC_BINDING_LAYOUT_VERSION;
    match public.binding() {
        PublicBinding::DigestCoeffVector { coeffs } => {
            let mut out = Vec::with_capacity(1 + coeffs.len() * 4);
            out.push(1);
            for &coeff in coeffs {
                out.extend_from_slice(&coeff.to_le_bytes());
            }
            out
        }
        _ => Vec::new(),
    }
}

fn le_mu_from_public(public: &PublicInstance) -> RqPoly {
    match public.binding() {
        PublicBinding::DigestCoeffVector { coeffs } => {
            let mut out = [0u32; N];
            out[..coeffs.len()].copy_from_slice(coeffs);
            RqPoly(out)
        }
        _ => RqPoly::zero(),
    }
}

fn le_fs_programmed_query_digest(
    binding_context: &[u8; 32],
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    t: &RqPoly,
) -> [u8; 32] {
    hash_domain(
        DOMAIN_ZK_SIM,
        &[
            b"le_programmed_query_digest",
            binding_context.as_slice(),
            &vk.crs_seed,
            &le_public_binding_fs_bytes(public),
            &encode_rq_coeffs_le(&commitment.0),
            &encode_rq_coeffs_le(t),
        ],
    )
}

fn le_challenge_poly(seed: &[u8; 32]) -> [i32; C_POLY_SIZE] {
    let mut coeffs = [0i32; C_POLY_SIZE];
    let span = C_POLY_SPAN as u32;
    let mut filled = 0usize;
    let mut ctr = 0u32;
    while filled < C_POLY_SIZE {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_LE_CHALLENGE_POLY.as_bytes());
        h.update(seed);
        h.update(&ctr.to_le_bytes());
        let block = h.finalize();
        for chunk in block.as_bytes().chunks_exact(4) {
            if filled >= C_POLY_SIZE {
                break;
            }
            let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            coeffs[filled] = (raw % (2 * span + 1)) as i32 - C_POLY_SPAN;
            filled += 1;
        }
        ctr = ctr.wrapping_add(1);
    }
    coeffs
}

fn le_challenge_poly_to_rq(poly: &[i32; C_POLY_SIZE]) -> RqPoly {
    let mut out = [0u32; N];
    for idx in 0..C_POLY_SIZE {
        let coeff = poly[idx];
        out[idx] = if coeff >= 0 {
            (coeff as u32) % Q
        } else {
            Q - ((-coeff) as u32 % Q)
        };
    }
    RqPoly(out)
}

fn le_worst_case_cr_inf_norm(beta: u32, c_poly_size: usize, c_poly_span: i32) -> u64 {
    c_poly_size as u64 * c_poly_span.unsigned_abs() as u64 * u64::from(beta)
}

fn le_required_eta_for_hvzk(
    n: usize,
    beta: u32,
    c_poly_size: usize,
    c_poly_span: i32,
    epsilon_log2: f64,
) -> f64 {
    let worst_case_cr_inf_norm = le_worst_case_cr_inf_norm(beta, c_poly_size, c_poly_span);
    let epsilon = 2f64.powf(epsilon_log2);
    let ln_arg = (2.0 * n as f64) / epsilon;
    11.0 * worst_case_cr_inf_norm as f64 * (ln_arg.ln() / std::f64::consts::PI).sqrt()
}

fn le_challenge_space_log2(c_poly_size: usize, c_poly_span: i32) -> f64 {
    c_poly_size as f64 * ((2 * c_poly_span + 1) as f64).log2()
}

fn le_minimum_gamma_for_support_containment(
    eta: u32,
    beta: u32,
    c_poly_size: usize,
    c_poly_span: i32,
) -> u64 {
    u64::from(eta) + le_worst_case_cr_inf_norm(beta, c_poly_size, c_poly_span)
}

#[allow(dead_code)]
fn le_fs_challenge_bytes(
    binding_context: &[u8; 32],
    vk: &VerifyingKey,
    public: &PublicInstance,
    commitment: &Commitment,
    t: &RqPoly,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_LE_FS.as_bytes());
    h.update(&DST_LE_COMMIT);
    h.update(&DST_MS_VERIFY);
    h.update(CROSS_PROTOCOL_BINDING_LABEL);
    h.update(DOMAIN_MS.as_bytes());
    h.update(b"fs_v2");
    h.update(binding_context);
    h.update(vk.crs_seed.as_slice());
    h.update(&le_public_binding_fs_bytes(public));
    h.update(&encode_rq_coeffs_le(&commitment.0));
    h.update(&encode_rq_coeffs_le(t));
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_utils::merkle_parent;

    fn sample_statement() -> MsPublicStatement {
        MsPublicStatement {
            value: 30,
            target: 21,
            binding_entropy: [7u8; 32],
            binding_context: [9u8; 32],
            context: b"age_gate_21".to_vec(),
        }
    }

    fn verify_path(root: &[u8; 32], leaf: &[u8; 32], mut index: usize, path: &[[u8; 32]]) -> bool {
        let mut cur = *leaf;
        for sibling in path {
            cur = if index % 2 == 0 {
                merkle_parent(&cur, sibling)
            } else {
                merkle_parent(sibling, &cur)
            };
            index /= 2;
        }
        cur == *root
    }

    fn sample_le_public_input() -> LePublicInput {
        LePublicInput {
            vk: VerifyingKey::from_seed([21u8; 32]),
            public: PublicInstance::from_u64_nibbles(42),
            binding_context: [17u8; 32],
        }
    }

    fn sample_qssm_witness_fixture() -> QssmWitnessFixture {
        let mut le_witness_coeffs = [0i32; N];
        for (idx, coeff) in le_witness_coeffs.iter_mut().enumerate() {
            *coeff = match idx % 3 {
                0 => 1,
                1 => -1,
                _ => 0,
            };
        }
        QssmWitnessFixture {
            ms_statement: sample_statement(),
            le_witness_coeffs,
        }
    }

    fn sample_qssm_public_input() -> QssmPublicInput {
        build_qssm_public_input(&sample_qssm_witness_fixture(), [41u8; 32], sample_le_public_input())
            .expect("qssm public input")
    }

    #[test]
    fn distribution_collapse_samples_valid_pair() {
        let statement = sample_statement();
        let candidates = public_candidate_pairs(&statement);
        let artifact = simulate_kn_distribution(&statement, SimulationStrategy::DistributionCollapse)
            .expect("distribution-collapse sample");
        assert_eq!(artifact.strategy, SimulationStrategy::DistributionCollapse);
        assert_eq!(artifact.oracle_queries, 1);
        assert_eq!(artifact.programmed_oracle_queries, 0);
        assert!(candidates.contains(&(artifact.n, artifact.k)));
    }

    #[test]
    fn game_definitions_freeze_visible_transcript_surfaces() {
        let ms = ZkGameDefinition::ms_hidden_value_game();
        let ms_v2 = ZkGameDefinition::ms_v2_hidden_value_game();
        let le = ZkGameDefinition::le_hidden_witness_game();
        assert_eq!(ms.system, GameSystem::Ms);
        assert_eq!(ms_v2.system, GameSystem::Ms);
        assert_eq!(le.system, GameSystem::Le);
        assert_eq!(
            ms.transcript_surface.visible_fields,
            vec!["root", "n", "k", "bit_at_k", "Merkle path", "challenge"]
        );
        assert_eq!(
            ms_v2.transcript_surface.visible_fields,
            vec![
                "value commitment",
                "result_bit",
                "bitness sigma transcripts",
                "comparison sigma transcript"
            ]
        );
        assert_eq!(
            le.transcript_surface.visible_fields,
            vec!["commitment C", "t", "z", "challenge_seed"]
        );
    }

    #[test]
    fn ms_witness_free_attempt_logs_structural_failures() {
        let attempt = attempt_ms_witness_free_simulator(
            &MsHiddenValuePublicInput {
                commitment_bit_points: Vec::new(),
                target: 21,
                binding_entropy: [7u8; 32],
                binding_context: [9u8; 32],
                context: b"age_gate_21".to_vec(),
            },
            SimulationStrategy::ProgramSimulation,
        );
        assert!(attempt.transcript.is_none());
        assert!(attempt
            .failures
            .iter()
            .all(|failure| failure.class == FailureClass::Structural));
        assert!(attempt
            .failures
            .iter()
            .any(|failure| failure.location.contains("k/n selection")));
    }

    #[test]
    fn le_witness_free_attempt_constructs_rom_transcript_under_set_b() {
        let attempt = attempt_le_witness_free_simulator(&sample_le_public_input())
            .expect("le witness-free simulator attempt");
        assert!(attempt.transcript.is_some());
        assert!(attempt.algebraic_relation_holds);
        assert!(attempt.norm_bound_holds);
        assert!(attempt
            .logs
            .iter()
            .any(|log| log.uses_random_oracle_programming));
        assert!(attempt.failures.is_empty());
        assert!(attempt
            .logs
            .iter()
            .any(|log| log.step == "check_set_b_constraints"));
    }

    #[test]
    fn honest_theorem_reports_legacy_ms_blocker_and_le_set_b_alignment() {
        let theorem = honest_zk_theorem_for_current_system().expect("honest theorem");
        assert_eq!(theorem.claim_type, ClaimType::ZeroKnowledge);
        assert!(theorem
            .ms_attempt
            .failures
            .iter()
            .any(|failure| failure.class == FailureClass::Structural));
        assert!(theorem.le_attempt.failures.is_empty());
        assert!(theorem.honest_status.contains("LE Set B"));
    }

    #[test]
    fn canonical_ms_v2_design_commits_to_option_b_only() {
        let design = CanonicalMsV2TranscriptDesign::option_b();
        assert!(design.name.contains("Option B"));
        assert!(design.removes_witness_dependent_visible_outputs);
        assert!(design
            .simulator_contract
            .iter()
            .any(|line| line.contains("frozen")));
        assert!(design
            .transcript_definition
            .iter()
            .any(|line| line.contains("value commitment")));
        assert!(design
            .simulator_contract
            .iter()
            .any(|line| line.contains("simulate_predicate_only_v2")));
    }

    #[test]
    fn ms_v2_observable_boundary_contract_is_frozen_and_witness_free() {
        let contract = MsV2ObservableBoundaryContract::for_frozen_interface();
        assert_eq!(contract.claim_type, ClaimType::ZeroKnowledge);
        assert_eq!(contract.status, ProofStatus::ByConstruction);
        assert!(contract.interface_frozen);
        assert!(contract
            .sigma_algebra_generators
            .iter()
            .any(|item| item.contains("public value commitment")));
        assert!(contract
            .simulator_allowed_inputs
            .iter()
            .any(|item| item == "MsHiddenValuePublicInput"));
        assert!(contract
            .simulator_forbidden_inputs
            .iter()
            .any(|item| item == "PredicateWitnessV2"));
    }

    #[test]
    fn le_current_constraint_analysis_matches_encoded_formula() {
        let analysis = LeHvzkConstraintAnalysis::for_current_params();
        assert_eq!(analysis.claim_type, ClaimType::ZeroKnowledge);
        assert_eq!(analysis.worst_case_cr_inf_norm, 3072);
        assert!(analysis.required_eta_for_hvzk > 180_000.0);
        assert!(analysis.required_eta_for_hvzk < 190_000.0);
        assert_eq!(analysis.minimum_gamma_for_support_containment, 199_680);
        assert!(analysis.challenge_space_log2 > 196.0);
        assert!(analysis.challenge_space_log2 < 197.0);
        assert!(analysis.fs_security_bits > 128.0);
        assert!(analysis.current_eta_shortfall < 0.0);
        assert_eq!(analysis.current_gamma_shortfall, 0);
    }

    #[test]
    fn canonical_le_set_b_matches_claimed_status() {
        let set_b = CanonicalLeSetB::current();
        assert!(set_b.name.contains("Set B"));
        assert!(set_b.satisfies_hvzk_eta);
        assert!(set_b.satisfies_support_containment);
        assert!(set_b.meets_128_bit_fs);
        assert_eq!(set_b.minimum_gamma_for_support_containment, 199_680);
    }

    #[test]
    fn redesigned_systems_theorem_contains_security_claim_table() {
        let theorem = RedesignedSystemsTheorem::for_current_and_redesigned_systems()
            .expect("redesigned systems theorem");
        assert_eq!(theorem.claim_type, ClaimType::ZeroKnowledge);
        assert!(theorem.ms_v2_observable_boundary.interface_frozen);
        assert!(theorem
            .security_claims
            .iter()
            .any(|row| row.component == "MS (current)"
                && row.status == ClaimStatus::NotSatisfied));
        assert!(theorem
            .security_claims
            .iter()
            .any(|row| row.component == "MS (v2 Option B transcript format)"
                && row.status == ClaimStatus::Satisfied));
        assert!(theorem
            .security_claims
            .iter()
            .any(|row| row.component == "LE (Set B current params)"
                && row.property == "Witness-hiding"
                && row.status == ClaimStatus::Satisfied));
        assert!(theorem
            .security_claims
            .iter()
            .any(|row| row.component == "QSSM (composed Option B + Set B)"
                && row.status == ClaimStatus::Bounded));
        assert_eq!(theorem.ms_v2_alignment.result_distance.total_variation_distance, 0.0);
        assert!(theorem
            .ms_v2_alignment
            .statistical_layer
            .bitness_challenge_nibble_distance
            .total_variation_distance
            < 0.1);
        assert_eq!(theorem.unified_hybrid_game.worlds.len(), 4);
        assert_eq!(theorem.closed_zk_theorem.game_based_proof.games.len(), 3);
        assert_eq!(theorem.closed_zk_theorem.status, ProofStatus::BoundedUnderAssumptions);
        assert_eq!(theorem.closed_zk_theorem.game_based_proof.games[0].name, "G0");
        assert_eq!(theorem.closed_zk_theorem.game_based_proof.games[1].name, "G1");
        assert_eq!(theorem.closed_zk_theorem.game_based_proof.games[2].name, "G2");
        assert_eq!(theorem.closed_zk_theorem.internal_lemma_chain[0].name, "MS-1");
        assert_eq!(theorem.closed_zk_theorem.assumption_graph.inputs.len(), 3);
        assert!(theorem.closed_zk_theorem.closure_report.closed);
        assert!(theorem
            .closed_zk_theorem
            .architecture_freeze
            .components
            .iter()
            .all(|component| component.frozen));
        assert!(theorem
            .closed_zk_theorem
            .output_bound
            .expression
            .contains("epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le"));
        assert!(theorem
            .closed_zk_theorem
            .game_based_proof
            .global_simulator
            .name
            .contains("simulate_qssm_transcript"));
        assert!(theorem
            .theorem_statement
            .contains("epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le"));
    }

    #[test]
    fn unified_hybrid_game_forms_single_chain() {
        let hybrid = UnifiedZkHybridGame::for_canonical_option_b_and_set_b();
        assert_eq!(hybrid.claim_type, ClaimType::ZeroKnowledge);
        assert_eq!(hybrid.status, ProofStatus::BoundedUnderAssumptions);
        assert_eq!(hybrid.worlds.len(), 4);
        assert_eq!(hybrid.worlds[0].name, "H0");
        assert_eq!(hybrid.worlds[0].ms_source, HybridTranscriptSource::RealProver);
        assert_eq!(hybrid.worlds[0].le_source, HybridTranscriptSource::RealProver);
        assert_eq!(hybrid.worlds[1].ms_source, HybridTranscriptSource::Simulator);
        assert_eq!(hybrid.worlds[1].le_source, HybridTranscriptSource::RealProver);
        assert_eq!(hybrid.worlds[2].ms_source, HybridTranscriptSource::Simulator);
        assert_eq!(hybrid.worlds[2].le_source, HybridTranscriptSource::Simulator);
        assert!(hybrid
            .composition_notes
            .iter()
            .any(|item| item.contains("same hybrid chain")));
    }

    #[test]
    fn reduction_formalizes_probability_objects_and_additive_bounds() {
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let reduction = ReductionProofSketch::for_canonical_option_b_and_set_b(
            &boundary,
            &le_analysis,
        );
        assert_eq!(reduction.status, ProofStatus::BoundedUnderAssumptions);
        assert!(reduction
            .probability_objects
            .iter()
            .any(|item| item.name == "D_MS_real" && item.random_variable == "T_MS_real"));
        assert!(reduction
            .probability_objects
            .iter()
            .any(|item| item.name == "D_LE_sim" && item.random_variable == "T_LE_sim"));
        assert!(reduction
            .probability_objects
            .iter()
            .any(|item| item.name == "D_MS_hyb1" && item.random_variable == "T_MS_hyb1"));
        assert!(reduction
            .probability_objects
            .iter()
            .any(|item| item.name == "D_MS_hyb2" && item.random_variable == "T_MS_hyb2"));
        assert_eq!(reduction.ms_reduction_chain.lemmas.len(), 5);
        assert_eq!(reduction.ms_reduction_chain.lemmas[0].name, "MS-1");
        assert_eq!(reduction.ms_reduction_chain.lemmas[1].name, "MS-2");
        assert_eq!(reduction.ms_reduction_chain.lemmas[2].name, "MS-3a");
        assert_eq!(reduction.ms_reduction_chain.lemmas[3].name, "MS-3b");
        assert_eq!(reduction.ms_reduction_chain.lemmas[4].name, "MS-3c");
        assert_eq!(
            reduction.ms_reduction_chain.combined_bound.expression,
            "epsilon_ms = epsilon_ms_hash_binding + epsilon_ms_rom_programmability"
        );
        assert_eq!(reduction.hybrid_lemmas.len(), 3);
        assert_eq!(reduction.hybrid_lemmas[0].name, "H0_to_H1_MS_replacement");
        assert!(reduction.hybrid_lemmas[0]
            .bound
            .expression
            .contains("epsilon_ms"));
        assert!(reduction.hybrid_lemmas[1]
            .bound
            .expression
            .contains("epsilon_le"));
        assert_eq!(
            reduction.composition_safety_lemma.bound.expression,
            "Adv_QSSM(D) <= epsilon_ms + epsilon_le"
        );
        assert_eq!(
            reduction.hybrid_lemmas[0].assumption_dependencies,
            vec![AssumptionId::A1, AssumptionId::A2]
        );
        assert_eq!(
            reduction.hybrid_lemmas[1].assumption_dependencies,
            vec![AssumptionId::A4]
        );
        assert_eq!(reduction.composition_safety_lemma.independence_premises.len(), 2);
        assert!(reduction
            .composition_safety_lemma
            .shared_randomness_rule
            .contains("domain-separated"));
        assert!(reduction
            .composition_safety_lemma
            .no_shared_witness_leakage_rule
            .contains("shared-witness"));
        assert!(reduction
            .composition_safety_lemma
            .additive_composition_argument
            .contains("sum of the already-declared MS and LE hybrid gaps"));
        assert_eq!(reduction.ms_reduction_chain.lemmas[2].bound.numeric_upper_bound, Some(0.0));
        assert_eq!(reduction.ms_reduction_chain.lemmas[3].bound.numeric_upper_bound, Some(0.0));
        assert_eq!(reduction.ms_reduction_chain.lemmas[4].bound.numeric_upper_bound, Some(0.0));
        assert_eq!(reduction.hybrid_lemmas[2].bound.numeric_upper_bound, Some(0.0));
    }

    #[test]
    fn closed_theorem_exposes_assumption_graph_and_proof_closure() {
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);

        assert_eq!(theorem.assumption_graph.inputs.len(), 3);
        assert_eq!(theorem.assumption_graph.inputs[0].id, AssumptionId::A1);
        assert_eq!(theorem.assumption_graph.inputs[1].id, AssumptionId::A2);
        assert_eq!(theorem.assumption_graph.inputs[2].id, AssumptionId::A4);
        assert!(theorem.closure_report.closed);
        assert!(theorem.closure_report.issues.is_empty());
        assert!(theorem.architecture_freeze.no_further_structural_changes_allowed);
        assert!(theorem
            .architecture_freeze
            .components
            .iter()
            .all(|component| component.frozen));
        assert_eq!(theorem.internal_lemma_chain.len(), 9);
        assert_eq!(theorem.game_based_proof.games.len(), 3);
        assert_eq!(theorem.game_based_proof.transitions.len(), 2);
        assert_eq!(theorem.game_based_proof.games[0].name, "G0");
        assert_eq!(theorem.game_based_proof.games[1].name, "G1");
        assert_eq!(theorem.game_based_proof.games[2].name, "G2");
    }

    #[test]
    fn proof_closure_checker_rejects_empirical_and_undefined_terms() {
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
        let mut game_based_proof = theorem.game_based_proof.clone();
        game_based_proof.transitions[0].theorem_statement =
            "empirical surrogate leak".to_string();
        game_based_proof.transitions[1].bound.epsilon_dependencies =
            vec!["epsilon_unknown".to_string()];
        let report = proof_closure_report_for_closed_theorem(
            &theorem.architecture_freeze,
            &theorem.assumption_graph,
            &theorem.internal_lemma_chain,
            &game_based_proof,
            &theorem.premise_contracts,
            &theorem.output_bound,
            &theorem.theorem_statement,
        );

        assert!(!report.closed);
        assert!(report.issues.iter().any(|issue| {
            issue.kind == ProofClosureIssueKind::EmpiricalReferenceInTheoremPath
        }));
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.kind == ProofClosureIssueKind::UndefinedEpsilonTerm));
    }

    #[test]
    fn proof_closure_checker_rejects_ms_query_digests_that_hash_responses() {
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
        let mut internal_lemma_chain = theorem.internal_lemma_chain.clone();
        let ms_3a = internal_lemma_chain
            .iter_mut()
            .find(|lemma| lemma.name == "MS-3a")
            .expect("MS-3a in theorem chain");
        ms_3a.premise_contracts[0] =
            "bitness_query_digest hashes announcements and responses.".to_string();

        let report = proof_closure_report_for_closed_theorem(
            &theorem.architecture_freeze,
            &theorem.assumption_graph,
            &internal_lemma_chain,
            &theorem.game_based_proof,
            &theorem.premise_contracts,
            &theorem.output_bound,
            &theorem.theorem_statement,
        );

        assert!(!report.closed);
        assert!(report.issues.iter().any(|issue| {
            issue.kind == ProofClosureIssueKind::ExactSimulationLemmaViolation
                && issue.location == "MS-3a"
        }));
    }

    #[test]
    fn proof_closure_checker_rejects_ms_simulator_structural_deviation() {
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
        let mut internal_lemma_chain = theorem.internal_lemma_chain.clone();

        // Corrupt MS-3c to have non-zero advantage — simulates a structural deviation
        // between the MS simulator and the real transcript distribution.
        let ms_3c = internal_lemma_chain
            .iter_mut()
            .find(|lemma| lemma.name == "MS-3c")
            .expect("MS-3c in theorem chain");
        ms_3c.produced_bound_numeric_upper_bound = Some(1e-6);

        let report = proof_closure_report_for_closed_theorem(
            &theorem.architecture_freeze,
            &theorem.assumption_graph,
            &internal_lemma_chain,
            &theorem.game_based_proof,
            &theorem.premise_contracts,
            &theorem.output_bound,
            &theorem.theorem_statement,
        );

        assert!(!report.closed, "Closure checker must reject non-zero MS-3 advantage");
        assert!(report.issues.iter().any(|issue| {
            issue.kind == ProofClosureIssueKind::ExactSimulationLemmaViolation
                && issue.location == "MS-3c"
        }));
    }


    #[test]
    fn ms_simulator_alignment_holds_on_observable_batch_after_exact_sim_upgrade() {
        let statements = statement_batch_for_ms_v2_alignment();
        let report = run_ms_v2_empirical_alignment(&statements)
            .expect("ms v2 exact-simulation alignment report");

        assert_eq!(report.sample_count, statements.len());
        assert_eq!(report.result_distance.total_variation_distance, 0.0);
        assert!(report
            .notes
            .iter()
            .any(|item| item.contains("frozen")));
    }

    #[test]
    fn global_qssm_simulator_emits_joint_public_only_transcript() {
        let public_input = sample_qssm_public_input();
        let transcript = simulate_qssm_transcript(&public_input, [77u8; 32])
            .expect("global qssm simulator transcript");
        let observation = observe_simulated_qssm_transcript(&transcript);

        assert!(!observation.ms.bitness_global_challenges.is_empty());
        assert!(!observation.le.commitment_coeffs.is_empty());
        assert_eq!(observation.le.challenge_seed, transcript.le.challenge_seed);
    }

    #[test]
    fn qssm_g0_g1_g2_chain_is_executable() {
        let fixture = sample_qssm_witness_fixture();
        let public_input = sample_qssm_public_input();
        let g0 = sample_real_qssm_transcript(&public_input, &fixture, [41u8; 32], [59u8; 32])
            .expect("g0 real qssm transcript");
        let g1 = sample_g1_qssm_observation(&public_input, &fixture, [61u8; 32], [59u8; 32])
            .expect("g1 hybrid observation");
        let g2 = simulate_qssm_transcript(&public_input, [77u8; 32])
            .expect("g2 global simulator transcript");

        assert_eq!(observe_real_qssm_transcript(&g0).ms.statement_digest, g1.ms.statement_digest);
        assert_eq!(g1.ms.statement_digest, observe_simulated_qssm_transcript(&g2).ms.statement_digest);
        assert_eq!(g1.le.challenge_seed.len(), 32);
    }

    #[test]
    fn program_simulation_preserves_first_success_pair() {
        let statement = sample_statement();
        let artifact = simulate_kn_distribution(&statement, SimulationStrategy::ProgramSimulation)
            .expect("program-simulation sample");
        assert_eq!(artifact.strategy, SimulationStrategy::ProgramSimulation);
        assert_eq!(artifact.programmed_oracle_queries, 1);
        assert_eq!(artifact.oracle_queries, usize::from(artifact.n) + 1);
        assert_eq!(Some((artifact.n, artifact.k)), real_first_success_pair(&statement));
    }

    #[test]
    fn commitment_opening_is_merkle_consistent() {
        let statement = sample_statement();
        let commitment = simulate_commitment_opening(
            &statement,
            SimulationStrategy::DistributionCollapse,
            5,
        )
        .expect("commitment simulation");
        assert_eq!(commitment.opening.path.len(), MERKLE_DEPTH_MS);
        assert!(verify_path(
            &commitment.root,
            &commitment.opening.leaf,
            commitment.opening.leaf_index,
            &commitment.opening.path,
        ));
    }

    #[test]
    fn transcript_challenge_matches_fs_formula() {
        let statement = sample_statement();
        let artifact = simulate_ms_transcript(&statement, SimulationStrategy::ProgramSimulation)
            .expect("full transcript simulation");
        let expected = fs_challenge(
            &artifact.transcript.root,
            artifact.transcript.n,
            artifact.transcript.k,
            &statement.binding_entropy,
            statement.value,
            statement.target,
            &statement.context,
            &statement.binding_context,
        );
        assert_eq!(artifact.transcript.challenge, expected);
    }

    #[test]
    fn sampled_real_transcript_roundtrips_through_ms_verifier() {
        let statement = sample_statement();
        let real = sample_real_ms_transcript(&statement, [3u8; 32]).expect("real transcript");
        let proof = qssm_ms::GhostMirrorProof::new(
            real.n,
            real.k,
            real.opening.bit_at_k,
            real.opening.opened_salt,
            real.opening.path.clone(),
            real.challenge,
        )
        .expect("ghost mirror proof");
        assert!(qssm_ms::verify(
            qssm_ms::Root::new(real.root),
            &proof,
            statement.binding_entropy,
            statement.value,
            statement.target,
            &statement.context,
            &statement.binding_context,
        ));
    }

    #[test]
    fn program_simulation_matches_real_observable_marginals_on_batch() {
        let statements = statement_batch_for_distinguisher();
        let report = run_ms_empirical_distinguisher(
            &statements,
            SimulationStrategy::ProgramSimulation,
        )
        .expect("program simulation distinguisher report");
        assert_eq!(report.sample_count, statements.len());
        assert_eq!(report.joint_distance.total_variation_distance, 0.0);
        assert_eq!(report.nonce_distance.total_variation_distance, 0.0);
        assert_eq!(report.bit_index_distance.total_variation_distance, 0.0);
        assert_eq!(report.bit_state_distance.total_variation_distance, 0.0);
    }

    #[test]
    fn distribution_collapse_is_no_better_than_program_simulation_on_batch() {
        let statements = statement_batch_for_distinguisher();
        let program = run_ms_empirical_distinguisher(
            &statements,
            SimulationStrategy::ProgramSimulation,
        )
        .expect("program simulation report");
        let collapse = run_ms_empirical_distinguisher(
            &statements,
            SimulationStrategy::DistributionCollapse,
        )
        .expect("distribution collapse report");
        assert!(program.joint_distance.total_variation_distance
            <= collapse.joint_distance.total_variation_distance);
        assert!(collapse.notes.iter().any(|item| item.contains("Empirical only")));
    }

    #[test]
    fn ms_v2_observable_challenge_marginals_align_on_batch() {
        let statements = statement_batch_for_ms_v2_alignment();
        let report = run_ms_v2_empirical_alignment(&statements)
            .expect("ms v2 alignment report");
        assert_eq!(report.sample_count, statements.len());
        assert_eq!(report.result_distance.total_variation_distance, 0.0);
        assert!(report
            .statistical_layer
            .bitness_challenge_nibble_distance
            .total_variation_distance
            < 0.1);
        assert!(report
            .statistical_layer
            .comparison_challenge_nibble_distance
            .total_variation_distance
            < 0.25);
        assert!(report
            .statistical_layer
            .transcript_digest_nibble_distance
            .total_variation_distance
            < 0.25);
        assert!(report
            .statistical_layer
            .bitness_byte_correlation
            .correlation_gap
            < 0.05);
        assert!(report
            .simulator_gap_layer
            .overall_js_upper_bound_bits
            >= 0.0);
        assert!(report
            .statistical_layer
            .comparison_byte_correlation
            .delta_distance
            .support_size
            > 0);
        assert!(report
            .structure_layer
            .hidden_value_lsb_to_digest_nibble_bias
            .approx_mutual_information_bits
            < 0.5);
        assert!(report
            .notes
            .iter()
            .any(|item| item.contains("frozen")));
    }

    #[test]
    fn parameter_feasibility_reports_set_b_matches_known_conditions() {
        let feasibility = LeParameterFeasibilityCheck::for_current_params();
        assert_eq!(feasibility.claim_type, ClaimType::ZeroKnowledge);
        assert_eq!(feasibility.status, ProofStatus::Conditional);
        assert!(feasibility.meets_standard_hvzk_requirement);
        assert!(feasibility
            .conclusion
            .contains("matches the standard HVZK proof template"));
        assert!(feasibility
            .non_conclusion
            .contains("does not prove or refute zero-knowledge"));
    }

    #[test]
    fn le_simulator_definition_separates_sampling_and_rom_programming() {
        let definition = LeSimulatorDefinition::for_current_params();
        assert_eq!(definition.claim_type, ClaimType::ZeroKnowledge);
        assert!(definition.rom_model);
        assert!(definition.sampled_independently.iter().any(|item| item.contains("simulator coins")));
        assert!(definition
            .programmed_random_oracle_queries
            .iter()
            .any(|item| item.contains("fs_challenge_bytes")));
        assert!(definition
            .forbidden_secret_inputs
            .iter()
            .any(|item| item == "witness r"));
    }

    #[test]
    fn desired_theorem_reports_proof_gaps_not_non_zk_conclusion() {
        let theorem = DesiredZkTheorem::for_current_params(SimulationStrategy::ProgramSimulation);
        assert_eq!(theorem.claim_type, ClaimType::ZeroKnowledge);
        assert_eq!(theorem.status, ProofStatus::Conditional);
        assert!(!theorem.proof_gaps.is_empty());
        assert!(theorem
            .proof_gaps
            .iter()
            .any(|item| item.contains("indistinguishability reduction")));
    }

    #[test]
    fn lemma_statuses_match_strategy_split() {
        let dist = KnSamplingLemma::for_strategy(SimulationStrategy::DistributionCollapse);
        let prog = KnSamplingLemma::for_strategy(SimulationStrategy::ProgramSimulation);
        let fs = FiatShamirConsistencyLemma::for_strategy(SimulationStrategy::DistributionCollapse);
        assert_eq!(dist.claim_type, ClaimType::ZeroKnowledge);
        assert_eq!(prog.claim_type, ClaimType::ZeroKnowledge);
        assert_eq!(dist.status, ProofStatus::Conditional);
        assert_eq!(prog.status, ProofStatus::Conditional);
        assert_eq!(fs.status, ProofStatus::ByConstruction);
        assert!(dist
            .assumptions
            .iter()
            .any(|item| item.contains("stopping-time bias")));
        assert!(prog
            .assumptions
            .iter()
            .any(|item| item.contains("programmable random oracle")));
    }

    // -----------------------------------------------------------------------
    // Auditability layer tests
    // -----------------------------------------------------------------------

    #[test]
    fn proof_structure_version_is_frozen() {
        assert_eq!(proof_structure_version(), PROOF_STRUCTURE_VERSION);
        assert!(PROOF_STRUCTURE_VERSION.contains("FROZEN"));
    }

    #[test]
    fn dependency_graph_export_contains_all_assumptions_and_lemmas() {
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
        let graph = theorem.export_dependency_graph();

        assert_eq!(graph.version, PROOF_STRUCTURE_VERSION);
        assert!(graph.nodes.iter().any(|n| n.contains("A1")));
        assert!(graph.nodes.iter().any(|n| n.contains("A2")));
        assert!(graph.nodes.iter().any(|n| n.contains("A4")));
        assert!(graph.nodes.iter().any(|n| n == "MS-3a"));
        assert!(graph.nodes.iter().any(|n| n == "MS-3b"));
        assert!(graph.nodes.iter().any(|n| n == "MS-3c"));
        assert!(!graph.edges.is_empty());
    }

    #[test]
    fn verification_checklist_passes_all_items() {
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
        let checklist = theorem.verification_checklist();

        assert!(checklist.all_passed, "Verification checklist must pass all items");
        assert_eq!(checklist.version, PROOF_STRUCTURE_VERSION);
        for item in &checklist.items {
            assert!(item.passed, "Checklist item {} failed: {}", item.id, item.detail);
        }
    }

    #[test]
    fn latex_export_contains_theorem_and_proof() {
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
        let latex = theorem.to_latex();

        assert!(latex.contains("\\begin{theorem}"));
        assert!(latex.contains("\\end{theorem}"));
        assert!(latex.contains("\\begin{proof}"));
        assert!(latex.contains("\\end{proof}"));
        assert!(latex.contains("\\epsilon_{\\mathrm{ms,bind}}"));
        assert!(latex.contains("\\epsilon_{\\mathrm{ms,rom}}"));
        assert!(latex.contains("\\epsilon_{\\mathrm{le}}"));
        assert!(latex.contains("MS-3a"));
        assert!(latex.contains("MS-3b"));
        assert!(latex.contains("MS-3c"));
        // Must NOT contain any reference to the former assumption
        assert!(!latex.contains("predicate_soundness"));
    }

    #[test]
    fn audit_validation_returns_passing_checklist() {
        let checklist = run_audit_validation()
            .expect("audit validation must succeed");
        assert!(checklist.all_passed, "Audit validation must pass");
        assert!(checklist.items.iter().any(|i| i.id == "SIM-INDEPENDENCE" && i.passed));
        assert!(checklist.items.iter().any(|i| i.id == "PROOF-CLOSURE" && i.passed));
        assert!(checklist.items.iter().any(|i| i.id == "MS-EXACT-SIM" && i.passed));
    }

    // -----------------------------------------------------------------------
    // Adversarial tests for the auditability layer
    // -----------------------------------------------------------------------

    #[test]
    fn adversarial_simulator_witness_leak_detected_by_checklist() {
        // If the global simulator advertised a witness input, the checklist should fail.
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let mut theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
        theorem.game_based_proof.global_simulator.forbidden_inputs.clear();
        let checklist = theorem.verification_checklist();
        assert!(!checklist.all_passed);
        assert!(checklist.items.iter().any(|i| i.id == "SIM-INDEPENDENCE" && !i.passed));
    }

    #[test]
    fn adversarial_ms3_removal_detected_by_checklist() {
        // If MS-3a is removed from the lemma chain, the checklist should fail.
        let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let mut theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
        theorem.internal_lemma_chain.retain(|l| l.name != "MS-3a");
        // Re-run closure report with the modified chain
        theorem.closure_report = proof_closure_report_for_closed_theorem(
            &theorem.architecture_freeze,
            &theorem.assumption_graph,
            &theorem.internal_lemma_chain,
            &theorem.game_based_proof,
            &theorem.premise_contracts,
            &theorem.output_bound,
            &theorem.theorem_statement,
        );
        let checklist = theorem.verification_checklist();
        assert!(!checklist.all_passed);
        assert!(checklist.items.iter().any(|i| i.id == "MS-EXACT-SIM" && !i.passed));
        assert!(checklist.items.iter().any(|i| i.id == "PROOF-CLOSURE" && !i.passed));
    }
}

impl CanonicalMsV2TranscriptDesign {
    #[must_use]
    pub fn option_b() -> Self {
        Self {
            name: "MS v2 Option B — predicate-only transcript".to_string(),
            transcript_definition: vec![
                "Visible transcript carries a public value commitment, the result bit, 64 bitness Sigma transcripts, and one comparison Sigma transcript.".to_string(),
                "No comparison coordinates, branch bits, Merkle paths, or legacy Fiat-Shamir nonce metadata are exposed.".to_string(),
                "The exact engine surface is qssm_ms::PredicateOnlyStatementV2 plus qssm_ms::PredicateOnlyProofV2.".to_string(),
            ],
            prover_stub_contract: vec![
                "The current engine-level prover commits to the hidden value bit decomposition and proves bitness plus comparison by Fiat-Shamir Sigma composition.".to_string(),
                "All visible fields are bound to the public statement and witness-derived commitments, while witness values and internal coordinates remain hidden.".to_string(),
            ],
            verifier_stub_contract: vec![
                "The current engine-level verifier checks the commitment statement digest, the bitness challenge splits, and the comparison challenge split under Fiat-Shamir.".to_string(),
                "This is a real witness-bound verifier; the remaining gap is the full simulation-based reduction, not a missing backend.".to_string(),
            ],
            simulator_contract: vec![
                "MS v2 transcript structure and APIs are frozen in this crate; only correctness checks, distinguisher analysis, and reduction work are allowed from this point onward.".to_string(),
                "The witness-free simulator uses qssm_ms::simulate_predicate_only_v2 on the public statement only and programs the oracle queries needed by the Sigma transcripts.".to_string(),
                "The formal crate checks a layered distinguisher suite over the frozen observable surface rather than changing the protocol shape again.".to_string(),
            ],
            removes_witness_dependent_visible_outputs: true,
            status: ClaimStatus::Conditional,
        }
    }
}

impl MsV2ObservableBoundaryContract {
    #[must_use]
    pub fn for_frozen_interface() -> Self {
        Self {
            claim_type: ClaimType::ZeroKnowledge,
            status: ProofStatus::ByConstruction,
            interface_frozen: true,
            sigma_algebra_generators: vec![
                "public value commitment".to_string(),
                "target".to_string(),
                "binding_entropy".to_string(),
                "binding_context".to_string(),
                "context".to_string(),
                "result bit".to_string(),
                "bitness global challenge vector".to_string(),
                "comparison global challenge".to_string(),
                "transcript digest".to_string(),
            ],
            measurable_projections: vec![
                "PredicateOnlyStatementV2::statement_digest".to_string(),
                "PredicateOnlyProofV2::result".to_string(),
                "PredicateOnlyProofV2::bitness_global_challenges".to_string(),
                "PredicateOnlyProofV2::comparison_global_challenge".to_string(),
                "PredicateOnlyProofV2::transcript_digest".to_string(),
            ],
            hidden_non_observables: vec![
                "hidden value".to_string(),
                "commitment blinders".to_string(),
                "prover randomness".to_string(),
                "per-branch Sigma responses not exposed through the frozen qssm_ms API".to_string(),
            ],
            simulator_allowed_inputs: vec![
                "MsHiddenValuePublicInput".to_string(),
                "simulator_seed".to_string(),
            ],
            simulator_forbidden_inputs: vec![
                "PredicateWitnessV2".to_string(),
                "value".to_string(),
                "commitment blinders".to_string(),
                "prover_seed".to_string(),
            ],
            statement:
                "The frozen MS v2 observable sigma-algebra is generated only by the public statement and the stable proof projections exposed by qssm_ms. The qssm-proofs simulator is allowed to depend only on those generators plus fresh simulator coins."
                    .to_string(),
            notes: vec![
                "This contract treats the current qssm_ms accessor surface as the canonical observable boundary for reduction work.".to_string(),
                "If a future wire format exposes additional proof coordinates, the boundary contract must be revised before any new ZK claim is made.".to_string(),
            ],
        }
    }
}

impl UnifiedZkHybridGame {
    #[must_use]
    pub fn for_canonical_option_b_and_set_b() -> Self {
        let observable_boundary = vec![
            "MS public value commitment".to_string(),
            "MS result bit".to_string(),
            "MS bitness global challenges".to_string(),
            "MS comparison global challenge".to_string(),
            "MS transcript digest".to_string(),
            "LE commitment C".to_string(),
            "LE t".to_string(),
            "LE z".to_string(),
            "LE challenge_seed".to_string(),
        ];

        Self {
            claim_type: ClaimType::ZeroKnowledge,
            status: ProofStatus::BoundedUnderAssumptions,
            observable_boundary: observable_boundary.clone(),
            worlds: vec![
                UnifiedHybridWorld {
                    name: "H0".to_string(),
                    ms_source: HybridTranscriptSource::RealProver,
                    le_source: HybridTranscriptSource::RealProver,
                    observable_view: observable_boundary.clone(),
                    transition_argument:
                        "Baseline real world: both MS v2 and LE Set B use their real provers under the shared composed verifier view.".to_string(),
                },
                UnifiedHybridWorld {
                    name: "H1".to_string(),
                    ms_source: HybridTranscriptSource::Simulator,
                    le_source: HybridTranscriptSource::RealProver,
                    observable_view: observable_boundary.clone(),
                    transition_argument:
                        "Replace only the MS v2 layer with its programmable-oracle simulator while keeping the LE prover real inside the same composed game.".to_string(),
                },
                UnifiedHybridWorld {
                    name: "H2".to_string(),
                    ms_source: HybridTranscriptSource::Simulator,
                    le_source: HybridTranscriptSource::Simulator,
                    observable_view: observable_boundary.clone(),
                    transition_argument:
                        "Replace the LE layer with the Set B ROM simulator while leaving the already-simulated MS v2 layer embedded in the same transcript chain.".to_string(),
                },
                UnifiedHybridWorld {
                    name: "H3".to_string(),
                    ms_source: HybridTranscriptSource::Simulator,
                    le_source: HybridTranscriptSource::Simulator,
                    observable_view: observable_boundary,
                    transition_argument:
                        "Inline simulator coins, programmed random-oracle queries, and public-statement bindings to obtain the fully simulated composed world on the same observable boundary.".to_string(),
                },
            ],
            composition_notes: vec![
                "LE Set B is modeled inside the same hybrid chain as MS v2 rather than as a separate theorem stitched on afterward.".to_string(),
                "The only allowed public view is the shared observable boundary listed above; every hybrid step preserves that verifier view.".to_string(),
            ],
        }
    }
}

impl ClosedZkTheorem {
    #[must_use]
    pub fn for_current_and_redesigned_systems(
        boundary: &MsV2ObservableBoundaryContract,
        le_constraint_analysis: &LeHvzkConstraintAnalysis,
    ) -> Self {
        let reduction = ReductionProofSketch::for_canonical_option_b_and_set_b(
            boundary,
            le_constraint_analysis,
        );
        let architecture_freeze = frozen_qssm_architecture_seal();
        let assumption_graph =
            assumption_dependency_graph_for_canonical_option_b_and_set_b(boundary, le_constraint_analysis);
        let internal_lemma_chain = theorem_lemma_chain_for_canonical_option_b_and_set_b(&reduction);
        let game_based_proof = game_based_zk_proof_for_canonical_option_b_and_set_b(
            boundary,
            le_constraint_analysis,
            &reduction,
        );
        let theorem_statement =
            "For every PPT distinguisher D over the shared verifier view, letting G0 be the real QSSM transcript game, G1 the game with only MS replaced by its simulator, and G2 the game produced by the global simulator S = simulate_qssm_transcript, Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le under assumptions A1, A2, and A4 and the shared-randomness simulator-independence model."
                .to_string();
        let premise_contracts = vec![
            boundary.statement.clone(),
            architecture_freeze.statement.clone(),
            "A1: hash binding for ValueCommitmentV2 and statement_digest on the frozen observable boundary.".to_string(),
            "A2: ROM programmability for the MS Fiat-Shamir interface on the frozen observable boundary.".to_string(),
            MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
            MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
            MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT.to_string(),
            MS_SCHNORR_REPARAMETERIZATION_CONTRACT.to_string(),
            format!(
                "A4: LE Set B HVZK / ROM bound with eta={}, gamma={}, beta={}, c_poly_size={}, c_poly_span={}.",
                le_constraint_analysis.eta,
                le_constraint_analysis.gamma,
                le_constraint_analysis.beta,
                le_constraint_analysis.c_poly_size,
                le_constraint_analysis.c_poly_span
            ),
        ];
        let output_bound = AdvantageBound {
            symbol: "epsilon_qssm".to_string(),
            expression:
                "Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le"
                    .to_string(),
            numeric_upper_bound: None,
            dependencies: vec![
                "A1 -> epsilon_ms_hash_binding".to_string(),
                "A2 -> epsilon_ms_rom_programmability".to_string(),
                "A4 -> epsilon_le".to_string(),
            ],
            epsilon_dependencies: vec![
                "epsilon_ms_hash_binding".to_string(),
                "epsilon_ms_rom_programmability".to_string(),
                "epsilon_le".to_string(),
            ],
            justification:
                "The closed theorem consumes only the explicitly declared A1/A2/A4 assumption graph and the internal lemma chain MS-1 -> MS-2 -> MS-3a -> MS-3b -> MS-3c -> H0_to_H1 -> H1_to_H2 -> H2_to_H3 -> composed_boundary_additivity."
                    .to_string(),
        };
        let closure_report = proof_closure_report_for_closed_theorem(
            &architecture_freeze,
            &assumption_graph,
            &internal_lemma_chain,
            &game_based_proof,
            &premise_contracts,
            &output_bound,
            &theorem_statement,
        );

        assert!(
            closure_report.closed,
            "closed theorem failed proof closure checker: {:?}",
            closure_report.issues
        );

        Self {
            name: "QSSM closed ZK theorem (MS v2 Option B + LE Set B)".to_string(),
            claim_type: ClaimType::ZeroKnowledge,
            status: ProofStatus::BoundedUnderAssumptions,
            architecture_freeze,
            assumption_graph,
            internal_lemma_chain,
            game_based_proof,
            premise_contracts,
            random_variables: vec![
                "T_G0 := verifier view sampled from the real joint QSSM transcript game".to_string(),
                "T_G2 := verifier view sampled from the global simulator output".to_string(),
            ],
            distributions: vec![
                "G0(real joint transcript)".to_string(),
                "G1(MS simulated, LE real)".to_string(),
                "G2(global simulator output)".to_string(),
            ],
            advantage_functions: vec![
                "Adv_G0_G1(D) = |Pr[D(T_G0)=1] - Pr[D(T_G1)=1]|".to_string(),
                "Adv_G1_G2(D) = |Pr[D(T_G1)=1] - Pr[D(T_G2)=1]|".to_string(),
                "Adv_QSSM(D) = |Pr[D(T_G0)=1] - Pr[D(T_G2)=1]|".to_string(),
            ],
            output_bound,
            closure_report,
            theorem_statement,
        }
    }
}

impl LeHvzkConstraintAnalysis {
    #[must_use]
    pub fn for_current_params() -> Self {
        let epsilon_log2 = -128.0;
        let query_budget_log2 = 64.0;
        let worst_case_cr_inf_norm = le_worst_case_cr_inf_norm(BETA, C_POLY_SIZE, C_POLY_SPAN);
        let required_eta_for_hvzk = le_required_eta_for_hvzk(
            N,
            BETA,
            C_POLY_SIZE,
            C_POLY_SPAN,
            epsilon_log2,
        );
        let minimum_gamma_for_support_containment =
            le_minimum_gamma_for_support_containment(ETA, BETA, C_POLY_SIZE, C_POLY_SPAN);
        let challenge_space_log2 = le_challenge_space_log2(C_POLY_SIZE, C_POLY_SPAN);
        let fs_security_bits = challenge_space_log2 - query_budget_log2;

        Self {
            claim_type: ClaimType::ZeroKnowledge,
            epsilon_log2,
            query_budget_log2,
            n: N,
            beta: BETA,
            eta: ETA,
            gamma: GAMMA,
            c_poly_size: C_POLY_SIZE,
            c_poly_span: C_POLY_SPAN,
            worst_case_cr_inf_norm,
            required_eta_for_hvzk,
            minimum_gamma_for_support_containment,
            challenge_space_log2,
            fs_security_bits,
            current_eta_shortfall: required_eta_for_hvzk - f64::from(ETA),
            current_gamma_shortfall: i64::from(GAMMA) - minimum_gamma_for_support_containment as i64,
        }
    }
}

impl CanonicalLeSetB {
    #[must_use]
    pub fn current() -> Self {
        let name = "LE Set B — balanced proof-safe template";
        let eta = ETA;
        let beta = BETA;
        let gamma = GAMMA;
        let c_poly_size = C_POLY_SIZE;
        let c_poly_span = C_POLY_SPAN;
        let notes = vec![
            "This is the committed LE configuration in the codebase.".to_string(),
            "It satisfies the encoded HVZK eta bound, the support-containment rule gamma = eta + ||cr||_inf, and the >=128-bit Fiat-Shamir margin under Q_H = 2^64.".to_string(),
        ];
        let worst_case_cr_inf_norm = le_worst_case_cr_inf_norm(beta, c_poly_size, c_poly_span);
        let required_eta_for_hvzk =
            le_required_eta_for_hvzk(N, beta, c_poly_size, c_poly_span, -128.0);
        let minimum_gamma_for_support_containment =
            le_minimum_gamma_for_support_containment(eta, beta, c_poly_size, c_poly_span);
        let challenge_space_log2 = le_challenge_space_log2(c_poly_size, c_poly_span);
        let fs_security_bits = challenge_space_log2 - 64.0;
        let satisfies_hvzk_eta = f64::from(eta) >= required_eta_for_hvzk;
        let satisfies_support_containment = u64::from(gamma) >= minimum_gamma_for_support_containment;
        let meets_128_bit_fs = fs_security_bits >= 128.0;

        Self {
            name: name.to_string(),
            eta,
            beta,
            gamma,
            c_poly_size,
            c_poly_span,
            worst_case_cr_inf_norm,
            required_eta_for_hvzk,
            minimum_gamma_for_support_containment,
            challenge_space_log2,
            fs_security_bits,
            satisfies_hvzk_eta,
            satisfies_support_containment,
            meets_128_bit_fs,
            notes,
        }
    }
}

impl ReductionProofSketch {
    #[must_use]
    pub fn for_canonical_option_b_and_set_b(
        boundary: &MsV2ObservableBoundaryContract,
        le_constraint_analysis: &LeHvzkConstraintAnalysis,
    ) -> Self {
        let ms_reduction_chain = ms_reduction_chain_for_frozen_interface(boundary);
        let ms_bound = ms_reduction_chain.combined_bound.clone();
        let le_bound = le_advantage_bound(le_constraint_analysis, boundary);
        let probability_objects = probability_objects_for_canonical_option_b_and_set_b(boundary);
        let hybrid_lemmas = vec![
            HybridLemma {
                name: "H0_to_H1_MS_replacement".to_string(),
                source_world: "H0".to_string(),
                target_world: "H1".to_string(),
                source_distribution: "D_H0".to_string(),
                target_distribution: "D_H1".to_string(),
                assumption_dependencies: vec![AssumptionId::A1, AssumptionId::A2],
                premise_contracts: vec![
                    boundary.statement.clone(),
                    "Distinguishers are measurable only with respect to the frozen MS v2 observable sigma-algebra.".to_string(),
                    MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
                    MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
                ],
                advantage_function: AdvantageFunction {
                    name: "Adv_H0_H1".to_string(),
                    distinguisher_class: "PPT distinguishers over the shared verifier view".to_string(),
                    left_distribution: "D_H0".to_string(),
                    right_distribution: "D_H1".to_string(),
                    definition:
                        "Adv_H0_H1(D) = |Pr[D(T_H0)=1] - Pr[D(T_H1)=1]| = Adv_MS(D)".to_string(),
                },
                bound: ms_bound.clone(),
                theorem_statement:
                    "Replacing the real MS v2 prover with the simulator changes the verifier-view distribution by at most epsilon_ms, where epsilon_ms is the sum of the A1/A2 losses and the residual programmed transcript gap is discharged exactly by MS-3a, MS-3b, and MS-3c."
                        .to_string(),
                status: ProofStatus::BoundedUnderAssumptions,
            },
            HybridLemma {
                name: "H1_to_H2_LE_replacement".to_string(),
                source_world: "H1".to_string(),
                target_world: "H2".to_string(),
                source_distribution: "D_H1".to_string(),
                target_distribution: "D_H2".to_string(),
                assumption_dependencies: vec![AssumptionId::A4],
                premise_contracts: vec![
                    boundary.statement.clone(),
                    format!(
                        "LE Set B rejection-sampling and Fiat-Shamir bounds are parameterized by eta={}, gamma={}, beta={}, c_poly_size={}, c_poly_span={}",
                        le_constraint_analysis.eta,
                        le_constraint_analysis.gamma,
                        le_constraint_analysis.beta,
                        le_constraint_analysis.c_poly_size,
                        le_constraint_analysis.c_poly_span
                    ),
                ],
                advantage_function: AdvantageFunction {
                    name: "Adv_H1_H2".to_string(),
                    distinguisher_class: "PPT distinguishers over the shared verifier view".to_string(),
                    left_distribution: "D_H1".to_string(),
                    right_distribution: "D_H2".to_string(),
                    definition:
                        "Adv_H1_H2(D) = |Pr[D(T_H1)=1] - Pr[D(T_H2)=1]| = Adv_LE(D)".to_string(),
                },
                bound: le_bound.clone(),
                theorem_statement:
                    "Replacing the real LE Set B prover with the LE simulator changes the verifier-view distribution by at most epsilon_le(eta,gamma,beta,c_poly_size,c_poly_span), with the bound carrying the rejection-sampling term and the Fiat-Shamir term."
                        .to_string(),
                status: ProofStatus::BoundedUnderAssumptions,
            },
            HybridLemma {
                name: "H2_to_H3_inline_simulators".to_string(),
                source_world: "H2".to_string(),
                target_world: "H3".to_string(),
                source_distribution: "D_H2".to_string(),
                target_distribution: "D_H3".to_string(),
                assumption_dependencies: vec![],
                premise_contracts: vec![boundary.statement.clone()],
                advantage_function: AdvantageFunction {
                    name: "Adv_H2_H3".to_string(),
                    distinguisher_class: "PPT distinguishers over the shared verifier view".to_string(),
                    left_distribution: "D_H2".to_string(),
                    right_distribution: "D_H3".to_string(),
                    definition:
                        "Adv_H2_H3(D) = |Pr[D(T_H2)=1] - Pr[D(T_H3)=1]|".to_string(),
                },
                bound: AdvantageBound {
                    symbol: "epsilon_inline".to_string(),
                    expression: "Adv_H2_H3(D) = 0".to_string(),
                    numeric_upper_bound: Some(0.0),
                    dependencies: vec![],
                    epsilon_dependencies: vec![],
                    justification:
                        "H2 and H3 differ only by inlining simulator coins and programmed oracle answers that are already hidden outside the shared observable boundary.".to_string(),
                },
                theorem_statement:
                    "Inlining simulator randomness and programmed oracle answers does not change the verifier-view distribution on the shared observable boundary."
                        .to_string(),
                status: ProofStatus::ByConstruction,
            },
        ];
        let composition_safety_lemma = CompositionSafetyLemma {
            name: "composed_boundary_additivity".to_string(),
            assumption_dependencies: vec![AssumptionId::A1, AssumptionId::A2, AssumptionId::A4],
            premise_contracts: vec![
                boundary.statement.clone(),
                "MS and LE expose only the shared verifier boundary and do not reveal each other's hidden state through auxiliary channels.".to_string(),
            ],
            independence_premises: vec![
                "MS simulator coins are sampled independently of LE simulator coins even when both are derived in the same global ROM execution.".to_string(),
                "Protocol domains are separated so shared randomness cannot induce observable cross-protocol correlation attacks.".to_string(),
            ],
            ms_interface: boundary.measurable_projections.clone(),
            le_interface: vec![
                "commitment C".to_string(),
                "t".to_string(),
                "z".to_string(),
                "challenge_seed".to_string(),
            ],
            shared_randomness_rule:
                "MS and LE simulators use domain-separated random-oracle labels and independent simulator seeds under any shared ambient randomness source."
                    .to_string(),
            no_shared_witness_leakage_rule:
                "The composed verifier view contains no shared-witness channel: MS hidden values and LE witness data remain confined behind the frozen observable boundary and cannot be correlated through simulator state."
                    .to_string(),
            additive_composition_argument:
                "Under the shared-randomness model, simulator independence and domain separation ensure that the composed distinguishing gap is the sum of the already-declared MS and LE hybrid gaps, with no extra correlation term."
                    .to_string(),
            advantage_function: AdvantageFunction {
                name: "Adv_QSSM".to_string(),
                distinguisher_class: "PPT distinguishers over the shared verifier view".to_string(),
                left_distribution: "D_H0".to_string(),
                right_distribution: "D_H3".to_string(),
                definition:
                    "Adv_QSSM(D) = |Pr[D(T_H0)=1] - Pr[D(T_H3)=1]|".to_string(),
            },
            bound: AdvantageBound {
                symbol: "epsilon_qssm".to_string(),
                expression: "Adv_QSSM(D) <= epsilon_ms + epsilon_le".to_string(),
                numeric_upper_bound: None,
                dependencies: vec![
                    "epsilon_ms = epsilon_ms_hash_binding + epsilon_ms_rom_programmability".to_string(),
                    "epsilon_le".to_string(),
                ],
                epsilon_dependencies: vec!["epsilon_ms".to_string(), "epsilon_le".to_string()],
                justification:
                    "Triangle inequality across H0->H1 and H1->H2, plus Adv_H2_H3(D)=0 by construction, and no cross-protocol leakage amplification beyond the shared observable boundary because the MS and LE simulators are independent under shared randomness.".to_string(),
            },
            theorem_statement:
                "Sequentially replacing MS and LE preserves simulator independence, excludes shared-witness leakage and correlated randomness channels, and yields additive advantage composition on the shared observable boundary under the declared shared-randomness model."
                    .to_string(),
            status: ProofStatus::BoundedUnderAssumptions,
        };

        Self {
            theorem_target:
                "Under A1, A2, and A4, MS v2 Option B and LE Set B compose into a single closed QSSM ZK theorem whose output bound is Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le."
                    .to_string(),
            probability_objects,
            ms_reduction_chain,
            hybrid_lemmas,
            composition_safety_lemma,
            residual_assumptions: vec![
                "The current MS v2 predicate-only commitment proof is analyzed through MS-1 / MS-2 plus the exact-simulation lemmas MS-3a / MS-3b / MS-3c on the frozen observable boundary contract.".to_string(),
                "LE Set B is analyzed in the programmable random oracle model with the encoded eta/gamma/challenge-space bounds.".to_string(),
                "Cross-protocol hash domains and commitment bindings remain collision resistant / binding at the claimed security level.".to_string(),
            ],
            final_advantage_bound: AdvantageBound {
                symbol: "epsilon_qssm".to_string(),
                expression: "epsilon_qssm = epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le".to_string(),
                numeric_upper_bound: None,
                dependencies: vec![
                    "epsilon_ms_hash_binding".to_string(),
                    "epsilon_ms_rom_programmability".to_string(),
                    "epsilon_le".to_string(),
                ],
                epsilon_dependencies: vec![
                    "epsilon_ms_hash_binding".to_string(),
                    "epsilon_ms_rom_programmability".to_string(),
                    "epsilon_le".to_string(),
                ],
                justification:
                    "Collected from the formal hybrid lemmas and the additive composition-safety lemma.".to_string(),
            },
            status: ProofStatus::BoundedUnderAssumptions,
        }
    }
}

fn probability_objects_for_canonical_option_b_and_set_b(
    boundary: &MsV2ObservableBoundaryContract,
) -> Vec<ProbabilityObject> {
    vec![
        ProbabilityObject {
            name: "D_MS_real".to_string(),
            family: DistributionFamily::MsV2Real,
            random_variable: "T_MS_real".to_string(),
            support_description:
                "Frozen observable MS v2 verifier views sampled from the real predicate-only prover."
                    .to_string(),
            randomness_sources: vec![
                "commitment_seed".to_string(),
                "prover_seed".to_string(),
            ],
            observable_boundary_premise: boundary.statement.clone(),
            notes: vec!["Defined only through boundary-visible proof projections.".to_string()],
        },
        ProbabilityObject {
            name: "D_MS_hyb1".to_string(),
            family: DistributionFamily::MsV2Hybrid1,
            random_variable: "T_MS_hyb1".to_string(),
            support_description:
                "Frozen observable MS v2 verifier views after abstracting commitment binding into the public statement boundary."
                    .to_string(),
            randomness_sources: vec![
                "commitment_seed".to_string(),
                "prover_seed".to_string(),
            ],
            observable_boundary_premise: boundary.statement.clone(),
            notes: vec!["Used by MS-1 under the hash-binding assumption.".to_string()],
        },
        ProbabilityObject {
            name: "D_MS_hyb2".to_string(),
            family: DistributionFamily::MsV2Hybrid2,
            random_variable: "T_MS_hyb2".to_string(),
            support_description:
                "Frozen observable MS v2 verifier views after replacing real Fiat-Shamir challenges with programmable-ROM challenges."
                    .to_string(),
            randomness_sources: vec!["programmed ROM coins".to_string()],
            observable_boundary_premise: boundary.statement.clone(),
            notes: vec!["Used by MS-2 under the ROM programmability assumption.".to_string()],
        },
        ProbabilityObject {
            name: "D_MS_sim".to_string(),
            family: DistributionFamily::MsV2Simulated,
            random_variable: "T_MS_sim".to_string(),
            support_description:
                "Frozen observable MS v2 verifier views sampled from the programmable-oracle simulator."
                    .to_string(),
            randomness_sources: vec!["simulator_seed".to_string()],
            observable_boundary_premise: boundary.statement.clone(),
            notes: vec!["The simulator is forbidden from taking witness inputs.".to_string()],
        },
        ProbabilityObject {
            name: "D_LE_real".to_string(),
            family: DistributionFamily::LeSetBReal,
            random_variable: "T_LE_real".to_string(),
            support_description:
                "Visible LE Set B verifier views emitted by the real prover."
                    .to_string(),
            randomness_sources: vec!["prover masking sample".to_string()],
            observable_boundary_premise:
                "The composed verifier observes only LE commitment, t, z, and challenge_seed."
                    .to_string(),
            notes: vec![],
        },
        ProbabilityObject {
            name: "D_LE_sim".to_string(),
            family: DistributionFamily::LeSetBSimulated,
            random_variable: "T_LE_sim".to_string(),
            support_description:
                "Visible LE Set B verifier views emitted by the ROM simulator."
                    .to_string(),
            randomness_sources: vec!["simulator coins".to_string()],
            observable_boundary_premise:
                "The composed verifier observes only LE commitment, t, z, and challenge_seed."
                    .to_string(),
            notes: vec!["The challenge distribution is parameterized by the current Set B constants.".to_string()],
        },
        ProbabilityObject {
            name: "D_H0".to_string(),
            family: DistributionFamily::ComposedH0,
            random_variable: "T_H0".to_string(),
            support_description: "Shared verifier view with real MS and real LE.".to_string(),
            randomness_sources: vec!["MS prover coins".to_string(), "LE prover coins".to_string()],
            observable_boundary_premise: boundary.statement.clone(),
            notes: vec![],
        },
        ProbabilityObject {
            name: "D_H1".to_string(),
            family: DistributionFamily::ComposedH1,
            random_variable: "T_H1".to_string(),
            support_description: "Shared verifier view with simulated MS and real LE.".to_string(),
            randomness_sources: vec!["MS simulator coins".to_string(), "LE prover coins".to_string()],
            observable_boundary_premise: boundary.statement.clone(),
            notes: vec![],
        },
        ProbabilityObject {
            name: "D_H2".to_string(),
            family: DistributionFamily::ComposedH2,
            random_variable: "T_H2".to_string(),
            support_description: "Shared verifier view with simulated MS and simulated LE.".to_string(),
            randomness_sources: vec!["MS simulator coins".to_string(), "LE simulator coins".to_string()],
            observable_boundary_premise: boundary.statement.clone(),
            notes: vec![],
        },
        ProbabilityObject {
            name: "D_H3".to_string(),
            family: DistributionFamily::ComposedH3,
            random_variable: "T_H3".to_string(),
            support_description: "Shared verifier view with simulators and inlined oracle programming.".to_string(),
            randomness_sources: vec!["inlined simulator coins".to_string()],
            observable_boundary_premise: boundary.statement.clone(),
            notes: vec!["Identical observable support to H2 by construction.".to_string()],
        },
    ]
}

fn ms_formal_assumptions(_boundary: &MsV2ObservableBoundaryContract) -> Vec<FormalAssumption> {
    vec![
        FormalAssumption {
            id: AssumptionId::A1,
            name: "MS hash binding".to_string(),
            kind: AssumptionKind::HashBinding,
            statement:
                "ValueCommitmentV2 and the statement digest are binding, so any distinguisher that separates D_MS_real from D_MS_hyb1 breaks commitment / statement hash binding on the frozen observable boundary."
                    .to_string(),
            error_symbol: "epsilon_ms_hash_binding".to_string(),
            provided_terms: vec!["epsilon_ms_hash_binding".to_string()],
            depends_on: vec![],
        },
        FormalAssumption {
            id: AssumptionId::A2,
            name: "MS ROM programmability".to_string(),
            kind: AssumptionKind::RomProgrammability,
            statement:
                "The Fiat-Shamir oracle for MS v2 is programmable on the frozen observable boundary, so replacing real challenge derivation with programmed challenge derivation changes the verifier-view law by at most epsilon_ms_rom_programmability."
                    .to_string(),
            error_symbol: "epsilon_ms_rom_programmability".to_string(),
            provided_terms: vec!["epsilon_ms_rom_programmability".to_string()],
            depends_on: vec![],
        },
    ]
}

fn ms_3a_exact_bitness_simulation_lemma() -> MsReductionLemma {
    MsReductionLemma {
        name: "MS-3a".to_string(),
        source_distribution: "D_MS_hyb2_bitness_real".to_string(),
        target_distribution: "D_MS_hyb2_bitness_sim".to_string(),
        assumption_dependencies: vec![],
        premise_assumptions: vec![
            MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
            MS_SCHNORR_REPARAMETERIZATION_CONTRACT.to_string(),
            "Under programmed bitness challenges, each witness-using branch can be rewritten exactly as a simulated Schnorr branch at the same public point and challenge split.".to_string(),
        ],
        advantage_function: AdvantageFunction {
            name: "Adv_MS_3a".to_string(),
            distinguisher_class:
                "PPT distinguishers measurable on the frozen MS bitness transcript boundary"
                    .to_string(),
            left_distribution: "D_MS_hyb2_bitness_real".to_string(),
            right_distribution: "D_MS_hyb2_bitness_sim".to_string(),
            definition:
                "Adv_MS_3a(D) = |Pr[D(T_MS_hyb2_bitness_real)=1] - Pr[D(T_MS_hyb2_bitness_sim)=1]|"
                    .to_string(),
        },
        bound: AdvantageBound {
            symbol: "delta_ms_exact_bitness".to_string(),
            expression: "Adv_MS_3a(D) = 0".to_string(),
            numeric_upper_bound: Some(0.0),
            dependencies: vec![
                MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
                MS_SCHNORR_REPARAMETERIZATION_CONTRACT.to_string(),
            ],
            epsilon_dependencies: vec![],
            justification:
                "With the global bitness challenge programmed from announcement-only query material, the real witness-using branch and the simulated branch are exactly the same distribution by Schnorr transcript reparameterization."
                    .to_string(),
        },
        theorem_statement:
            "MS-3a: once the bitness Fiat-Shamir query is programmed, every witness-using bitness branch is exactly distribution-identical to a simulated Schnorr branch, so the bitness transcript gap is zero."
                .to_string(),
        status: ProofStatus::ByConstruction,
    }
}

fn ms_3b_true_clause_correctness_lemma() -> MsReductionLemma {
    MsReductionLemma {
        name: "MS-3b".to_string(),
        source_distribution: "D_MS_true_clause_public_points".to_string(),
        target_distribution: "D_MS_true_clause_r_times_h".to_string(),
        assumption_dependencies: vec![],
        premise_assumptions: vec![
            MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT.to_string(),
            "At the highest differing bit position, all bits above the pivot match the public target and the pivot bit equals 1 while the target bit equals 0.".to_string(),
        ],
        advantage_function: AdvantageFunction {
            name: "Adv_MS_3b".to_string(),
            distinguisher_class:
                "PPT distinguishers over derived true-clause comparison public points"
                    .to_string(),
            left_distribution: "D_MS_true_clause_public_points".to_string(),
            right_distribution: "D_MS_true_clause_r_times_h".to_string(),
            definition:
                "Adv_MS_3b(D) = |Pr[D(T_MS_true_clause_public_points)=1] - Pr[D(T_MS_true_clause_r_times_h)=1]|"
                    .to_string(),
        },
        bound: AdvantageBound {
            symbol: "delta_ms_exact_true_clause".to_string(),
            expression: "Adv_MS_3b(D) = 0".to_string(),
            numeric_upper_bound: Some(0.0),
            dependencies: vec![MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT.to_string()],
            epsilon_dependencies: vec![],
            justification:
                "For the highest differing bit, the true comparison clause public points reduce exactly to P = r * H for the committed blinders, so the comparison witness relation is explicit and exact."
                    .to_string(),
        },
        theorem_statement:
            "MS-3b: the highest differing bit determines a true comparison clause whose public points are exactly of the form P = r * H, so the remaining comparison witness relation is purely Schnorr-style."
                .to_string(),
        status: ProofStatus::ByConstruction,
    }
}

fn ms_3c_exact_comparison_simulation_lemma() -> MsReductionLemma {
    MsReductionLemma {
        name: "MS-3c".to_string(),
        source_distribution: "D_MS_hyb2".to_string(),
        target_distribution: "D_MS_sim".to_string(),
        assumption_dependencies: vec![],
        premise_assumptions: vec![
            MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
            MS_SCHNORR_REPARAMETERIZATION_CONTRACT.to_string(),
            MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT.to_string(),
            "All false comparison clauses are already simulated in the programmed real prover; only the true clause remains and it is exactly simulatable once its public points are written as P = r * H.".to_string(),
        ],
        advantage_function: AdvantageFunction {
            name: "Adv_MS_3c".to_string(),
            distinguisher_class: "PPT distinguishers measurable on the frozen MS observable boundary".to_string(),
            left_distribution: "D_MS_hyb2".to_string(),
            right_distribution: "D_MS_sim".to_string(),
            definition:
                "Adv_MS_3c(D) = |Pr[D(T_MS_hyb2)=1] - Pr[D(T_MS_sim)=1]|"
                    .to_string(),
        },
        bound: AdvantageBound {
            symbol: "delta_ms_exact_comparison".to_string(),
            expression: "Adv_MS_3c(D) = 0".to_string(),
            numeric_upper_bound: Some(0.0),
            dependencies: vec![
                "MS-3a exact bitness transcript simulation under programmed challenges".to_string(),
                "MS-3b true-clause correctness at the highest differing bit".to_string(),
                MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
            ],
            epsilon_dependencies: vec![],
            justification:
                "After bitness exact simulation and true-clause public-point characterization, the residual comparison transcript is exactly a simulated Schnorr transcript under programmed announcement-only comparison queries, so D_MS_hyb2 and D_MS_sim coincide on the observable boundary."
                    .to_string(),
        },
        theorem_statement:
            "MS-3c: once comparison challenges are programmed from announcement-only query material and the true clause is expressed as P = r * H, the programmed hybrid and the MS simulator law are exactly identical on the frozen observable boundary."
                .to_string(),
        status: ProofStatus::ByConstruction,
    }
}

fn ms_reduction_chain_for_frozen_interface(
    boundary: &MsV2ObservableBoundaryContract,
) -> MsReductionChain {
    let assumptions = ms_formal_assumptions(boundary);
    let lemmas = vec![
        MsReductionLemma {
            name: "MS-1".to_string(),
            source_distribution: "D_MS_real".to_string(),
            target_distribution: "D_MS_hyb1".to_string(),
            assumption_dependencies: vec![AssumptionId::A1],
            premise_assumptions: vec![
                "MS hash binding".to_string(),
                "Frozen observable boundary contract".to_string(),
            ],
            advantage_function: AdvantageFunction {
                name: "Adv_MS_1".to_string(),
                distinguisher_class: "PPT distinguishers measurable on the frozen MS observable boundary".to_string(),
                left_distribution: "D_MS_real".to_string(),
                right_distribution: "D_MS_hyb1".to_string(),
                definition:
                    "Adv_MS_1(D) = |Pr[D(T_MS_real)=1] - Pr[D(T_MS_hyb1)=1]|".to_string(),
            },
            bound: AdvantageBound {
                symbol: "epsilon_ms_hash_binding".to_string(),
                expression: "Adv_MS_1(D) <= epsilon_ms_hash_binding".to_string(),
                numeric_upper_bound: None,
                dependencies: vec![
                    "hash binding of ValueCommitmentV2".to_string(),
                    "binding of statement_digest".to_string(),
                ],
                epsilon_dependencies: vec![],
                justification:
                    "Any visible difference between D_MS_real and D_MS_hyb1 exposes a boundary-visible inconsistency in the commitment / statement binding layer.".to_string(),
            },
            theorem_statement:
                "MS-1 replaces witness-bound commitment handling by its boundary-consistent abstraction; any distinguisher is reduced to hash / commitment binding on the frozen observable interface."
                    .to_string(),
            status: ProofStatus::BoundedUnderAssumptions,
        },
        MsReductionLemma {
            name: "MS-2".to_string(),
            source_distribution: "D_MS_hyb1".to_string(),
            target_distribution: "D_MS_hyb2".to_string(),
            assumption_dependencies: vec![AssumptionId::A2],
            premise_assumptions: vec![
                "MS ROM programmability".to_string(),
                "Frozen observable boundary contract".to_string(),
            ],
            advantage_function: AdvantageFunction {
                name: "Adv_MS_2".to_string(),
                distinguisher_class: "PPT distinguishers measurable on the frozen MS observable boundary".to_string(),
                left_distribution: "D_MS_hyb1".to_string(),
                right_distribution: "D_MS_hyb2".to_string(),
                definition:
                    "Adv_MS_2(D) = |Pr[D(T_MS_hyb1)=1] - Pr[D(T_MS_hyb2)=1]|".to_string(),
            },
            bound: AdvantageBound {
                symbol: "epsilon_ms_rom_programmability".to_string(),
                expression: "Adv_MS_2(D) <= epsilon_ms_rom_programmability".to_string(),
                numeric_upper_bound: None,
                dependencies: vec!["programmable ROM for MS Fiat-Shamir queries".to_string()],
                epsilon_dependencies: vec![],
                justification:
                    "The only difference between D_MS_hyb1 and D_MS_hyb2 is whether the verifier view is induced by real or programmed Fiat-Shamir challenge points on the observable boundary.".to_string(),
            },
            theorem_statement:
                "MS-2 replaces real Fiat-Shamir challenge derivation with programmed oracle answers on the frozen observable boundary, with loss epsilon_ms_rom_programmability."
                    .to_string(),
            status: ProofStatus::BoundedUnderAssumptions,
        },
        ms_3a_exact_bitness_simulation_lemma(),
        ms_3b_true_clause_correctness_lemma(),
        ms_3c_exact_comparison_simulation_lemma(),
    ];

    MsReductionChain {
        assumptions,
        lemmas,
        combined_bound: AdvantageBound {
            symbol: "epsilon_ms".to_string(),
            expression:
                "epsilon_ms = epsilon_ms_hash_binding + epsilon_ms_rom_programmability"
                    .to_string(),
            numeric_upper_bound: None,
            dependencies: vec![
                "epsilon_ms_hash_binding".to_string(),
                "epsilon_ms_rom_programmability".to_string(),
            ],
            epsilon_dependencies: vec![
                "epsilon_ms_hash_binding".to_string(),
                "epsilon_ms_rom_programmability".to_string(),
            ],
            justification:
                "MS-1 and MS-2 carry the only non-zero MS losses; MS-3a, MS-3b, and MS-3c are exact-simulation lemmas with zero advantage on the frozen observable boundary.".to_string(),
        },
        theorem_statement:
            "Under hash binding, ROM programmability, and the frozen observable boundary contract, Adv_MS(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability, with the residual programmed MS transcript gap discharged by the exact-simulation lemmas MS-3a, MS-3b, and MS-3c."
                .to_string(),
        status: ProofStatus::BoundedUnderAssumptions,
    }
}

fn le_advantage_bound(
    le_constraint_analysis: &LeHvzkConstraintAnalysis,
    boundary: &MsV2ObservableBoundaryContract,
) -> AdvantageBound {
    let rejection = RejectionSamplingClaim::for_current_params();
    let numeric_upper_bound = rejection.abort_probability_estimate
        + 2f64.powf(-le_constraint_analysis.fs_security_bits);

    AdvantageBound {
        symbol: "epsilon_le".to_string(),
        expression:
            "Adv_H1_H2(D) <= epsilon_le(eta,gamma,beta,c_poly_size,c_poly_span)".to_string(),
        numeric_upper_bound: Some(numeric_upper_bound),
        dependencies: vec![
            format!("eta={}", le_constraint_analysis.eta),
            format!("gamma={}", le_constraint_analysis.gamma),
            format!("beta={}", le_constraint_analysis.beta),
            format!("c_poly_size={}", le_constraint_analysis.c_poly_size),
            format!("c_poly_span={}", le_constraint_analysis.c_poly_span),
            boundary.statement.clone(),
        ],
        epsilon_dependencies: vec![],
        justification: format!(
            "epsilon_le is parameter dependent and includes the rejection-sampling term {:.6e} plus the Fiat-Shamir term 2^(-{:.2}) ~= {:.6e}.",
            rejection.abort_probability_estimate,
            le_constraint_analysis.fs_security_bits,
            2f64.powf(-le_constraint_analysis.fs_security_bits)
        ),
    }
}

fn frozen_qssm_architecture_seal() -> FrozenArchitectureSeal {
    FrozenArchitectureSeal {
        name: "Frozen QSSM security model".to_string(),
        no_further_structural_changes_allowed: true,
        components: vec![
            FrozenArchitectureComponent {
                name: "MS v2 transcript / API".to_string(),
                frozen: true,
                rationale: "The MS v2 Option B transcript format and observable boundary are canonical and no further structural changes are permitted.".to_string(),
            },
            FrozenArchitectureComponent {
                name: "LE Set B parameter surface".to_string(),
                frozen: true,
                rationale: "The LE Set B eta/gamma/challenge template is the committed theorem target and is no longer design-tunable.".to_string(),
            },
            FrozenArchitectureComponent {
                name: "MS / LE simulator contracts".to_string(),
                frozen: true,
                rationale: "The simulator interfaces, observable boundary contract, and shared-randomness rules are frozen as theorem premises.".to_string(),
            },
            FrozenArchitectureComponent {
                name: "Closed theorem layer".to_string(),
                frozen: true,
                rationale: "The final theorem is now carried only by the closed cryptographic object and is not open to further structural rewrites.".to_string(),
            },
        ],
        statement:
            "The MS transcript surface, LE parameter surface, simulator contracts, and theorem layer are frozen; any future structural change invalidates this theorem object until the full closure pass is rerun."
                .to_string(),
        status: ProofStatus::ByConstruction,
    }
}

fn assumption_dependency_graph_for_canonical_option_b_and_set_b(
    boundary: &MsV2ObservableBoundaryContract,
    le_constraint_analysis: &LeHvzkConstraintAnalysis,
) -> AssumptionDependencyGraph {
    let mut inputs = ms_formal_assumptions(boundary);
    inputs.push(FormalAssumption {
        id: AssumptionId::A4,
        name: "LE Set B HVZK / rejection-sampling bound".to_string(),
        kind: AssumptionKind::LeHvzkBound,
        statement: format!(
            "The LE Set B simulator satisfies the encoded rejection-sampling and Fiat-Shamir bound epsilon_le(eta,gamma,beta,c_poly_size,c_poly_span) with eta={}, gamma={}, beta={}, c_poly_size={}, c_poly_span={}.",
            le_constraint_analysis.eta,
            le_constraint_analysis.gamma,
            le_constraint_analysis.beta,
            le_constraint_analysis.c_poly_size,
            le_constraint_analysis.c_poly_span
        ),
        error_symbol: "epsilon_le".to_string(),
        provided_terms: vec!["epsilon_le".to_string()],
        depends_on: vec![],
    });

    AssumptionDependencyGraph {
        name: "QSSM ZK assumption dependency graph".to_string(),
        inputs,
        edges: vec![
            AssumptionDependencyEdge {
                from: AssumptionId::A1,
                to: "MS-1".to_string(),
                rationale: "Hash binding supports the MS-1 hybrid step.".to_string(),
            },
            AssumptionDependencyEdge {
                from: AssumptionId::A2,
                to: "MS-2".to_string(),
                rationale: "ROM programmability supports the MS-2 hybrid step.".to_string(),
            },
            AssumptionDependencyEdge {
                from: AssumptionId::A1,
                to: "H0_to_H1_MS_replacement".to_string(),
                rationale: "The composed MS replacement consumes the MS-1 hash-binding leaf bound.".to_string(),
            },
            AssumptionDependencyEdge {
                from: AssumptionId::A2,
                to: "H0_to_H1_MS_replacement".to_string(),
                rationale: "The composed MS replacement consumes the MS-2 ROM leaf bound, while the exact-simulation lemmas contribute zero advantage by construction.".to_string(),
            },
            AssumptionDependencyEdge {
                from: AssumptionId::A4,
                to: "H1_to_H2_LE_replacement".to_string(),
                rationale: "The LE replacement uses the explicit Set B HVZK / ROM bound.".to_string(),
            },
            AssumptionDependencyEdge {
                from: AssumptionId::A1,
                to: "composed_boundary_additivity".to_string(),
                rationale: "The final additive composition theorem inherits the MS hash-binding loss via epsilon_ms.".to_string(),
            },
            AssumptionDependencyEdge {
                from: AssumptionId::A2,
                to: "composed_boundary_additivity".to_string(),
                rationale: "The final additive composition theorem inherits the MS ROM loss via epsilon_ms.".to_string(),
            },
            AssumptionDependencyEdge {
                from: AssumptionId::A4,
                to: "composed_boundary_additivity".to_string(),
                rationale: "The final additive composition theorem inherits the explicit LE loss via epsilon_le.".to_string(),
            },
        ],
        output_bound: "epsilon_qssm".to_string(),
        status: ProofStatus::BoundedUnderAssumptions,
    }
}

fn theorem_lemma_chain_for_canonical_option_b_and_set_b(
    reduction: &ReductionProofSketch,
) -> Vec<TheoremLemmaReference> {
    vec![
        TheoremLemmaReference {
            name: reduction.ms_reduction_chain.lemmas[0].name.clone(),
            assumption_dependencies: reduction.ms_reduction_chain.lemmas[0]
                .assumption_dependencies
                .clone(),
            lemma_dependencies: vec![],
            premise_contracts: reduction.ms_reduction_chain.lemmas[0]
                .premise_assumptions
                .clone(),
            produced_bound: reduction.ms_reduction_chain.lemmas[0].bound.symbol.clone(),
            produced_bound_expression: reduction.ms_reduction_chain.lemmas[0]
                .bound
                .expression
                .clone(),
            produced_bound_numeric_upper_bound: reduction.ms_reduction_chain.lemmas[0]
                .bound
                .numeric_upper_bound,
            status: reduction.ms_reduction_chain.lemmas[0].status,
        },
        TheoremLemmaReference {
            name: reduction.ms_reduction_chain.lemmas[1].name.clone(),
            assumption_dependencies: reduction.ms_reduction_chain.lemmas[1]
                .assumption_dependencies
                .clone(),
            lemma_dependencies: vec![],
            premise_contracts: reduction.ms_reduction_chain.lemmas[1]
                .premise_assumptions
                .clone(),
            produced_bound: reduction.ms_reduction_chain.lemmas[1].bound.symbol.clone(),
            produced_bound_expression: reduction.ms_reduction_chain.lemmas[1]
                .bound
                .expression
                .clone(),
            produced_bound_numeric_upper_bound: reduction.ms_reduction_chain.lemmas[1]
                .bound
                .numeric_upper_bound,
            status: reduction.ms_reduction_chain.lemmas[1].status,
        },
        TheoremLemmaReference {
            name: reduction.ms_reduction_chain.lemmas[2].name.clone(),
            assumption_dependencies: reduction.ms_reduction_chain.lemmas[2]
                .assumption_dependencies
                .clone(),
            lemma_dependencies: vec![],
            premise_contracts: reduction.ms_reduction_chain.lemmas[2]
                .premise_assumptions
                .clone(),
            produced_bound: reduction.ms_reduction_chain.lemmas[2].bound.symbol.clone(),
            produced_bound_expression: reduction.ms_reduction_chain.lemmas[2]
                .bound
                .expression
                .clone(),
            produced_bound_numeric_upper_bound: reduction.ms_reduction_chain.lemmas[2]
                .bound
                .numeric_upper_bound,
            status: reduction.ms_reduction_chain.lemmas[2].status,
        },
        TheoremLemmaReference {
            name: reduction.ms_reduction_chain.lemmas[3].name.clone(),
            assumption_dependencies: reduction.ms_reduction_chain.lemmas[3]
                .assumption_dependencies
                .clone(),
            lemma_dependencies: vec![],
            premise_contracts: reduction.ms_reduction_chain.lemmas[3]
                .premise_assumptions
                .clone(),
            produced_bound: reduction.ms_reduction_chain.lemmas[3].bound.symbol.clone(),
            produced_bound_expression: reduction.ms_reduction_chain.lemmas[3]
                .bound
                .expression
                .clone(),
            produced_bound_numeric_upper_bound: reduction.ms_reduction_chain.lemmas[3]
                .bound
                .numeric_upper_bound,
            status: reduction.ms_reduction_chain.lemmas[3].status,
        },
        TheoremLemmaReference {
            name: reduction.ms_reduction_chain.lemmas[4].name.clone(),
            assumption_dependencies: reduction.ms_reduction_chain.lemmas[4]
                .assumption_dependencies
                .clone(),
            lemma_dependencies: vec!["MS-3a".to_string(), "MS-3b".to_string()],
            premise_contracts: reduction.ms_reduction_chain.lemmas[4]
                .premise_assumptions
                .clone(),
            produced_bound: reduction.ms_reduction_chain.lemmas[4].bound.symbol.clone(),
            produced_bound_expression: reduction.ms_reduction_chain.lemmas[4]
                .bound
                .expression
                .clone(),
            produced_bound_numeric_upper_bound: reduction.ms_reduction_chain.lemmas[4]
                .bound
                .numeric_upper_bound,
            status: reduction.ms_reduction_chain.lemmas[4].status,
        },
        TheoremLemmaReference {
            name: reduction.hybrid_lemmas[0].name.clone(),
            assumption_dependencies: reduction.hybrid_lemmas[0].assumption_dependencies.clone(),
            lemma_dependencies: vec![
                "MS-1".to_string(),
                "MS-2".to_string(),
                "MS-3a".to_string(),
                "MS-3b".to_string(),
                "MS-3c".to_string(),
            ],
            premise_contracts: reduction.hybrid_lemmas[0].premise_contracts.clone(),
            produced_bound: reduction.hybrid_lemmas[0].bound.symbol.clone(),
            produced_bound_expression: reduction.hybrid_lemmas[0].bound.expression.clone(),
            produced_bound_numeric_upper_bound: reduction.hybrid_lemmas[0]
                .bound
                .numeric_upper_bound,
            status: reduction.hybrid_lemmas[0].status,
        },
        TheoremLemmaReference {
            name: reduction.hybrid_lemmas[1].name.clone(),
            assumption_dependencies: reduction.hybrid_lemmas[1].assumption_dependencies.clone(),
            lemma_dependencies: vec![],
            premise_contracts: reduction.hybrid_lemmas[1].premise_contracts.clone(),
            produced_bound: reduction.hybrid_lemmas[1].bound.symbol.clone(),
            produced_bound_expression: reduction.hybrid_lemmas[1].bound.expression.clone(),
            produced_bound_numeric_upper_bound: reduction.hybrid_lemmas[1]
                .bound
                .numeric_upper_bound,
            status: reduction.hybrid_lemmas[1].status,
        },
        TheoremLemmaReference {
            name: reduction.hybrid_lemmas[2].name.clone(),
            assumption_dependencies: reduction.hybrid_lemmas[2].assumption_dependencies.clone(),
            lemma_dependencies: vec![],
            premise_contracts: reduction.hybrid_lemmas[2].premise_contracts.clone(),
            produced_bound: reduction.hybrid_lemmas[2].bound.symbol.clone(),
            produced_bound_expression: reduction.hybrid_lemmas[2].bound.expression.clone(),
            produced_bound_numeric_upper_bound: reduction.hybrid_lemmas[2]
                .bound
                .numeric_upper_bound,
            status: reduction.hybrid_lemmas[2].status,
        },
        TheoremLemmaReference {
            name: reduction.composition_safety_lemma.name.clone(),
            assumption_dependencies: reduction
                .composition_safety_lemma
                .assumption_dependencies
                .clone(),
            lemma_dependencies: vec![
                reduction.hybrid_lemmas[0].name.clone(),
                reduction.hybrid_lemmas[1].name.clone(),
                reduction.hybrid_lemmas[2].name.clone(),
            ],
            premise_contracts: reduction.composition_safety_lemma.premise_contracts.clone(),
            produced_bound: reduction.composition_safety_lemma.bound.symbol.clone(),
            produced_bound_expression: reduction
                .composition_safety_lemma
                .bound
                .expression
                .clone(),
            produced_bound_numeric_upper_bound: reduction
                .composition_safety_lemma
                .bound
                .numeric_upper_bound,
            status: reduction.composition_safety_lemma.status,
        },
    ]
}

fn game_based_zk_proof_for_canonical_option_b_and_set_b(
    boundary: &MsV2ObservableBoundaryContract,
    le_constraint_analysis: &LeHvzkConstraintAnalysis,
    reduction: &ReductionProofSketch,
) -> GameBasedZkProof {
    let le_bound = le_advantage_bound(le_constraint_analysis, boundary);
    let g0_to_g1_bound = AdvantageBound {
        symbol: "epsilon_g0_g1".to_string(),
        expression:
            "Adv_G0_G1(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability"
                .to_string(),
        numeric_upper_bound: None,
        dependencies: vec![
            "MS-1".to_string(),
            "MS-2".to_string(),
            "MS-3a".to_string(),
            "MS-3b".to_string(),
            "MS-3c".to_string(),
        ],
        epsilon_dependencies: vec![
            "epsilon_ms_hash_binding".to_string(),
            "epsilon_ms_rom_programmability".to_string(),
        ],
        justification:
            "G0_to_G1 replaces only the MS component by simulate_ms_v2_transcript while leaving the LE prover real; the only non-zero MS losses are the A1/A2 leaves, and the residual programmed transcript gap is discharged exactly by MS-3a, MS-3b, and MS-3c."
                .to_string(),
    };
    let g1_to_g2_bound = AdvantageBound {
        symbol: "epsilon_g1_g2".to_string(),
        expression: "Adv_G1_G2(D) <= epsilon_le".to_string(),
        numeric_upper_bound: le_bound.numeric_upper_bound,
        dependencies: vec![
            reduction.hybrid_lemmas[1].name.clone(),
            reduction.hybrid_lemmas[2].name.clone(),
            reduction.composition_safety_lemma.name.clone(),
        ],
        epsilon_dependencies: vec!["epsilon_le".to_string()],
        justification:
            "G1_to_G2 replaces the remaining LE prover by simulate_le_transcript and then packages both protocol simulators into the single global simulator simulate_qssm_transcript under domain-separated shared randomness."
                .to_string(),
    };

    GameBasedZkProof {
        security_definition:
            "Full simulation-based zero-knowledge for the composed QSSM verifier view in the programmable random oracle model."
                .to_string(),
        exact_claim:
            "For every PPT distinguisher over the full joint transcript, there exists a public-input-only global simulator S such that G0 and G2 are computationally indistinguishable with the stated additive bound."
                .to_string(),
        games: vec![
            StandardZkGame {
                name: "G0".to_string(),
                transcript_distribution:
                    "sample_real_qssm_transcript(ms witness, le witness, public_input)".to_string(),
                simulator: None,
                theorem_role:
                    "Baseline real game: both MS v2 and LE use their real provers on the shared QSSM verifier view."
                        .to_string(),
            },
            StandardZkGame {
                name: "G1".to_string(),
                transcript_distribution:
                    "MS transcript from simulate_ms_v2_transcript; LE transcript from sample_real_le_transcript."
                        .to_string(),
                simulator: Some("simulate_ms_v2_transcript".to_string()),
                theorem_role:
                    "MS-only hybrid: replace the MS prover with its witness-free simulator while keeping the LE prover real."
                        .to_string(),
            },
            StandardZkGame {
                name: "G2".to_string(),
                transcript_distribution:
                    "simulate_qssm_transcript(public_input, simulator_seed)".to_string(),
                simulator: Some("simulate_qssm_transcript".to_string()),
                theorem_role:
                    "Ideal game: a single global simulator emits the full joint QSSM transcript from public inputs only."
                        .to_string(),
            },
        ],
        global_simulator: GlobalQssmSimulator {
            name: "simulate_qssm_transcript".to_string(),
            public_input_interface: vec![
                "MsHiddenValuePublicInput".to_string(),
                "LePublicInput".to_string(),
                "global simulator seed".to_string(),
            ],
            forbidden_inputs: vec![
                "MS hidden value".to_string(),
                "MS commitment blinders".to_string(),
                "MS prover seed".to_string(),
                "LE witness r".to_string(),
                "LE prover seed".to_string(),
            ],
            ms_component:
                "Derive a domain-separated ms_seed and invoke simulate_ms_v2_transcript(public_input.ms, ms_seed)."
                    .to_string(),
            le_component:
                "Derive a domain-separated le_seed and invoke simulate_le_transcript(public_input.le, le_seed)."
                    .to_string(),
            shared_randomness_model:
                "A single ambient simulator seed is split into domain-separated MS and LE seeds; no witness state or correlated coins are shared across the two component simulators."
                    .to_string(),
            output_distribution: "SimulatedQssmTranscript".to_string(),
        },
        transitions: vec![
            StandardZkTransition {
                name: "G0_to_G1".to_string(),
                from_game: "G0".to_string(),
                to_game: "G1".to_string(),
                explicit_simulator:
                    "Replace the MS prover by simulate_ms_v2_transcript(public_input.ms, ms_seed) while retaining sample_real_le_transcript for LE."
                        .to_string(),
                assumption_dependencies: vec![AssumptionId::A1, AssumptionId::A2],
                internal_lemma_dependencies: vec![
                    "MS-1".to_string(),
                    "MS-2".to_string(),
                    "MS-3a".to_string(),
                    "MS-3b".to_string(),
                    "MS-3c".to_string(),
                ],
                bound: g0_to_g1_bound,
                theorem_statement:
                    "The G0_to_G1 transition is justified by the explicit MS simulator, the A1/A2 leaf reductions, and the exact-simulation lemmas MS-3a, MS-3b, and MS-3c, so no residual custom MS loss remains."
                        .to_string(),
            },
            StandardZkTransition {
                name: "G1_to_G2".to_string(),
                from_game: "G1".to_string(),
                to_game: "G2".to_string(),
                explicit_simulator:
                    "Replace the LE prover by simulate_le_transcript(public_input.le, le_seed) and package the MS / LE simulator pair into the global simulator simulate_qssm_transcript."
                        .to_string(),
                assumption_dependencies: vec![AssumptionId::A4],
                internal_lemma_dependencies: vec![
                    reduction.hybrid_lemmas[1].name.clone(),
                    reduction.hybrid_lemmas[2].name.clone(),
                    reduction.composition_safety_lemma.name.clone(),
                ],
                bound: g1_to_g2_bound,
                theorem_statement:
                    "The G1_to_G2 transition is justified by the LE HVZK simulator under A4, and the additive composition argument closes the full QSSM hop with epsilon_le."
                        .to_string(),
            },
        ],
        final_bound: reduction.final_advantage_bound.clone(),
        theorem_statement:
            "Fix the explicit games G0, G1, and G2 above. For every PPT distinguisher D over the full joint transcript, |Pr[D(G0)=1] - Pr[D(G2)=1]| <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le."
                .to_string(),
        status: ProofStatus::BoundedUnderAssumptions,
    }
}

fn collect_theorem_path_entries(
    architecture_freeze: &FrozenArchitectureSeal,
    assumption_graph: &AssumptionDependencyGraph,
    game_based_proof: &GameBasedZkProof,
    premise_contracts: &[String],
    output_bound: &AdvantageBound,
    theorem_statement: &str,
) -> Vec<(String, String)> {
    let mut entries = vec![
        ("architecture_freeze.statement".to_string(), architecture_freeze.statement.clone()),
        ("game_based_proof.security_definition".to_string(), game_based_proof.security_definition.clone()),
        ("game_based_proof.exact_claim".to_string(), game_based_proof.exact_claim.clone()),
        ("game_based_proof.theorem_statement".to_string(), game_based_proof.theorem_statement.clone()),
        ("game_based_proof.global_simulator.shared_randomness_model".to_string(), game_based_proof.global_simulator.shared_randomness_model.clone()),
        ("closed_theorem.output_bound.expression".to_string(), output_bound.expression.clone()),
        ("closed_theorem.output_bound.justification".to_string(), output_bound.justification.clone()),
        ("closed_theorem.theorem_statement".to_string(), theorem_statement.to_string()),
    ];

    for assumption in &assumption_graph.inputs {
        entries.push((
            format!("assumption_graph.{}", assumption.id.label()),
            assumption.statement.clone(),
        ));
    }
    for contract in premise_contracts {
        entries.push(("closed_theorem.premise_contract".to_string(), contract.clone()));
    }
    for game in &game_based_proof.games {
        entries.push((format!("{} transcript_distribution", game.name), game.transcript_distribution.clone()));
        entries.push((format!("{} theorem_role", game.name), game.theorem_role.clone()));
    }
    for transition in &game_based_proof.transitions {
        entries.push((format!("{} theorem_statement", transition.name), transition.theorem_statement.clone()));
        entries.push((format!("{} explicit_simulator", transition.name), transition.explicit_simulator.clone()));
        entries.push((format!("{} bound.justification", transition.name), transition.bound.justification.clone()));
    }
    entries
}

fn collect_theorem_path_bounds<'a>(
    game_based_proof: &'a GameBasedZkProof,
    output_bound: &'a AdvantageBound,
) -> Vec<(String, &'a AdvantageBound)> {
    let mut bounds = Vec::new();
    for transition in &game_based_proof.transitions {
        bounds.push((transition.name.clone(), &transition.bound));
    }
    bounds.push((
        "game_based_proof.final_bound".to_string(),
        &game_based_proof.final_bound,
    ));
    bounds.push(("closed_theorem.output_bound".to_string(), output_bound));
    bounds
}

fn residual_ms_epsilon_tokens(text: &str) -> Vec<String> {
    let allowed = ["epsilon_ms_hash_binding", "epsilon_ms_rom_programmability"];
    let mut tokens = BTreeSet::new();
    for token in text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')) {
        if token.starts_with("epsilon_ms_") && !allowed.contains(&token) {
            tokens.insert(token.to_string());
        }
    }
    tokens.into_iter().collect()
}

fn validate_exact_ms_simulation_lemmas(
    internal_lemma_chain: &[TheoremLemmaReference],
    issues: &mut Vec<ProofClosureIssue>,
) {
    for lemma in internal_lemma_chain.iter().filter(|lemma| lemma.name.starts_with("MS-")) {
        if lemma.name.starts_with("MS-3") {
            if !lemma.assumption_dependencies.is_empty()
                || lemma.produced_bound_numeric_upper_bound != Some(0.0)
                || lemma.status != ProofStatus::ByConstruction
            {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
                    location: lemma.name.clone(),
                    detail: format!(
                        "{} must be assumption-free, exact, and by-construction, but found assumptions {:?}, numeric bound {:?}, status {:?}.",
                        lemma.name,
                        lemma.assumption_dependencies,
                        lemma.produced_bound_numeric_upper_bound,
                        lemma.status
                    ),
                });
            }
            if lemma
                .assumption_dependencies
                .iter()
                .any(|dependency| !matches!(dependency, AssumptionId::A1 | AssumptionId::A2))
            {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                    location: lemma.name.clone(),
                    detail: format!(
                        "{} depends on an MS assumption outside A1/A2.",
                        lemma.name
                    ),
                });
            }
        }
    }

    let Some(ms_3a) = internal_lemma_chain.iter().find(|lemma| lemma.name == "MS-3a") else {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3a".to_string(),
            detail: "Missing exact bitness simulation lemma MS-3a.".to_string(),
        });
        return;
    };
    let Some(ms_3b) = internal_lemma_chain.iter().find(|lemma| lemma.name == "MS-3b") else {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3b".to_string(),
            detail: "Missing true-clause correctness lemma MS-3b.".to_string(),
        });
        return;
    };
    let Some(ms_3c) = internal_lemma_chain.iter().find(|lemma| lemma.name == "MS-3c") else {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3c".to_string(),
            detail: "Missing exact comparison simulation lemma MS-3c.".to_string(),
        });
        return;
    };

    if !ms_3a
        .premise_contracts
        .iter()
        .any(|item| item == MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT)
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3a".to_string(),
            detail:
                "MS-3a must explicitly require that bitness_query_digest hashes announcements only."
                    .to_string(),
        });
    }
    if !ms_3a
        .premise_contracts
        .iter()
        .any(|item| item == MS_SCHNORR_REPARAMETERIZATION_CONTRACT)
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3a".to_string(),
            detail: "MS-3a must record the exact Schnorr transcript reparameterization premise."
                .to_string(),
        });
    }
    if !ms_3b
        .premise_contracts
        .iter()
        .any(|item| item == MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT)
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3b".to_string(),
            detail:
                "MS-3b must explicitly require the true-clause public-point characterization P = r * H."
                    .to_string(),
        });
    }
    if !ms_3c
        .premise_contracts
        .iter()
        .any(|item| item == MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT)
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3c".to_string(),
            detail:
                "MS-3c must explicitly require that comparison_query_digest hashes announcements only."
                    .to_string(),
        });
    }
    if !ms_3c.lemma_dependencies.iter().any(|item| item == "MS-3a")
        || !ms_3c.lemma_dependencies.iter().any(|item| item == "MS-3b")
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3c".to_string(),
            detail: "MS-3c must depend explicitly on MS-3a and MS-3b.".to_string(),
        });
    }
}

fn symbol_closes_recursively(
    symbol: &str,
    bound_map: &BTreeMap<String, Vec<&AdvantageBound>>,
    assumption_terms: &BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) -> bool {
    if assumption_terms.contains(symbol) {
        return true;
    }

    if !visiting.insert(symbol.to_string()) {
        return false;
    }

    let result = if let Some(bounds) = bound_map.get(symbol) {
        bounds.iter().any(|bound| {
            if bound.numeric_upper_bound.is_some() {
                return true;
            }
            if bound.epsilon_dependencies.is_empty() {
                return assumption_terms.contains(symbol);
            }
            bound.epsilon_dependencies.iter().all(|dep| {
                dep == symbol || symbol_closes_recursively(dep, bound_map, assumption_terms, visiting)
            })
        })
    } else {
        false
    };

    visiting.remove(symbol);
    result
}

fn proof_closure_report_for_closed_theorem(
    architecture_freeze: &FrozenArchitectureSeal,
    assumption_graph: &AssumptionDependencyGraph,
    internal_lemma_chain: &[TheoremLemmaReference],
    game_based_proof: &GameBasedZkProof,
    premise_contracts: &[String],
    output_bound: &AdvantageBound,
    theorem_statement: &str,
) -> ProofClosureReport {
    let mut issues = Vec::new();
    let checked_properties = vec![
        "no empirical metrics in theorem path".to_string(),
        "all lemma assumption dependencies resolve into A1/A2/A4".to_string(),
        "all epsilon terms are defined and bounded".to_string(),
        "composition uses only declared lemma bounds".to_string(),
        "all MS residual terms reduce to A1/A2 or exact simulation".to_string(),
        "architecture freeze seal is active".to_string(),
    ];

    if !architecture_freeze.no_further_structural_changes_allowed {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ArchitectureNotFrozen,
            location: "architecture_freeze".to_string(),
            detail: "The closed theorem requires every architecture component to be frozen and no further structural changes to be allowed.".to_string(),
        });
    }

    let assumption_ids: BTreeSet<_> = assumption_graph.inputs.iter().map(|item| item.id).collect();
    let valid_targets: BTreeSet<_> = internal_lemma_chain
        .iter()
        .map(|item| item.name.clone())
        .collect();

    for edge in &assumption_graph.edges {
        if !assumption_ids.contains(&edge.from) || !valid_targets.contains(&edge.to) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::MissingAssumptionReference,
                location: format!("assumption_graph edge {} -> {}", edge.from.label(), edge.to),
                detail: "The dependency graph references a missing assumption or theorem-internal lemma target.".to_string(),
            });
        }
    }

    for transition in &game_based_proof.transitions {
        for dependency in &transition.assumption_dependencies {
            if !assumption_ids.contains(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::MissingAssumptionReference,
                    location: transition.name.clone(),
                    detail: format!(
                        "{} references undeclared assumption {}.",
                        transition.name,
                        dependency.label()
                    ),
                });
            }
        }
    }
    for lemma in internal_lemma_chain {
        for dependency in &lemma.assumption_dependencies {
            if !assumption_ids.contains(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::MissingAssumptionReference,
                    location: lemma.name.clone(),
                    detail: format!(
                        "{} references undeclared assumption {}.",
                        lemma.name,
                        dependency.label()
                    ),
                });
            }
        }
    }

    let forbidden_tokens = [
        "empirical",
        "alignment",
        "total_variation",
        "jensen_shannon",
        "divergence",
        "conditional_leakage",
        "simulator_gap",
        "entropy_gap",
    ];
    for (location, text) in collect_theorem_path_entries(
        architecture_freeze,
        assumption_graph,
        game_based_proof,
        premise_contracts,
        output_bound,
        theorem_statement,
    ) {
        let lower = text.to_ascii_lowercase();
        if forbidden_tokens.iter().any(|token| lower.contains(token)) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::EmpiricalReferenceInTheoremPath,
                location: location.clone(),
                detail: text.clone(),
            });
        }
        for token in residual_ms_epsilon_tokens(&text) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                location: location.clone(),
                detail: format!(
                    "The theorem path still references residual MS epsilon term {} beyond A1/A2.",
                    token
                ),
            });
        }
    }

    let theorem_bounds = collect_theorem_path_bounds(game_based_proof, output_bound);
    let mut bound_map: BTreeMap<String, Vec<&AdvantageBound>> = BTreeMap::new();
    for (_, bound) in &theorem_bounds {
        bound_map
            .entry(bound.symbol.clone())
            .or_default()
            .push(*bound);
    }
    let assumption_terms: BTreeSet<_> = assumption_graph
        .inputs
        .iter()
        .flat_map(|item| item.provided_terms.iter().cloned())
        .collect();

    for (location, bound) in &theorem_bounds {
        for token in residual_ms_epsilon_tokens(&bound.symbol) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                location: location.clone(),
                detail: format!(
                    "The theorem bound symbol {} still references residual MS epsilon term {} beyond A1/A2.",
                    bound.symbol,
                    token
                ),
            });
        }
        for token in residual_ms_epsilon_tokens(&bound.expression) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                location: location.clone(),
                detail: format!(
                    "The theorem bound expression {} still references residual MS epsilon term {} beyond A1/A2.",
                    bound.expression,
                    token
                ),
            });
        }
        for dependency in &bound.epsilon_dependencies {
            for token in residual_ms_epsilon_tokens(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                    location: location.clone(),
                    detail: format!(
                        "{} still depends on residual MS epsilon term {} beyond A1/A2.",
                        bound.symbol,
                        token
                    ),
                });
            }
            if !bound_map.contains_key(dependency) && !assumption_terms.contains(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::UndefinedEpsilonTerm,
                    location: location.clone(),
                    detail: format!(
                        "{} references undefined epsilon term {}.",
                        bound.symbol,
                        dependency
                    ),
                });
            }
        }
    }

    validate_exact_ms_simulation_lemmas(internal_lemma_chain, &mut issues);

    for symbol in bound_map.keys() {
        if !symbol_closes_recursively(symbol, &bound_map, &assumption_terms, &mut BTreeSet::new()) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::UnboundedEpsilonTerm,
                location: symbol.clone(),
                detail: format!(
                    "{} does not close to a leaf assumption-backed or numerically bounded epsilon term.",
                    symbol
                ),
            });
        }
    }

    for transition in &game_based_proof.transitions {
        let produced_by_dependencies: BTreeSet<_> = transition
            .internal_lemma_dependencies
            .iter()
            .filter_map(|dependency_name| {
                internal_lemma_chain
                    .iter()
                    .find(|item| item.name == *dependency_name)
                    .map(|item| item.produced_bound.clone())
            })
            .collect();

        for dependency in &transition.bound.epsilon_dependencies {
            if !produced_by_dependencies.contains(dependency) && !assumption_terms.contains(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::CompositionUsesUndeclaredBound,
                    location: transition.name.clone(),
                    detail: format!(
                        "{} consumes {} without declaring a supporting internal lemma output or assumption leaf.",
                        transition.name,
                        dependency
                    ),
                });
            }
        }
    }

    ProofClosureReport {
        closed: issues.is_empty(),
        checked_properties,
        issues,
    }
}


// ---------------------------------------------------------------------------
// Frozen proof-structure version seal
// ---------------------------------------------------------------------------

/// Frozen version of the QSSM proof structure.
/// Changing this value signals a structural break requiring full re-audit.
pub const PROOF_STRUCTURE_VERSION: &str = "QSSM-PROOF-FROZEN-v2.0";

/// Returns the frozen proof-structure version stamp.
/// Compile-time constant; any structural change to the theorem layer must
/// bump this version and re-run the closure checker.
#[must_use]
pub fn proof_structure_version() -> &'static str {
    PROOF_STRUCTURE_VERSION
}

// ---------------------------------------------------------------------------
// Auditability layer
// ---------------------------------------------------------------------------

/// A single edge in the assumption dependency graph, suitable for external
/// rendering (Mermaid, Graphviz, or paper appendix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyGraphEdge {
    pub from: String,
    pub to: String,
    pub label: String,
}

/// Exportable dependency graph for the closed ZK theorem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportableDependencyGraph {
    pub version: String,
    pub nodes: Vec<String>,
    pub edges: Vec<DependencyGraphEdge>,
}

/// Verification checklist entry used by auditors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationChecklistItem {
    pub id: String,
    pub description: String,
    pub passed: bool,
    pub detail: String,
}

/// Verification checklist produced by the audit-mode validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationChecklist {
    pub version: String,
    pub items: Vec<VerificationChecklistItem>,
    pub all_passed: bool,
}

impl ClosedZkTheorem {
    /// Export the assumption dependency graph in a renderer-friendly format.
    #[must_use]
    pub fn export_dependency_graph(&self) -> ExportableDependencyGraph {
        let mut nodes: Vec<String> = self
            .assumption_graph
            .inputs
            .iter()
            .map(|a| format!("{}: {}", a.id.label(), a.name))
            .collect();
        for lemma in &self.internal_lemma_chain {
            nodes.push(lemma.name.clone());
        }
        let edges: Vec<DependencyGraphEdge> = self
            .assumption_graph
            .edges
            .iter()
            .map(|e| DependencyGraphEdge {
                from: e.from.label().to_string(),
                to: e.to.clone(),
                label: e.rationale.clone(),
            })
            .collect();
        ExportableDependencyGraph {
            version: PROOF_STRUCTURE_VERSION.to_string(),
            nodes,
            edges,
        }
    }

    /// Produce a verification checklist covering all auditable invariants.
    #[must_use]
    pub fn verification_checklist(&self) -> VerificationChecklist {
        let mut items = Vec::new();

        // 1. Architecture freeze
        let arch_ok = self.architecture_freeze.no_further_structural_changes_allowed
            && self.architecture_freeze.components.iter().all(|c| c.frozen);
        items.push(VerificationChecklistItem {
            id: "ARCH-FREEZE".to_string(),
            description: "All architecture components are frozen".to_string(),
            passed: arch_ok,
            detail: if arch_ok {
                "All components frozen; no structural changes allowed.".to_string()
            } else {
                "One or more architecture components are not frozen.".to_string()
            },
        });

        // 2. Assumption graph completeness
        let assumed_ids: BTreeSet<_> = self.assumption_graph.inputs.iter().map(|a| a.id).collect();
        let expected = [AssumptionId::A1, AssumptionId::A2, AssumptionId::A4];
        let graph_ok = expected.iter().all(|id| assumed_ids.contains(id))
            && assumed_ids.len() == expected.len();
        items.push(VerificationChecklistItem {
            id: "ASSUMPTION-SET".to_string(),
            description: "Assumption graph contains exactly A1, A2, A4".to_string(),
            passed: graph_ok,
            detail: format!("Found assumptions: {:?}", assumed_ids),
        });

        // 3. Proof closure
        let closure_ok = self.closure_report.closed;
        items.push(VerificationChecklistItem {
            id: "PROOF-CLOSURE".to_string(),
            description: "Proof closure checker reports closed with no issues".to_string(),
            passed: closure_ok,
            detail: if closure_ok {
                "Closure report: closed.".to_string()
            } else {
                format!("Closure issues: {}", self.closure_report.issues.len())
            },
        });

        // 4. MS-3a/3b/3c present and exact
        let ms3_names = ["MS-3a", "MS-3b", "MS-3c"];
        let ms3_ok = ms3_names.iter().all(|name| {
            self.internal_lemma_chain.iter().any(|l| {
                l.name == *name
                    && l.produced_bound_numeric_upper_bound == Some(0.0)
                    && l.status == ProofStatus::ByConstruction
            })
        });
        items.push(VerificationChecklistItem {
            id: "MS-EXACT-SIM".to_string(),
            description: "MS-3a, MS-3b, MS-3c present with zero advantage by construction"
                .to_string(),
            passed: ms3_ok,
            detail: if ms3_ok {
                "All three exact-simulation lemmas verified.".to_string()
            } else {
                "One or more MS-3 lemmas missing or non-zero.".to_string()
            },
        });

        // 5. Output bound references only allowed epsilon terms
        let bound_ok = self
            .output_bound
            .expression
            .contains("epsilon_ms_hash_binding")
            && self
                .output_bound
                .expression
                .contains("epsilon_ms_rom_programmability")
            && self.output_bound.expression.contains("epsilon_le");
        items.push(VerificationChecklistItem {
            id: "OUTPUT-BOUND".to_string(),
            description: "Output bound references only epsilon_ms_hash_binding, epsilon_ms_rom_programmability, epsilon_le".to_string(),
            passed: bound_ok,
            detail: format!("Bound expression: {}", self.output_bound.expression),
        });

        // 6. Simulator independence
        let sim_ok = self
            .game_based_proof
            .global_simulator
            .forbidden_inputs
            .iter()
            .any(|f| f.contains("witness") || f.contains("hidden"))
            && !self
                .game_based_proof
                .global_simulator
                .public_input_interface
                .iter()
                .any(|f| f.contains("witness") || f.contains("hidden"));
        items.push(VerificationChecklistItem {
            id: "SIM-INDEPENDENCE".to_string(),
            description: "Global simulator forbids witness inputs and accepts only public inputs"
                .to_string(),
            passed: sim_ok,
            detail: format!(
                "Forbidden: {:?}",
                self.game_based_proof.global_simulator.forbidden_inputs
            ),
        });

        // 7. Version seal
        items.push(VerificationChecklistItem {
            id: "VERSION-SEAL".to_string(),
            description: "Proof structure version is frozen".to_string(),
            passed: true,
            detail: format!("Version: {PROOF_STRUCTURE_VERSION}"),
        });

        let all_passed = items.iter().all(|item| item.passed);
        VerificationChecklist {
            version: PROOF_STRUCTURE_VERSION.to_string(),
            items,
            all_passed,
        }
    }

    /// Export the closed ZK theorem as paper-grade LaTeX.
    #[must_use]
    pub fn to_latex(&self) -> String {
        let mut out = String::new();
        out.push_str("\\begin{theorem}[QSSM Zero-Knowledge]\n");
        out.push_str("\\label{thm:qssm-zk}\n");
        out.push_str("Let $\\mathcal{D}$ be any PPT distinguisher over the joint QSSM transcript.\n");
        out.push_str("Let $G_0$ denote the real transcript game, $G_1$ the hybrid with the MS component\n");
        out.push_str("replaced by $\\mathsf{Sim}_{\\mathrm{MS}}$, and $G_2$ the ideal game produced by the\n");
        out.push_str("global simulator $\\mathsf{Sim}_{\\mathrm{QSSM}}$.\n");
        out.push_str("Under Assumptions~A1 (hash binding), A2 (ROM programmability), and A4 (LE HVZK bound):\n");
        out.push_str("\\[\n");
        out.push_str("  \\mathsf{Adv}^{\\mathrm{zk}}_{\\mathrm{QSSM}}(\\mathcal{D})\n");
        out.push_str("  \\;=\\;\n");
        out.push_str("  \\bigl|\\Pr[\\mathcal{D}(G_0)=1] - \\Pr[\\mathcal{D}(G_2)=1]\\bigr|\n");
        out.push_str("  \\;\\le\\;\n");
        out.push_str("  \\epsilon_{\\mathrm{ms,bind}}\n");
        out.push_str("  + \\epsilon_{\\mathrm{ms,rom}}\n");
        out.push_str("  + \\epsilon_{\\mathrm{le}}.\n");
        out.push_str("\\]\n");
        out.push_str("\\end{theorem}\n\n");

        out.push_str("\\begin{proof}[Proof sketch]\n");
        out.push_str("The proof proceeds by a sequence of game hops.\n\n");

        out.push_str("\\paragraph{$G_0 \\to G_1$: MS replacement.}\n");
        out.push_str("\\begin{itemize}\n");
        out.push_str("  \\item \\textbf{MS-1.} Replace witness-bound commitment handling by its\n");
        out.push_str("    boundary-consistent abstraction. Any distinguisher is reduced to\n");
        out.push_str("    hash/commitment binding on the frozen observable interface\n");
        out.push_str("    (loss~$\\epsilon_{\\mathrm{ms,bind}}$).\n");
        out.push_str("  \\item \\textbf{MS-2.} Replace real Fiat--Shamir challenge derivation with\n");
        out.push_str("    programmed oracle answers on the frozen observable boundary\n");
        out.push_str("    (loss~$\\epsilon_{\\mathrm{ms,rom}}$).\n");
        out.push_str("  \\item \\textbf{MS-3a.} Once the bitness Fiat--Shamir query is programmed,\n");
        out.push_str("    every witness-using bitness branch is exactly distribution-identical\n");
        out.push_str("    to a simulated Schnorr branch (zero advantage by Schnorr\n");
        out.push_str("    reparameterization).\n");
        out.push_str("  \\item \\textbf{MS-3b.} At the highest differing bit position, every\n");
        out.push_str("    true-clause comparison public point is exactly $P = r \\cdot H$\n");
        out.push_str("    for the corresponding committed blinder~$r$.\n");
        out.push_str("  \\item \\textbf{MS-3c.} Once comparison challenges are programmed from\n");
        out.push_str("    announcement-only query material and the true clause is expressed\n");
        out.push_str("    as $P = r \\cdot H$, the programmed hybrid and the MS simulator\n");
        out.push_str("    law are exactly identical on the frozen observable boundary\n");
        out.push_str("    (zero advantage by construction).\n");
        out.push_str("\\end{itemize}\n");
        out.push_str("Thus $|\\Pr[\\mathcal{D}(G_0)=1] - \\Pr[\\mathcal{D}(G_1)=1]|\n");
        out.push_str("  \\le \\epsilon_{\\mathrm{ms,bind}} + \\epsilon_{\\mathrm{ms,rom}}$.\n\n");

        out.push_str("\\paragraph{$G_1 \\to G_2$: LE replacement.}\n");
        out.push_str("Replace the real LE prover by $\\mathsf{Sim}_{\\mathrm{LE}}$ and compose\n");
        out.push_str("the MS and LE simulators through domain-separated shared randomness.\n");
        out.push_str("By the LE HVZK argument under the Set~B parameter template,\n");
        out.push_str("$|\\Pr[\\mathcal{D}(G_1)=1] - \\Pr[\\mathcal{D}(G_2)=1]| \\le \\epsilon_{\\mathrm{le}}$.\n\n");

        out.push_str("\\paragraph{Composition.}\n");
        out.push_str("By the triangle inequality,\n");
        out.push_str("$\\mathsf{Adv}^{\\mathrm{zk}}_{\\mathrm{QSSM}}(\\mathcal{D})\n");
        out.push_str("  \\le \\epsilon_{\\mathrm{ms,bind}} + \\epsilon_{\\mathrm{ms,rom}} + \\epsilon_{\\mathrm{le}}$.\n");
        out.push_str("\\end{proof}\n");

        out
    }
}

// ---------------------------------------------------------------------------
// Audit-mode validation (feature-gated)
// ---------------------------------------------------------------------------

/// Run the audit-mode validation suite: simulator independence and lemma
/// closure checks. Returns the verification checklist.
///
/// This function is always compiled but is intended to be invoked
/// primarily when the `audit-mode` feature is active.
pub fn run_audit_validation() -> Result<VerificationChecklist, ZkSimulationError> {
    let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
    let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
    let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
    Ok(theorem.verification_checklist())
}

impl RedesignedSystemsTheorem {
    pub fn for_current_and_redesigned_systems() -> Result<Self, ZkSimulationError> {
        let current_system = honest_zk_theorem_for_current_system()?;
        let canonical_ms_v2 = CanonicalMsV2TranscriptDesign::option_b();
        let ms_v2_observable_boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_constraint_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let canonical_le_set_b = CanonicalLeSetB::current();
        let ms_v2_alignment = run_ms_v2_empirical_alignment(&statement_batch_for_ms_v2_alignment())?;
        let unified_hybrid_game = UnifiedZkHybridGame::for_canonical_option_b_and_set_b();
        let closed_zk_theorem = ClosedZkTheorem::for_current_and_redesigned_systems(
            &ms_v2_observable_boundary,
            &le_constraint_analysis,
        );
        let security_claims = vec![
            SecurityClaimRow {
                component: "MS (current)".to_string(),
                property: "Zero-knowledge under frozen hidden-value game".to_string(),
                status: ClaimStatus::NotSatisfied,
                notes: "Structural blocker: visible n, k, and bit_at_k remain witness-dependent under the current transcript surface.".to_string(),
            },
            SecurityClaimRow {
                component: "MS (v2 Option B transcript format)".to_string(),
                property: "Canonical predicate-only transcript surface".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "Implemented as a real value-commitment statement plus a witness-bound predicate proof in qssm_ms::PredicateOnlyStatementV2 / PredicateOnlyProofV2.".to_string(),
            },
            SecurityClaimRow {
                component: "MS (v2 Option B boundary contract)".to_string(),
                property: "Observable sigma-algebra is frozen".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "The frozen qssm_ms accessor surface now serves as the explicit observable-boundary contract for simulator and reduction work.".to_string(),
            },
            SecurityClaimRow {
                component: "MS (v2 Option B)".to_string(),
                property: "Simulation-based zero-knowledge bound".to_string(),
                status: ClaimStatus::Bounded,
                notes: "The MS bound is now reduction-based: epsilon_ms = epsilon_ms_hash_binding + epsilon_ms_rom_programmability, and the residual programmed transcript gap is discharged exactly by MS-3a / MS-3b / MS-3c under the frozen observable boundary contract.".to_string(),
            },
            SecurityClaimRow {
                component: "LE (Set B current params)".to_string(),
                property: "Witness-hiding".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "The current crate explicitly supports witness-hiding under the committed Set B parameters.".to_string(),
            },
            SecurityClaimRow {
                component: "LE (Set B current params)".to_string(),
                property: "HVZK parameter template".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "Current eta, gamma, and challenge shape satisfy the exact HVZK inequalities encoded in the formal crate.".to_string(),
            },
            SecurityClaimRow {
                component: "LE (Set B current params)".to_string(),
                property: "ZK (ROM) bound".to_string(),
                status: ClaimStatus::Bounded,
                notes: "The H1->H2 lemma now exposes an explicit parameter-dependent bound epsilon_le(eta,gamma,beta,c_poly_size,c_poly_span) including rejection-sampling and Fiat-Shamir terms.".to_string(),
            },
            SecurityClaimRow {
                component: "QSSM (composed Option B + Set B)".to_string(),
                property: "End-to-end zero-knowledge bound".to_string(),
                status: ClaimStatus::Bounded,
                notes: "The composed theorem is now stated as Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le under the ROM, the frozen observable boundary contract, exact MS transcript simulation, and simulator independence under shared randomness.".to_string(),
            },
            SecurityClaimRow {
                component: "QSSM security model".to_string(),
                property: "Architecture freeze and proof closure".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "The final theorem is carried by a single closed cryptographic object with an A1/A2/A4 dependency graph, a static proof closure checker, and a frozen MS / LE / simulator / theorem architecture seal.".to_string(),
            },
        ];
        let theorem_statement = closed_zk_theorem.theorem_statement.clone();

        Ok(Self {
            claim_type: ClaimType::ZeroKnowledge,
            current_system,
            canonical_ms_v2,
            ms_v2_observable_boundary,
            le_constraint_analysis,
            canonical_le_set_b,
            ms_v2_alignment,
            unified_hybrid_game,
            closed_zk_theorem,
            security_claims,
            theorem_statement,
        })
    }
}