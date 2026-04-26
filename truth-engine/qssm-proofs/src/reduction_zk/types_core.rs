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

