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

