use super::*;

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
