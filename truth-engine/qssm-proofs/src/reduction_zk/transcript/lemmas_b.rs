use super::*;

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
