use super::*;

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
