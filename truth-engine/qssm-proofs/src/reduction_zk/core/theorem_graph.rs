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
                    "simulate_qssm_transcript(SimulatorOnly(public_input), simulator_seed)"
                        .to_string(),
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
                "Derive a domain-separated ms_seed and invoke simulate_ms_v2_transcript(SimulatorOnly(public_input.ms), ms_seed)."
                    .to_string(),
            le_component:
                "Derive a domain-separated le_seed and invoke simulate_le_transcript(SimulatorOnly(public_input.le), le_seed)."
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
                    "Replace the MS prover by simulate_ms_v2_transcript(SimulatorOnly(public_input.ms), ms_seed) while retaining sample_real_le_transcript for LE."
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
                    "Replace the LE prover by simulate_le_transcript(SimulatorOnly(public_input.le), le_seed) and package the MS / LE simulator pair into the global simulator simulate_qssm_transcript."
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
