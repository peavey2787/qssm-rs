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
