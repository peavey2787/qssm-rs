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

