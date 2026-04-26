
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
    fn honest_theorem_reports_ms_blocker_and_le_set_b_alignment() {
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

