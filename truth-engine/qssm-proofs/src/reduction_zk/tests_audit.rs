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
