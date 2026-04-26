impl CanonicalMsV2TranscriptDesign {
    #[must_use]
    pub fn option_b() -> Self {
        Self {
            name: "MS v2 Option B — predicate-only transcript".to_string(),
            transcript_definition: vec![
                "Visible transcript carries a public value commitment, the result bit, 64 bitness Sigma transcripts, and one comparison Sigma transcript.".to_string(),
                "No comparison coordinates, branch bits, Merkle paths, or legacy Fiat-Shamir nonce metadata are exposed.".to_string(),
                "The exact engine surface is qssm_ms::PredicateOnlyStatementV2 plus qssm_ms::PredicateOnlyProofV2.".to_string(),
            ],
            prover_stub_contract: vec![
                "The current engine-level prover commits to the hidden value bit decomposition and proves bitness plus comparison by Fiat-Shamir Sigma composition.".to_string(),
                "All visible fields are bound to the public statement and witness-derived commitments, while witness values and internal coordinates remain hidden.".to_string(),
            ],
            verifier_stub_contract: vec![
                "The current engine-level verifier checks the commitment statement digest, the bitness challenge splits, and the comparison challenge split under Fiat-Shamir.".to_string(),
                "This is a real witness-bound verifier; the remaining gap is the full simulation-based reduction, not a missing backend.".to_string(),
            ],
            simulator_contract: vec![
                "MS v2 transcript structure and APIs are frozen in this crate; only correctness checks, distinguisher analysis, and reduction work are allowed from this point onward.".to_string(),
                "The witness-free simulator uses qssm_ms::simulate_predicate_only_v2 on the public statement only and programs the oracle queries needed by the Sigma transcripts.".to_string(),
                "The formal crate checks a layered distinguisher suite over the frozen observable surface rather than changing the protocol shape again.".to_string(),
            ],
            removes_witness_dependent_visible_outputs: true,
            status: ClaimStatus::Conditional,
        }
    }
}

impl MsV2ObservableBoundaryContract {
    #[must_use]
    pub fn for_frozen_interface() -> Self {
        Self {
            claim_type: ClaimType::ZeroKnowledge,
            status: ProofStatus::ByConstruction,
            interface_frozen: true,
            sigma_algebra_generators: vec![
                "public value commitment".to_string(),
                "target".to_string(),
                "binding_entropy".to_string(),
                "binding_context".to_string(),
                "context".to_string(),
                "result bit".to_string(),
                "bitness global challenge vector".to_string(),
                "comparison global challenge".to_string(),
                "transcript digest".to_string(),
            ],
            measurable_projections: vec![
                "PredicateOnlyStatementV2::statement_digest".to_string(),
                "PredicateOnlyProofV2::result".to_string(),
                "PredicateOnlyProofV2::bitness_global_challenges".to_string(),
                "PredicateOnlyProofV2::comparison_global_challenge".to_string(),
                "PredicateOnlyProofV2::transcript_digest".to_string(),
            ],
            hidden_non_observables: vec![
                "hidden value".to_string(),
                "commitment blinders".to_string(),
                "prover randomness".to_string(),
                "per-branch Sigma responses not exposed through the frozen qssm_ms API".to_string(),
            ],
            simulator_allowed_inputs: vec![
                "MsHiddenValuePublicInput".to_string(),
                "simulator_seed".to_string(),
            ],
            simulator_forbidden_inputs: vec![
                "PredicateWitnessV2".to_string(),
                "value".to_string(),
                "commitment blinders".to_string(),
                "prover_seed".to_string(),
            ],
            statement:
                "The frozen MS v2 observable sigma-algebra is generated only by the public statement and the stable proof projections exposed by qssm_ms. The qssm-proofs simulator is allowed to depend only on those generators plus fresh simulator coins."
                    .to_string(),
            notes: vec![
                "This contract treats the current qssm_ms accessor surface as the canonical observable boundary for reduction work.".to_string(),
                "If a future wire format exposes additional proof coordinates, the boundary contract must be revised before any new ZK claim is made.".to_string(),
            ],
        }
    }
}

impl UnifiedZkHybridGame {
    #[must_use]
    pub fn for_canonical_option_b_and_set_b() -> Self {
        let observable_boundary = vec![
            "MS public value commitment".to_string(),
            "MS result bit".to_string(),
            "MS bitness global challenges".to_string(),
            "MS comparison global challenge".to_string(),
            "MS transcript digest".to_string(),
            "LE commitment C".to_string(),
            "LE t".to_string(),
            "LE z".to_string(),
            "LE challenge_seed".to_string(),
        ];

        Self {
            claim_type: ClaimType::ZeroKnowledge,
            status: ProofStatus::BoundedUnderAssumptions,
            observable_boundary: observable_boundary.clone(),
            worlds: vec![
                UnifiedHybridWorld {
                    name: "H0".to_string(),
                    ms_source: HybridTranscriptSource::RealProver,
                    le_source: HybridTranscriptSource::RealProver,
                    observable_view: observable_boundary.clone(),
                    transition_argument:
                        "Baseline real world: both MS v2 and LE Set B use their real provers under the shared composed verifier view.".to_string(),
                },
                UnifiedHybridWorld {
                    name: "H1".to_string(),
                    ms_source: HybridTranscriptSource::Simulator,
                    le_source: HybridTranscriptSource::RealProver,
                    observable_view: observable_boundary.clone(),
                    transition_argument:
                        "Replace only the MS v2 layer with its programmable-oracle simulator while keeping the LE prover real inside the same composed game.".to_string(),
                },
                UnifiedHybridWorld {
                    name: "H2".to_string(),
                    ms_source: HybridTranscriptSource::Simulator,
                    le_source: HybridTranscriptSource::Simulator,
                    observable_view: observable_boundary.clone(),
                    transition_argument:
                        "Replace the LE layer with the Set B ROM simulator while leaving the already-simulated MS v2 layer embedded in the same transcript chain.".to_string(),
                },
                UnifiedHybridWorld {
                    name: "H3".to_string(),
                    ms_source: HybridTranscriptSource::Simulator,
                    le_source: HybridTranscriptSource::Simulator,
                    observable_view: observable_boundary,
                    transition_argument:
                        "Inline simulator coins, programmed random-oracle queries, and public-statement bindings to obtain the fully simulated composed world on the same observable boundary.".to_string(),
                },
            ],
            composition_notes: vec![
                "LE Set B is modeled inside the same hybrid chain as MS v2 rather than as a separate theorem stitched on afterward.".to_string(),
                "The only allowed public view is the shared observable boundary listed above; every hybrid step preserves that verifier view.".to_string(),
            ],
        }
    }
}

impl ClosedZkTheorem {
    #[must_use]
    pub fn for_current_and_redesigned_systems(
        boundary: &MsV2ObservableBoundaryContract,
        le_constraint_analysis: &LeHvzkConstraintAnalysis,
    ) -> Self {
        let reduction = ReductionProofSketch::for_canonical_option_b_and_set_b(
            boundary,
            le_constraint_analysis,
        );
        let architecture_freeze = frozen_qssm_architecture_seal();
        let assumption_graph =
            assumption_dependency_graph_for_canonical_option_b_and_set_b(boundary, le_constraint_analysis);
        let internal_lemma_chain = theorem_lemma_chain_for_canonical_option_b_and_set_b(&reduction);
        let game_based_proof = game_based_zk_proof_for_canonical_option_b_and_set_b(
            boundary,
            le_constraint_analysis,
            &reduction,
        );
        let theorem_statement =
            "For every PPT distinguisher D over the shared verifier view, letting G0 be the real QSSM transcript game, G1 the game with only MS replaced by its simulator, and G2 the game produced by the global simulator S = simulate_qssm_transcript, Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le under assumptions A1, A2, and A4 and the shared-randomness simulator-independence model."
                .to_string();
        let premise_contracts = vec![
            boundary.statement.clone(),
            architecture_freeze.statement.clone(),
            "A1: hash binding for ValueCommitmentV2 and statement_digest on the frozen observable boundary.".to_string(),
            "A2: ROM programmability for the MS Fiat-Shamir interface on the frozen observable boundary.".to_string(),
            MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
            MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT.to_string(),
            MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT.to_string(),
            MS_SCHNORR_REPARAMETERIZATION_CONTRACT.to_string(),
            format!(
                "A4: LE Set B HVZK / ROM bound with eta={}, gamma={}, beta={}, c_poly_size={}, c_poly_span={}.",
                le_constraint_analysis.eta,
                le_constraint_analysis.gamma,
                le_constraint_analysis.beta,
                le_constraint_analysis.c_poly_size,
                le_constraint_analysis.c_poly_span
            ),
        ];
        let output_bound = AdvantageBound {
            symbol: "epsilon_qssm".to_string(),
            expression:
                "Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le"
                    .to_string(),
            numeric_upper_bound: None,
            dependencies: vec![
                "A1 -> epsilon_ms_hash_binding".to_string(),
                "A2 -> epsilon_ms_rom_programmability".to_string(),
                "A4 -> epsilon_le".to_string(),
            ],
            epsilon_dependencies: vec![
                "epsilon_ms_hash_binding".to_string(),
                "epsilon_ms_rom_programmability".to_string(),
                "epsilon_le".to_string(),
            ],
            justification:
                "The closed theorem consumes only the explicitly declared A1/A2/A4 assumption graph and the internal lemma chain MS-1 -> MS-2 -> MS-3a -> MS-3b -> MS-3c -> H0_to_H1 -> H1_to_H2 -> H2_to_H3 -> composed_boundary_additivity."
                    .to_string(),
        };
        let closure_report = proof_closure_report_for_closed_theorem(
            &architecture_freeze,
            &assumption_graph,
            &internal_lemma_chain,
            &game_based_proof,
            &premise_contracts,
            &output_bound,
            &theorem_statement,
        );

        assert!(
            closure_report.closed,
            "closed theorem failed proof closure checker: {:?}",
            closure_report.issues
        );

        Self {
            name: "QSSM closed ZK theorem (MS v2 Option B + LE Set B)".to_string(),
            claim_type: ClaimType::ZeroKnowledge,
            status: ProofStatus::BoundedUnderAssumptions,
            architecture_freeze,
            assumption_graph,
            internal_lemma_chain,
            game_based_proof,
            premise_contracts,
            random_variables: vec![
                "T_G0 := verifier view sampled from the real joint QSSM transcript game".to_string(),
                "T_G2 := verifier view sampled from the global simulator output".to_string(),
            ],
            distributions: vec![
                "G0(real joint transcript)".to_string(),
                "G1(MS simulated, LE real)".to_string(),
                "G2(global simulator output)".to_string(),
            ],
            advantage_functions: vec![
                "Adv_G0_G1(D) = |Pr[D(T_G0)=1] - Pr[D(T_G1)=1]|".to_string(),
                "Adv_G1_G2(D) = |Pr[D(T_G1)=1] - Pr[D(T_G2)=1]|".to_string(),
                "Adv_QSSM(D) = |Pr[D(T_G0)=1] - Pr[D(T_G2)=1]|".to_string(),
            ],
            output_bound,
            closure_report,
            theorem_statement,
        }
    }
}

impl LeHvzkConstraintAnalysis {
    #[must_use]
    pub fn for_current_params() -> Self {
        let epsilon_log2 = -128.0;
        let query_budget_log2 = 64.0;
        let worst_case_cr_inf_norm = le_worst_case_cr_inf_norm(BETA, C_POLY_SIZE, C_POLY_SPAN);
        let required_eta_for_hvzk = le_required_eta_for_hvzk(
            N,
            BETA,
            C_POLY_SIZE,
            C_POLY_SPAN,
            epsilon_log2,
        );
        let minimum_gamma_for_support_containment =
            le_minimum_gamma_for_support_containment(ETA, BETA, C_POLY_SIZE, C_POLY_SPAN);
        let challenge_space_log2 = le_challenge_space_log2(C_POLY_SIZE, C_POLY_SPAN);
        let fs_security_bits = challenge_space_log2 - query_budget_log2;

        Self {
            claim_type: ClaimType::ZeroKnowledge,
            epsilon_log2,
            query_budget_log2,
            n: N,
            beta: BETA,
            eta: ETA,
            gamma: GAMMA,
            c_poly_size: C_POLY_SIZE,
            c_poly_span: C_POLY_SPAN,
            worst_case_cr_inf_norm,
            required_eta_for_hvzk,
            minimum_gamma_for_support_containment,
            challenge_space_log2,
            fs_security_bits,
            current_eta_shortfall: required_eta_for_hvzk - f64::from(ETA),
            current_gamma_shortfall: i64::from(GAMMA) - minimum_gamma_for_support_containment as i64,
        }
    }
}

impl CanonicalLeSetB {
    #[must_use]
    pub fn current() -> Self {
        let name = "LE Set B — balanced proof-safe template";
        let eta = ETA;
        let beta = BETA;
        let gamma = GAMMA;
        let c_poly_size = C_POLY_SIZE;
        let c_poly_span = C_POLY_SPAN;
        let notes = vec![
            "This is the committed LE configuration in the codebase.".to_string(),
            "It satisfies the encoded HVZK eta bound, the support-containment rule gamma = eta + ||cr||_inf, and the >=128-bit Fiat-Shamir margin under Q_H = 2^64.".to_string(),
        ];
        let worst_case_cr_inf_norm = le_worst_case_cr_inf_norm(beta, c_poly_size, c_poly_span);
        let required_eta_for_hvzk =
            le_required_eta_for_hvzk(N, beta, c_poly_size, c_poly_span, -128.0);
        let minimum_gamma_for_support_containment =
            le_minimum_gamma_for_support_containment(eta, beta, c_poly_size, c_poly_span);
        let challenge_space_log2 = le_challenge_space_log2(c_poly_size, c_poly_span);
        let fs_security_bits = challenge_space_log2 - 64.0;
        let satisfies_hvzk_eta = f64::from(eta) >= required_eta_for_hvzk;
        let satisfies_support_containment = u64::from(gamma) >= minimum_gamma_for_support_containment;
        let meets_128_bit_fs = fs_security_bits >= 128.0;

        Self {
            name: name.to_string(),
            eta,
            beta,
            gamma,
            c_poly_size,
            c_poly_span,
            worst_case_cr_inf_norm,
            required_eta_for_hvzk,
            minimum_gamma_for_support_containment,
            challenge_space_log2,
            fs_security_bits,
            satisfies_hvzk_eta,
            satisfies_support_containment,
            meets_128_bit_fs,
            notes,
        }
    }
}
