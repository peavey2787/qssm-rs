use super::*;

impl RedesignedSystemsTheorem {
    pub fn for_current_and_redesigned_systems() -> Result<Self, ZkSimulationError> {
        let current_system = honest_zk_theorem_for_current_system()?;
        let canonical_ms_v2 = CanonicalMsV2TranscriptDesign::option_b();
        let ms_v2_observable_boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
        let le_constraint_analysis = LeHvzkConstraintAnalysis::for_current_params();
        let canonical_le_set_b = CanonicalLeSetB::current();
        let ms_v2_alignment =
            run_ms_v2_empirical_alignment(&statement_batch_for_ms_v2_alignment())?;
        let unified_hybrid_game = UnifiedZkHybridGame::for_canonical_option_b_and_set_b();
        let closed_zk_theorem = ClosedZkTheorem::for_current_and_redesigned_systems(
            &ms_v2_observable_boundary,
            &le_constraint_analysis,
        );
        let security_claims = vec![
            SecurityClaimRow {
                component: "MS (current)".to_string(),
                property: "Zero-knowledge under frozen hidden-value game".to_string(),
                status: ClaimStatus::NotSatisfied,
                notes: "Structural blocker: visible n, k, and bit_at_k remain witness-dependent under the current transcript surface.".to_string(),
            },
            SecurityClaimRow {
                component: "MS (v2 Option B transcript format)".to_string(),
                property: "Canonical predicate-only transcript surface".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "Implemented as a real value-commitment statement plus a witness-bound predicate proof in qssm_ms::PredicateOnlyStatementV2 / PredicateOnlyProofV2.".to_string(),
            },
            SecurityClaimRow {
                component: "MS (v2 Option B boundary contract)".to_string(),
                property: "Observable sigma-algebra is frozen".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "The frozen qssm_ms accessor surface now serves as the explicit observable-boundary contract for simulator and reduction work.".to_string(),
            },
            SecurityClaimRow {
                component: "MS (v2 Option B)".to_string(),
                property: "Simulation-based zero-knowledge bound".to_string(),
                status: ClaimStatus::Bounded,
                notes: "The MS bound is now reduction-based: epsilon_ms = epsilon_ms_hash_binding + epsilon_ms_rom_programmability, and the residual programmed transcript gap is discharged exactly by MS-3a / MS-3b / MS-3c under the frozen observable boundary contract.".to_string(),
            },
            SecurityClaimRow {
                component: "LE (Set B current params)".to_string(),
                property: "Witness-hiding".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "The current crate explicitly supports witness-hiding under the committed Set B parameters.".to_string(),
            },
            SecurityClaimRow {
                component: "LE (Set B current params)".to_string(),
                property: "HVZK parameter template".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "Current eta, gamma, and challenge shape satisfy the exact HVZK inequalities encoded in the formal crate.".to_string(),
            },
            SecurityClaimRow {
                component: "LE (Set B current params)".to_string(),
                property: "ZK (ROM) bound".to_string(),
                status: ClaimStatus::Bounded,
                notes: "The H1->H2 lemma now exposes an explicit parameter-dependent bound epsilon_le(eta,gamma,beta,c_poly_size,c_poly_span) including rejection-sampling and Fiat-Shamir terms.".to_string(),
            },
            SecurityClaimRow {
                component: "QSSM (composed Option B + Set B)".to_string(),
                property: "End-to-end zero-knowledge bound".to_string(),
                status: ClaimStatus::Bounded,
                notes: "The composed theorem is now stated as Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le under the ROM, the frozen observable boundary contract, exact MS transcript simulation, and simulator independence under shared randomness.".to_string(),
            },
            SecurityClaimRow {
                component: "QSSM security model".to_string(),
                property: "Architecture freeze and proof closure".to_string(),
                status: ClaimStatus::Satisfied,
                notes: "The final theorem is carried by a single closed cryptographic object with an A1/A2/A4 dependency graph, a static proof closure checker, and a frozen MS / LE / simulator / theorem architecture seal.".to_string(),
            },
        ];
        let theorem_statement = closed_zk_theorem.theorem_statement.clone();

        Ok(Self {
            claim_type: ClaimType::ZeroKnowledge,
            current_system,
            canonical_ms_v2,
            ms_v2_observable_boundary,
            le_constraint_analysis,
            canonical_le_set_b,
            ms_v2_alignment,
            unified_hybrid_game,
            closed_zk_theorem,
            security_claims,
            theorem_statement,
        })
    }
}
