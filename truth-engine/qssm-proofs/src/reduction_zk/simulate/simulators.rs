#[must_use]
pub fn attempt_ms_witness_free_simulator(
    public_input: &MsHiddenValuePublicInput,
    strategy: SimulationStrategy,
) -> MsWitnessFreeSimulatorAttempt {
    let mut logs = vec![SimulatorLogEntry {
        step: "freeze_ms_game".to_string(),
        detail: format!(
            "Frozen visible transcript surface: {}",
            ZkGameDefinition::ms_hidden_value_game()
                .transcript_surface
                .visible_fields
                .join(", ")
        ),
        requires_witness: false,
        uses_independent_sampling: false,
        uses_random_oracle_programming: false,
    }];
    let mut failures = Vec::new();

    let strategy_note = match strategy {
        SimulationStrategy::DistributionCollapse => {
            "distribution-collapse requires a public marginal over (k, n)"
        }
        SimulationStrategy::ProgramSimulation => {
            "program simulation requires evaluating the first valid nonce crossing"
        }
    };
    logs.push(SimulatorLogEntry {
        step: "select_kn".to_string(),
        detail: format!(
            "Attempted {} using only target={}, binding entropy, binding context, and context.",
            strategy_note, public_input.target
        ),
        requires_witness: false,
        uses_independent_sampling: false,
        uses_random_oracle_programming: strategy == SimulationStrategy::ProgramSimulation,
    });
    failures.push(SimulatorFailure {
        class: FailureClass::Structural,
        location: "MS k/n selection".to_string(),
        detail:
            "The visible fields n and k depend on hidden value material through the crossing predicate; with value hidden, the simulator cannot derive or validate the required pair from public inputs alone."
                .to_string(),
    });

    logs.push(SimulatorLogEntry {
        step: "extract_bit_at_k".to_string(),
        detail:
            "Attempted to determine bit_at_k for the visible opening branch without hidden value."
                .to_string(),
        requires_witness: true,
        uses_independent_sampling: false,
        uses_random_oracle_programming: false,
    });
    failures.push(SimulatorFailure {
        class: FailureClass::Structural,
        location: "MS bit_at_k extraction".to_string(),
        detail:
            "The visible branch bit bit_at_k is a function of the hidden value at position k; under the frozen visible transcript surface it cannot be produced from public inputs alone."
                .to_string(),
    });

    logs.push(SimulatorLogEntry {
        step: "simulate_opening".to_string(),
        detail:
            "Merkle opening simulation would be conditional on already having a valid visible branch index (k, bit_at_k)."
                .to_string(),
        requires_witness: false,
        uses_independent_sampling: true,
        uses_random_oracle_programming: false,
    });
    failures.push(SimulatorFailure {
        class: FailureClass::Structural,
        location: "MS visible opening".to_string(),
        detail:
            "Even if hiding commitments allow fake roots and paths, the frozen visible opening still has to target the witness-selected branch. That branch cannot be fixed without hidden value material."
                .to_string(),
    });

    MsWitnessFreeSimulatorAttempt {
        game: ZkGameDefinition::ms_hidden_value_game(),
        strategy,
        transcript: None,
        logs,
        failures,
    }
}

#[must_use]
pub fn attempt_ms_v2_witness_free_simulator(
    public_input: SimulatorOnly<&MsHiddenValuePublicInput>,
) -> MsV2WitnessFreeSimulatorAttempt {
    let public_input = public_input.into_inner();
    let statement = match ms_v2_statement_from_public_input(public_input) {
        Ok(statement) => statement,
        Err(error) => {
            return MsV2WitnessFreeSimulatorAttempt {
                game: ZkGameDefinition::ms_v2_hidden_value_game(),
                transcript: None,
                logs: vec![SimulatorLogEntry {
                    step: "rebuild_ms_v2_statement".to_string(),
                    detail: format!("Failed to reconstruct public MS v2 statement: {error}"),
                    requires_witness: false,
                    uses_independent_sampling: false,
                    uses_random_oracle_programming: false,
                }],
                failures: vec![SimulatorFailure {
                    class: FailureClass::Structural,
                    location: "MS v2 public statement reconstruction".to_string(),
                    detail: format!("The public value commitment could not be reconstructed: {error}"),
                }],
            };
        }
    };
    let simulator_seed = hash_domain(
        DOMAIN_MS,
        &[
            b"ms_v2_theorem_simulator_seed",
            statement.statement_digest().as_slice(),
        ],
    );
    let simulation = match qssm_ms::simulate_predicate_only_v2(&statement, simulator_seed) {
        Ok(simulation) => simulation,
        Err(error) => {
            return MsV2WitnessFreeSimulatorAttempt {
                game: ZkGameDefinition::ms_v2_hidden_value_game(),
                transcript: None,
                logs: vec![SimulatorLogEntry {
                    step: "simulate_ms_v2_transcript".to_string(),
                    detail: format!("MS v2 simulator failed to synthesize a transcript: {error}"),
                    requires_witness: false,
                    uses_independent_sampling: true,
                    uses_random_oracle_programming: true,
                }],
                failures: vec![SimulatorFailure {
                    class: FailureClass::Structural,
                    location: "MS v2 simulator synthesis".to_string(),
                    detail: format!("The real simulator failed to emit a transcript: {error}"),
                }],
            };
        }
    };
    let logs = vec![
        SimulatorLogEntry {
            step: "freeze_ms_v2_game".to_string(),
            detail: format!(
                "Frozen visible transcript surface: {}",
                ZkGameDefinition::ms_v2_hidden_value_game()
                    .transcript_surface
                    .visible_fields
                    .join(", ")
            ),
            requires_witness: false,
            uses_independent_sampling: false,
            uses_random_oracle_programming: false,
        },
        SimulatorLogEntry {
            step: "rebuild_public_statement".to_string(),
            detail:
                "Reconstructed the public predicate-only statement from the value commitment, target, binding inputs, and context only."
                    .to_string(),
            requires_witness: false,
            uses_independent_sampling: false,
            uses_random_oracle_programming: false,
        },
        SimulatorLogEntry {
            step: "program_random_oracle".to_string(),
            detail:
                "Synthesized the full predicate-only transcript directly from the public statement and programmed oracle queries; the simulator does not follow the prover witness path."
                    .to_string(),
            requires_witness: false,
            uses_independent_sampling: true,
            uses_random_oracle_programming: true,
        },
    ];
    let failures = match qssm_ms::verify_predicate_only_v2_with_programming(&statement, &simulation)
    {
        Ok(true) => Vec::new(),
        Ok(false) => vec![SimulatorFailure {
            class: FailureClass::Structural,
            location: "MS v2 programmed verification".to_string(),
            detail: "The programmed-oracle verifier rejected the simulated MS v2 transcript."
                .to_string(),
        }],
        Err(error) => vec![SimulatorFailure {
            class: FailureClass::Structural,
            location: "MS v2 programmed verification".to_string(),
            detail: format!(
                "The programmed-oracle verifier rejected the simulated MS v2 transcript: {error}"
            ),
        }],
    };

    MsV2WitnessFreeSimulatorAttempt {
        game: ZkGameDefinition::ms_v2_hidden_value_game(),
        transcript: Some(SimulatedMsV2Transcript {
            statement_digest: *simulation.proof().statement_digest(),
            result: simulation.proof().result(),
            bitness_global_challenges: simulation
                .proof()
                .bitness_global_challenges()
                .expect("simulated MS v2 bitness challenges")
                .to_vec(),
            comparison_global_challenge: simulation
                .proof()
                .comparison_global_challenge()
                .expect("simulated MS v2 comparison challenge"),
            transcript_digest: simulation.proof().transcript_digest(),
        }),
        logs,
        failures,
    }
}

pub fn attempt_le_witness_free_simulator(
    public_input: SimulatorOnly<&LePublicInput>,
) -> Result<LeWitnessFreeSimulatorAttempt, ZkSimulationError> {
    let public_input = public_input.into_inner();
    let mut logs = vec![SimulatorLogEntry {
        step: "freeze_le_game".to_string(),
        detail: format!(
            "Frozen visible transcript surface: {}",
            ZkGameDefinition::le_hidden_witness_game()
                .transcript_surface
                .visible_fields
                .join(", ")
        ),
        requires_witness: false,
        uses_independent_sampling: false,
        uses_random_oracle_programming: false,
    }];

    let core = simulate_le_core(
        public_input,
        None,
        b"le_sim_commitment_short",
        b"le_sim_z",
        b"le_sim_challenge_seed",
    )?;
    logs.push(SimulatorLogEntry {
        step: "sample_commitment".to_string(),
        detail:
            "Sampled an independent short vector to instantiate a visible commitment C without using the actual witness r."
                .to_string(),
        requires_witness: false,
        uses_independent_sampling: true,
        uses_random_oracle_programming: false,
    });
    logs.push(SimulatorLogEntry {
        step: "program_random_oracle".to_string(),
        detail:
            "Programmed the Fiat-Shamir oracle at fs_challenge_bytes(binding_context, vk, public, C, t) to return the chosen challenge_seed."
                .to_string(),
        requires_witness: false,
        uses_independent_sampling: true,
        uses_random_oracle_programming: true,
    });
    let algebraic_relation_holds = core.algebraic_relation_holds;
    let norm_bound_holds = core.norm_bound_holds;

    let mut failures = Vec::new();
    let rejection = RejectionSamplingClaim::for_current_params();
    if !rejection.meets_hvzk_requirement() {
        failures.push(SimulatorFailure {
            class: FailureClass::Parametric,
            location: "LE simulation lemma: rejection-sampling closeness".to_string(),
            detail: format!(
                "The witness-free ROM transcript construction exists, but the current parameters do not meet the standard HVZK proof template encoded in the crate: eta={} < required_eta_for_hvzk≈{:.0}.",
                rejection.eta, rejection.required_eta_for_hvzk
            ),
        });
    } else {
        logs.push(SimulatorLogEntry {
            step: "check_set_b_constraints".to_string(),
            detail: format!(
                "Current LE parameters satisfy the encoded HVZK template: eta={} >= required≈{:.0}, gamma={} >= eta+||cr||_inf={}.",
                rejection.eta,
                rejection.required_eta_for_hvzk,
                rejection.gamma,
                u64::from(rejection.eta) + rejection.worst_case_cr_inf_norm,
            ),
            requires_witness: false,
            uses_independent_sampling: false,
            uses_random_oracle_programming: false,
        });
    }

    Ok(LeWitnessFreeSimulatorAttempt {
        game: ZkGameDefinition::le_hidden_witness_game(),
        transcript: Some(core.transcript),
        logs,
        failures,
        algebraic_relation_holds,
        norm_bound_holds,
    })
}

#[must_use]
pub fn observe_real_le_transcript(transcript: &RealLeTranscript) -> LeTranscriptObservation {
    LeTranscriptObservation {
        commitment_coeffs: transcript.commitment_coeffs.clone(),
        t_coeffs: transcript.t_coeffs.clone(),
        z_coeffs: transcript.z_coeffs.clone(),
        challenge_seed: transcript.challenge_seed,
    }
}

#[must_use]
pub fn observe_simulated_le_transcript(
    transcript: &SimulatedLeTranscript,
) -> LeTranscriptObservation {
    LeTranscriptObservation {
        commitment_coeffs: transcript.commitment_coeffs.clone(),
        t_coeffs: transcript.t_coeffs.clone(),
        z_coeffs: transcript.z_coeffs.clone(),
        challenge_seed: transcript.challenge_seed,
    }
}

#[must_use]
pub fn observe_real_qssm_transcript(transcript: &RealQssmTranscript) -> QssmTranscriptObservation {
    QssmTranscriptObservation {
        ms: observe_real_ms_v2_transcript(&transcript.ms),
        le: observe_real_le_transcript(&transcript.le),
    }
}

#[must_use]
pub fn observe_simulated_qssm_transcript(
    transcript: &SimulatedQssmTranscript,
) -> QssmTranscriptObservation {
    QssmTranscriptObservation {
        ms: observe_simulated_ms_v2_transcript(&transcript.ms),
        le: observe_simulated_le_transcript(&transcript.le),
    }
}

pub fn build_qssm_public_input(
    fixture: &QssmWitnessFixture,
    ms_commitment_seed: [u8; 32],
    le_public_input: LePublicInput,
) -> Result<QssmPublicInput, ZkSimulationError> {
    let (ms_public_input, _, _, _) =
        ms_v2_artifacts_from_statement(&fixture.ms_statement, ms_commitment_seed)?;
    Ok(QssmPublicInput {
        ms: ms_public_input,
        le: le_public_input,
    })
}

pub fn sample_real_qssm_transcript(
    public_input: &QssmPublicInput,
    fixture: &QssmWitnessFixture,
    ms_commitment_seed: [u8; 32],
    le_prover_seed: [u8; 32],
) -> Result<RealQssmTranscript, ZkSimulationError> {
    let (expected_ms_public_input, _, _, _) =
        ms_v2_artifacts_from_statement(&fixture.ms_statement, ms_commitment_seed)?;
    if public_input.ms != expected_ms_public_input {
        return Err(ZkSimulationError::TheoremInvariant(
            "QSSM real transcript sampler received an MS public input inconsistent with the supplied witness fixture and commitment seed."
                .to_string(),
        ));
    }

    Ok(RealQssmTranscript {
        ms: sample_real_ms_v2_transcript(&fixture.ms_statement, ms_commitment_seed)?,
        le: sample_real_le_transcript(
            &public_input.le,
            WitnessOnly::new(fixture.le_witness_coeffs),
            RealProverOnly::new(le_prover_seed),
        )?,
    })
}

pub fn sample_g1_qssm_observation(
    public_input: &QssmPublicInput,
    fixture: &QssmWitnessFixture,
    ms_simulator_seed: [u8; 32],
    le_prover_seed: [u8; 32],
) -> Result<QssmTranscriptObservation, ZkSimulationError> {
    let ms = simulate_ms_v2_transcript(SimulatorOnly::new(&public_input.ms), ms_simulator_seed)?;
    let le = sample_real_le_transcript(
        &public_input.le,
        WitnessOnly::new(fixture.le_witness_coeffs),
        RealProverOnly::new(le_prover_seed),
    )?;

    Ok(QssmTranscriptObservation {
        ms: observe_simulated_ms_v2_transcript(&ms),
        le: observe_real_le_transcript(&le),
    })
}

pub fn simulate_qssm_transcript(
    public_input: SimulatorOnly<&QssmPublicInput>,
    simulator_seed: [u8; 32],
) -> Result<SimulatedQssmTranscript, ZkSimulationError> {
    let public_input = public_input.into_inner();
    let ms_statement = ms_v2_statement_from_public_input(&public_input.ms)?;
    let ms_seed = hash_domain(
        DOMAIN_ZK_SIM,
        &[
            b"qssm_global_sim_ms_seed",
            simulator_seed.as_slice(),
            ms_statement.statement_digest().as_slice(),
        ],
    );
    let le_seed = hash_domain(
        DOMAIN_ZK_SIM,
        &[
            b"qssm_global_sim_le_seed",
            simulator_seed.as_slice(),
            public_input.le.binding_context.as_slice(),
            &public_input.le.vk.crs_seed,
        ],
    );

    Ok(SimulatedQssmTranscript {
        ms: simulate_ms_v2_transcript(SimulatorOnly::new(&public_input.ms), ms_seed)?,
        le: simulate_le_transcript(SimulatorOnly::new(&public_input.le), le_seed)?,
    })
}

