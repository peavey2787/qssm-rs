use super::*;

pub fn honest_zk_theorem_for_current_system() -> Result<HonestZkTheorem, ZkSimulationError> {
    let ms_attempt = attempt_ms_witness_free_simulator(
        &MsHiddenValuePublicInput {
            commitment_bit_points: Vec::new(),
            target: 21,
            binding_entropy: [7u8; 32],
            binding_context: [9u8; 32],
            context: b"age_gate_21".to_vec(),
        },
        SimulationStrategy::ProgramSimulation,
    );
    let le_attempt = attempt_le_witness_free_simulator(SimulatorOnly::new(&LePublicInput {
        vk: VerifyingKey::from_seed([11u8; 32]),
        public: PublicInstance::from_u64_nibbles(42),
        binding_context: [13u8; 32],
    }))?;

    Ok(HonestZkTheorem {
        claim_type: ClaimType::ZeroKnowledge,
        theorem_statement:
            "Under the frozen visible transcript surfaces, the current deployed stack still lacks a complete end-to-end ZK theorem because the current MS hidden-value transcript exposes witness-dependent visible outputs. The LE layer is now committed to the proof-safe Set B regime, where the executable ROM transcript construction matches the encoded HVZK parameter template."
                .to_string(),
        honest_status:
            "MS structural blocker remains on the current hidden-value transcript; LE Set B is aligned with the proof-safe parameter template; the publishable path is to switch to the canonical MS v2 predicate-only transcript and complete the composed reduction."
                .to_string(),
        ms_attempt,
        le_attempt,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct LeSimulationCore {
    pub transcript: SimulatedLeTranscript,
    pub algebraic_relation_holds: bool,
    pub norm_bound_holds: bool,
}

pub(crate) fn simulate_le_core(
    public_input: &LePublicInput,
    simulator_seed: Option<[u8; 32]>,
    commitment_label: &[u8],
    z_label: &[u8],
    challenge_label: &[u8],
) -> Result<LeSimulationCore, ZkSimulationError> {
    let rejection = RejectionSamplingClaim::for_current_params();
    if !rejection.meets_hvzk_requirement() {
        return Err(ZkSimulationError::TheoremInvariant(format!(
            "LE Set B does not satisfy the encoded HVZK template: eta={} < required≈{:.0}",
            rejection.eta, rejection.required_eta_for_hvzk
        )));
    }

    let sampled_r = match simulator_seed {
        Some(seed) => sample_centered_vec_with_seed(
            commitment_label,
            public_input.binding_context,
            seed,
            BETA,
        ),
        None => sample_centered_vec(commitment_label, public_input.binding_context, BETA),
    };
    let commitment_r = short_vec_to_rq(&sampled_r)?;
    let a = public_input.vk.matrix_a_poly();
    let mu = le_mu_from_public(&public_input.public);
    let commitment_poly = a.mul(&commitment_r)?.add(&mu);
    let commitment = Commitment(commitment_poly);

    let z_arr = match simulator_seed {
        Some(seed) => {
            sample_centered_vec_with_seed(z_label, public_input.binding_context, seed, GAMMA)
        }
        None => sample_centered_vec(z_label, public_input.binding_context, GAMMA),
    };
    let z = short_vec_to_rq_bound(&z_arr, GAMMA)?;
    let fs_public_bytes = le_public_binding_fs_bytes(&public_input.public);
    let challenge_seed = FiatShamirOracle::le_challenge_seed(
        DOMAIN_ZK_SIM,
        challenge_label,
        simulator_seed.as_ref(),
        &public_input.binding_context,
        &public_input.vk,
        &fs_public_bytes,
        &commitment,
    );
    let c_poly = le_challenge_poly(&challenge_seed);
    let c_rq = le_challenge_poly_to_rq(&c_poly);
    let u = commitment.0.sub(&mu);
    let az = a.mul(&z)?;
    let cu = c_rq.mul(&u)?;
    let t = az.sub(&cu);
    let programmed_oracle_query_digest = le_fs_programmed_query_digest(
        &public_input.binding_context,
        &public_input.vk,
        &public_input.public,
        &commitment,
        &t,
    );

    let algebraic_relation_holds = a.mul(&z)? == t.add(&c_rq.mul(&u)?);
    let norm_bound_holds = z.inf_norm_centered() <= GAMMA;
    if !algebraic_relation_holds || !norm_bound_holds {
        return Err(ZkSimulationError::TheoremInvariant(
            "LE global simulator emitted a transcript that violates the programmed algebraic relation or gamma bound."
                .to_string(),
        ));
    }

    Ok(LeSimulationCore {
        transcript: SimulatedLeTranscript {
            commitment_coeffs: commitment.0 .0.to_vec(),
            t_coeffs: t.0.to_vec(),
            z_coeffs: z.0.to_vec(),
            challenge_seed,
            programmed_oracle_query_digest,
        },
        algebraic_relation_holds,
        norm_bound_holds,
    })
}

pub fn simulate_le_transcript(
    public_input: SimulatorOnly<&LePublicInput>,
    simulator_seed: [u8; 32],
) -> Result<SimulatedLeTranscript, ZkSimulationError> {
    Ok(simulate_le_core(
        public_input.into_inner(),
        Some(simulator_seed),
        b"le_global_sim_commitment_short",
        b"le_global_sim_z",
        b"le_global_sim_challenge_seed",
    )?
    .transcript)
}

pub fn sample_real_le_transcript(
    public_input: &LePublicInput,
    le_witness_coeffs: WitnessOnly<[i32; N]>,
    prover_seed: RealProverOnly<[u8; 32]>,
) -> Result<RealLeTranscript, ZkSimulationError> {
    let witness = Witness::new(le_witness_coeffs.into_inner());
    let (commitment, proof) = prove_arithmetic(
        &public_input.vk,
        &public_input.public,
        &witness,
        &public_input.binding_context,
        prover_seed.into_inner(),
    )?;
    let verified = verify_lattice(
        &public_input.vk,
        &public_input.public,
        &commitment,
        &proof,
        &public_input.binding_context,
    )?;
    if !verified {
        return Err(ZkSimulationError::TheoremInvariant(
            "Real LE prover emitted a transcript rejected by the verifier.".to_string(),
        ));
    }

    Ok(RealLeTranscript {
        commitment_coeffs: commitment.0 .0.to_vec(),
        t_coeffs: proof.t.0.to_vec(),
        z_coeffs: proof.z.0.to_vec(),
        challenge_seed: proof.challenge_seed,
    })
}

pub fn simulate_ms_v2_transcript(
    public_input: SimulatorOnly<&MsHiddenValuePublicInput>,
    simulator_seed: [u8; 32],
) -> Result<SimulatedMsV2Transcript, ZkSimulationError> {
    let statement = ms_v2_statement_from_public_input(public_input.into_inner())?;
    let simulation = qssm_ms::simulate_predicate_only_v2(&statement, simulator_seed)?;
    let verified = qssm_ms::verify_predicate_only_v2_with_programming(&statement, &simulation)?;
    if !verified {
        return Err(ZkSimulationError::Ms(
            qssm_ms::MsError::InvalidV2ProofField(
                "programmed-oracle verifier rejected the simulated transcript",
            ),
        ));
    }
    Ok(SimulatedMsV2Transcript {
        statement_digest: *simulation.proof().statement_digest(),
        result: simulation.proof().result(),
        bitness_global_challenges: simulation.proof().bitness_global_challenges()?,
        comparison_global_challenge: simulation.proof().comparison_global_challenge()?,
        transcript_digest: simulation.proof().transcript_digest(),
    })
}

pub fn sample_real_ms_v2_transcript(
    statement: &MsPublicStatement,
    commitment_seed: [u8; 32],
) -> Result<RealMsV2Transcript, ZkSimulationError> {
    statement.validate_yes_instance()?;
    let (_public_input, statement_v2, witness_v2, prover_seed) =
        ms_v2_artifacts_from_statement(statement, commitment_seed)?;
    let proof = qssm_ms::prove_predicate_only_v2(&statement_v2, &witness_v2, prover_seed)?;
    let verified = qssm_ms::verify_predicate_only_v2(&statement_v2, &proof)?;
    if !verified {
        return Err(ZkSimulationError::Ms(
            qssm_ms::MsError::InvalidV2ProofField(
                "real MS v2 verifier rejected the prover transcript",
            ),
        ));
    }

    Ok(RealMsV2Transcript {
        statement_digest: *proof.statement_digest(),
        result: proof.result(),
        bitness_global_challenges: proof.bitness_global_challenges()?,
        comparison_global_challenge: proof.comparison_global_challenge()?,
        transcript_digest: proof.transcript_digest(),
    })
}

#[must_use]
pub fn observe_real_ms_v2_transcript(transcript: &RealMsV2Transcript) -> MsV2TranscriptObservation {
    MsV2TranscriptObservation {
        statement_digest: transcript.statement_digest,
        result: transcript.result,
        bitness_global_challenges: transcript.bitness_global_challenges.clone(),
        comparison_global_challenge: transcript.comparison_global_challenge,
        transcript_digest: transcript.transcript_digest,
    }
}

#[must_use]
pub fn observe_simulated_ms_v2_transcript(
    transcript: &SimulatedMsV2Transcript,
) -> MsV2TranscriptObservation {
    MsV2TranscriptObservation {
        statement_digest: transcript.statement_digest,
        result: transcript.result,
        bitness_global_challenges: transcript.bitness_global_challenges.clone(),
        comparison_global_challenge: transcript.comparison_global_challenge,
        transcript_digest: transcript.transcript_digest,
    }
}
