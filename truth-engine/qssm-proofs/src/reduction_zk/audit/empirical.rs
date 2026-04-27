use super::*;

pub fn run_ms_v2_empirical_alignment(
    statements: &[MsPublicStatement],
) -> Result<MsV2EmpiricalAlignmentReport, ZkSimulationError> {
    let mut real_result = Vec::with_capacity(statements.len());
    let mut sim_result = Vec::with_capacity(statements.len());
    let mut real_bitness_nibbles = Vec::new();
    let mut sim_bitness_nibbles = Vec::new();
    let mut real_bitness_byte_deltas = Vec::new();
    let mut sim_bitness_byte_deltas = Vec::new();
    let mut real_comparison_nibbles = Vec::new();
    let mut sim_comparison_nibbles = Vec::new();
    let mut real_comparison_byte_deltas = Vec::new();
    let mut sim_comparison_byte_deltas = Vec::new();
    let mut real_transcript_digest_nibbles = Vec::new();
    let mut sim_transcript_digest_nibbles = Vec::new();
    let mut real_transcript_digest_byte_deltas = Vec::new();
    let mut sim_transcript_digest_byte_deltas = Vec::new();
    let mut real_bitness_bytes_all = Vec::new();
    let mut sim_bitness_bytes_all = Vec::new();
    let mut real_comparison_bytes_all = Vec::new();
    let mut sim_comparison_bytes_all = Vec::new();
    let mut real_transcript_digest_bytes_all = Vec::new();
    let mut sim_transcript_digest_bytes_all = Vec::new();
    let mut real_challenge_prefixes = Vec::new();
    let mut real_digest_prefixes = Vec::new();
    let mut hidden_gap_bit_conditions = Vec::new();
    let mut hidden_gap_bit_outcomes = Vec::new();
    let mut hidden_lsb_conditions = Vec::new();
    let mut hidden_lsb_outcomes = Vec::new();
    let mut hidden_hamming_weight_conditions = Vec::new();
    let mut hidden_hamming_weight_outcomes = Vec::new();

    for (sample_idx, statement) in statements.iter().enumerate() {
        let seed = harness_commitment_seed(statement, sample_idx as u32);
        let (public_input, _statement_v2, _witness_v2, _prover_seed) =
            ms_v2_artifacts_from_statement(statement, seed)?;
        let real = sample_real_ms_v2_transcript(statement, seed)?;
        let simulator_seed = hash_domain(
            DOMAIN_MS,
            &[
                b"zk_empirical_ms_v2_sim_seed",
                &seed,
                &statement.target.to_le_bytes(),
                statement.binding_context.as_slice(),
            ],
        );
        let sim = simulate_ms_v2_transcript(SimulatorOnly::new(&public_input), simulator_seed)?;
        let real_obs = observe_real_ms_v2_transcript(&real);
        let sim_obs = observe_simulated_ms_v2_transcript(&sim);
        let real_bitness_bytes = flatten_digest_bytes(&real_obs.bitness_global_challenges);
        let sim_bitness_bytes = flatten_digest_bytes(&sim_obs.bitness_global_challenges);
        let real_bitness_nibbles_local = byte_nibbles(&real_bitness_bytes);
        let sim_bitness_nibbles_local = byte_nibbles(&sim_bitness_bytes);
        let real_comparison_nibbles_local = byte_nibbles(&real_obs.comparison_global_challenge);
        let sim_comparison_nibbles_local = byte_nibbles(&sim_obs.comparison_global_challenge);
        let real_digest_nibbles_local = byte_nibbles(&real_obs.transcript_digest);
        let sim_digest_nibbles_local = byte_nibbles(&sim_obs.transcript_digest);
        let hidden_gap_bit = ms_v2_hidden_gap_bit(statement);
        let hidden_lsb = (statement.value & 1) as u8;
        let hidden_weight_bucket = ms_v2_hidden_hamming_weight_bucket(statement.value);

        real_result.push(real_obs.result);
        sim_result.push(sim_obs.result);
        real_bitness_bytes_all.extend(real_bitness_bytes.iter().copied());
        sim_bitness_bytes_all.extend(sim_bitness_bytes.iter().copied());
        real_bitness_nibbles.extend(real_bitness_nibbles_local.iter().copied());
        sim_bitness_nibbles.extend(sim_bitness_nibbles_local.iter().copied());
        real_bitness_byte_deltas.extend(adjacent_byte_deltas(&real_bitness_bytes));
        sim_bitness_byte_deltas.extend(adjacent_byte_deltas(&sim_bitness_bytes));
        real_comparison_bytes_all.extend(real_obs.comparison_global_challenge.iter().copied());
        sim_comparison_bytes_all.extend(sim_obs.comparison_global_challenge.iter().copied());
        real_comparison_nibbles.extend(real_comparison_nibbles_local.iter().copied());
        sim_comparison_nibbles.extend(sim_comparison_nibbles_local.iter().copied());
        real_comparison_byte_deltas
            .extend(adjacent_byte_deltas(&real_obs.comparison_global_challenge));
        sim_comparison_byte_deltas
            .extend(adjacent_byte_deltas(&sim_obs.comparison_global_challenge));
        real_transcript_digest_bytes_all.extend(real_obs.transcript_digest.iter().copied());
        sim_transcript_digest_bytes_all.extend(sim_obs.transcript_digest.iter().copied());
        real_transcript_digest_nibbles.extend(real_digest_nibbles_local.iter().copied());
        sim_transcript_digest_nibbles.extend(sim_digest_nibbles_local.iter().copied());
        real_transcript_digest_byte_deltas
            .extend(adjacent_byte_deltas(&real_obs.transcript_digest));
        sim_transcript_digest_byte_deltas.extend(adjacent_byte_deltas(&sim_obs.transcript_digest));
        real_challenge_prefixes.extend(real_comparison_nibbles_local.iter().copied());
        real_digest_prefixes.extend(real_digest_nibbles_local.iter().copied());
        hidden_gap_bit_conditions.extend(std::iter::repeat_n(
            hidden_gap_bit,
            real_comparison_nibbles_local.len(),
        ));
        hidden_gap_bit_outcomes.extend(real_comparison_nibbles_local.iter().copied());
        hidden_lsb_conditions.extend(std::iter::repeat_n(
            hidden_lsb,
            real_digest_nibbles_local.len(),
        ));
        hidden_lsb_outcomes.extend(real_digest_nibbles_local.iter().copied());
        hidden_hamming_weight_conditions.extend(std::iter::repeat_n(
            hidden_weight_bucket,
            real_bitness_nibbles_local.len(),
        ));
        hidden_hamming_weight_outcomes.extend(real_bitness_nibbles_local.iter().copied());
    }

    let bitness_nibble_distance = empirical_distance(&real_bitness_nibbles, &sim_bitness_nibbles);
    let comparison_nibble_distance =
        empirical_distance(&real_comparison_nibbles, &sim_comparison_nibbles);
    let transcript_digest_nibble_distance = empirical_distance(
        &real_transcript_digest_nibbles,
        &sim_transcript_digest_nibbles,
    );
    let bitness_nibble_divergence =
        smoothed_divergence(&real_bitness_nibbles, &sim_bitness_nibbles);
    let bitness_byte_delta_divergence =
        smoothed_divergence(&real_bitness_byte_deltas, &sim_bitness_byte_deltas);
    let comparison_byte_delta_divergence =
        smoothed_divergence(&real_comparison_byte_deltas, &sim_comparison_byte_deltas);
    let transcript_digest_byte_delta_divergence = smoothed_divergence(
        &real_transcript_digest_byte_deltas,
        &sim_transcript_digest_byte_deltas,
    );
    let overall_js_upper_bound_bits = bitness_nibble_divergence
        .jensen_shannon_bits
        .max(bitness_byte_delta_divergence.jensen_shannon_bits)
        .max(comparison_byte_delta_divergence.jensen_shannon_bits)
        .max(transcript_digest_byte_delta_divergence.jensen_shannon_bits);

    Ok(MsV2EmpiricalAlignmentReport {
        sample_count: statements.len(),
        result_distance: empirical_distance(&real_result, &sim_result),
        statistical_layer: MsV2StatisticalDistinguisherLayer {
            bitness_challenge_nibble_distance: bitness_nibble_distance,
            comparison_challenge_nibble_distance: comparison_nibble_distance,
            transcript_digest_nibble_distance,
            bitness_byte_correlation: byte_correlation_estimate(
                &real_bitness_bytes_all,
                &sim_bitness_bytes_all,
                &real_bitness_byte_deltas,
                &sim_bitness_byte_deltas,
            ),
            comparison_byte_correlation: byte_correlation_estimate(
                &real_comparison_bytes_all,
                &sim_comparison_bytes_all,
                &real_comparison_byte_deltas,
                &sim_comparison_byte_deltas,
            ),
            transcript_digest_byte_correlation: byte_correlation_estimate(
                &real_transcript_digest_bytes_all,
                &sim_transcript_digest_bytes_all,
                &real_transcript_digest_byte_deltas,
                &sim_transcript_digest_byte_deltas,
            ),
            bitness_challenge_entropy: entropy_estimate(
                &real_bitness_nibbles,
                &sim_bitness_nibbles,
            ),
            comparison_challenge_entropy: entropy_estimate(
                &real_comparison_nibbles,
                &sim_comparison_nibbles,
            ),
            transcript_digest_entropy: entropy_estimate(
                &real_transcript_digest_nibbles,
                &sim_transcript_digest_nibbles,
            ),
            challenge_to_digest_prefix_bias: conditional_leakage(
                &real_challenge_prefixes,
                &real_digest_prefixes,
                "comparison_challenge_nibble",
                "transcript_digest_nibble",
            ),
            notes: vec![
                "Statistical layer keeps nibble histograms, adds adjacent-byte correlation and byte-delta checks, estimates transcript entropy, and measures observable challenge-to-digest conditional bias on the frozen MS v2 boundary.".to_string(),
                "Response coordinates are not exposed through the frozen qssm_ms API, so transcript-digest nibbles are used as the stable observable proxy for conditional bias tests.".to_string(),
            ],
        },
        structure_layer: MsV2StructureDistinguisherLayer {
            hidden_gap_bit_to_comparison_nibble_bias: conditional_leakage(
                &hidden_gap_bit_conditions,
                &hidden_gap_bit_outcomes,
                "hidden_gap_bit",
                "comparison_challenge_nibble",
            ),
            hidden_value_lsb_to_digest_nibble_bias: conditional_leakage(
                &hidden_lsb_conditions,
                &hidden_lsb_outcomes,
                "hidden_value_lsb",
                "transcript_digest_nibble",
            ),
            hidden_hamming_weight_bucket_to_bitness_nibble_bias: conditional_leakage(
                &hidden_hamming_weight_conditions,
                &hidden_hamming_weight_outcomes,
                "hidden_hamming_weight_bucket",
                "bitness_challenge_nibble",
            ),
            notes: vec![
                "Structure layer probes witness-correlated hidden features against the frozen observable surface to catch residual leakage patterns even when the classical variables k, n, and bit_at_k are absent.".to_string(),
            ],
        },
        simulator_gap_layer: MsV2SimulatorGapLayer {
            bitness_challenge_nibble_divergence: bitness_nibble_divergence,
            bitness_byte_delta_divergence,
            comparison_byte_delta_divergence,
            transcript_digest_byte_delta_divergence,
            overall_js_upper_bound_bits,
            notes: vec![
                "Simulator-gap layer uses smoothed KL / Jensen-Shannon approximations over observable nibble and byte-delta projections rather than only total-variation histograms.".to_string(),
            ],
        },
        notes: vec![
            "MS v2 interface and transcript-access surface are treated as frozen in this crate; the distinguisher suite works strictly over frozen observable projections.".to_string(),
            "The empirical suite is still evidence, not a proof: it sharpens leakage and simulator-gap detection while the full ROM reduction remains a formal obligation.".to_string(),
        ],
    })
}

pub(crate) fn ms_v2_statement_from_public_input(
    public_input: &MsHiddenValuePublicInput,
) -> Result<qssm_ms::PredicateOnlyStatementV2, ZkSimulationError> {
    let commitment = qssm_ms::ValueCommitmentV2::new(public_input.commitment_bit_points.clone())?;
    Ok(qssm_ms::PredicateOnlyStatementV2::new(
        commitment,
        public_input.target,
        public_input.binding_entropy,
        public_input.binding_context,
        public_input.context.clone(),
    ))
}

pub(crate) fn ms_v2_artifacts_from_statement(
    statement: &MsPublicStatement,
    commitment_seed: [u8; 32],
) -> Result<
    (
        MsHiddenValuePublicInput,
        qssm_ms::PredicateOnlyStatementV2,
        qssm_ms::PredicateWitnessV2,
        [u8; 32],
    ),
    ZkSimulationError,
> {
    let (commitment, witness) =
        qssm_ms::commit_value_v2(statement.value, commitment_seed, statement.binding_entropy)?;
    let public_input = MsHiddenValuePublicInput {
        commitment_bit_points: commitment.bit_commitments().to_vec(),
        target: statement.target,
        binding_entropy: statement.binding_entropy,
        binding_context: statement.binding_context,
        context: statement.context.clone(),
    };
    let statement_v2 = qssm_ms::PredicateOnlyStatementV2::new(
        commitment,
        statement.target,
        statement.binding_entropy,
        statement.binding_context,
        statement.context.clone(),
    );
    let prover_seed = hash_domain(
        DOMAIN_MS,
        &[
            b"zk_empirical_ms_v2_prover_seed",
            &commitment_seed,
            statement_v2.statement_digest().as_slice(),
        ],
    );
    Ok((public_input, statement_v2, witness, prover_seed))
}

fn flatten_digest_bytes(digests: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(digests.len() * 32);
    for digest in digests {
        out.extend(digest);
    }
    out
}

fn byte_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(byte >> 4);
        out.push(byte & 0x0f);
    }
    out
}

fn adjacent_byte_deltas(bytes: &[u8]) -> Vec<u8> {
    bytes
        .windows(2)
        .map(|window| window[1].wrapping_sub(window[0]))
        .collect()
}

fn byte_correlation_estimate(
    real_bytes: &[u8],
    simulated_bytes: &[u8],
    real_deltas: &[u8],
    simulated_deltas: &[u8],
) -> ByteCorrelationEstimate {
    let real_adjacent_correlation = adjacent_byte_correlation(real_bytes);
    let simulated_adjacent_correlation = adjacent_byte_correlation(simulated_bytes);
    ByteCorrelationEstimate {
        real_adjacent_correlation,
        simulated_adjacent_correlation,
        correlation_gap: (real_adjacent_correlation - simulated_adjacent_correlation).abs(),
        delta_distance: empirical_distance(real_deltas, simulated_deltas),
    }
}

fn adjacent_byte_correlation(bytes: &[u8]) -> f64 {
    if bytes.len() < 2 {
        return 0.0;
    }

    let left: Vec<f64> = bytes[..bytes.len() - 1]
        .iter()
        .map(|byte| f64::from(*byte))
        .collect();
    let right: Vec<f64> = bytes[1..].iter().map(|byte| f64::from(*byte)).collect();
    let mean_left = left.iter().sum::<f64>() / left.len() as f64;
    let mean_right = right.iter().sum::<f64>() / right.len() as f64;
    let mut covariance = 0.0;
    let mut variance_left = 0.0;
    let mut variance_right = 0.0;
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        let centered_left = lhs - mean_left;
        let centered_right = rhs - mean_right;
        covariance += centered_left * centered_right;
        variance_left += centered_left * centered_left;
        variance_right += centered_right * centered_right;
    }
    if variance_left == 0.0 || variance_right == 0.0 {
        return 0.0;
    }
    covariance / (variance_left.sqrt() * variance_right.sqrt())
}

fn entropy_estimate<T>(real: &[T], simulated: &[T]) -> EntropyEstimate
where
    T: Ord + Clone,
{
    let real_entropy_bits = entropy_bits(real);
    let simulated_entropy_bits = entropy_bits(simulated);
    EntropyEstimate {
        real_entropy_bits,
        simulated_entropy_bits,
        entropy_gap_bits: (real_entropy_bits - simulated_entropy_bits).abs(),
    }
}

fn smoothed_divergence<T>(real: &[T], simulated: &[T]) -> SmoothedDivergenceEstimate
where
    T: Ord + Clone,
{
    let mut support = BTreeMap::<T, (usize, usize)>::new();
    for item in real {
        support.entry(item.clone()).or_insert((0, 0)).0 += 1;
    }
    for item in simulated {
        support.entry(item.clone()).or_insert((0, 0)).1 += 1;
    }
    if support.is_empty() {
        return SmoothedDivergenceEstimate {
            support_size: 0,
            kl_real_to_sim_bits: 0.0,
            kl_sim_to_real_bits: 0.0,
            jensen_shannon_bits: 0.0,
        };
    }

    let alpha = 1.0;
    let support_size = support.len();
    let support_size_f = support_size as f64;
    let real_total = real.len() as f64;
    let simulated_total = simulated.len() as f64;
    let denom_real = real_total + alpha * support_size_f;
    let denom_sim = simulated_total + alpha * support_size_f;
    let mut kl_real_to_sim_bits = 0.0;
    let mut kl_sim_to_real_bits = 0.0;
    let mut jensen_shannon_bits = 0.0;

    for (real_count, simulated_count) in support.values() {
        let p = (*real_count as f64 + alpha) / denom_real;
        let q = (*simulated_count as f64 + alpha) / denom_sim;
        let mean = 0.5 * (p + q);
        kl_real_to_sim_bits += p * (p / q).log2();
        kl_sim_to_real_bits += q * (q / p).log2();
        jensen_shannon_bits += 0.5 * p * (p / mean).log2();
        jensen_shannon_bits += 0.5 * q * (q / mean).log2();
    }

    SmoothedDivergenceEstimate {
        support_size,
        kl_real_to_sim_bits,
        kl_sim_to_real_bits,
        jensen_shannon_bits,
    }
}

fn conditional_leakage<C, O>(
    conditions: &[C],
    outcomes: &[O],
    condition_label: &str,
    outcome_label: &str,
) -> ConditionalLeakageEstimate
where
    C: Ord + Clone,
    O: Ord + Clone,
{
    debug_assert_eq!(conditions.len(), outcomes.len());
    if conditions.is_empty() || outcomes.is_empty() {
        return ConditionalLeakageEstimate {
            condition_label: condition_label.to_string(),
            outcome_label: outcome_label.to_string(),
            condition_support_size: 0,
            outcome_support_size: 0,
            average_total_variation_distance: 0.0,
            max_total_variation_distance: 0.0,
            approx_mutual_information_bits: 0.0,
        };
    }

    let mut grouped = BTreeMap::<C, Vec<O>>::new();
    for (condition, outcome) in conditions.iter().cloned().zip(outcomes.iter().cloned()) {
        grouped.entry(condition).or_default().push(outcome);
    }

    let total = outcomes.len() as f64;
    let global_entropy = entropy_bits(outcomes);
    let mut weighted_average_tvd = 0.0;
    let mut max_total_variation_distance: f64 = 0.0;
    let mut conditional_entropy = 0.0;

    for samples in grouped.values() {
        let weight = samples.len() as f64 / total;
        let group_distance = empirical_distance(samples, outcomes);
        let group_entropy = entropy_bits(samples);
        weighted_average_tvd += weight * group_distance.total_variation_distance;
        max_total_variation_distance =
            max_total_variation_distance.max(group_distance.total_variation_distance);
        conditional_entropy += weight * group_entropy;
    }

    let outcome_support_size = {
        let mut support = BTreeMap::<O, usize>::new();
        for outcome in outcomes {
            *support.entry(outcome.clone()).or_default() += 1;
        }
        support.len()
    };

    ConditionalLeakageEstimate {
        condition_label: condition_label.to_string(),
        outcome_label: outcome_label.to_string(),
        condition_support_size: grouped.len(),
        outcome_support_size,
        average_total_variation_distance: weighted_average_tvd,
        max_total_variation_distance,
        approx_mutual_information_bits: (global_entropy - conditional_entropy).max(0.0),
    }
}

fn entropy_bits<T>(samples: &[T]) -> f64
where
    T: Ord + Clone,
{
    if samples.is_empty() {
        return 0.0;
    }

    let mut support = BTreeMap::<T, usize>::new();
    for sample in samples {
        *support.entry(sample.clone()).or_default() += 1;
    }

    let total = samples.len() as f64;
    support
        .values()
        .map(|count| {
            let probability = *count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

fn ms_v2_hidden_gap_bit(statement: &MsPublicStatement) -> u8 {
    highest_differing_bit(statement.value, statement.target)
        .expect("MS v2 alignment statements must satisfy value > target")
}

fn ms_v2_hidden_hamming_weight_bucket(value: u64) -> u8 {
    (value.count_ones() / 8) as u8
}
