pub fn public_candidate_pairs(statement: &MsPublicStatement) -> Vec<(u8, u8)> {
    let r = binding_rotation(&statement.binding_entropy);
    let mut out = Vec::new();
    for n in 0u8..=u8::MAX {
        let rot = rot_for_nonce(r, n);
        let a_p = statement.value.wrapping_add(rot);
        let b_p = statement.target.wrapping_add(rot);
        if a_p <= b_p {
            continue;
        }
        if let Some(k) = highest_differing_bit(a_p, b_p) {
            out.push((n, k));
        }
    }
    out
}

#[must_use]
pub fn real_first_success_pair(statement: &MsPublicStatement) -> Option<(u8, u8)> {
    public_candidate_pairs(statement).into_iter().next()
}

pub fn simulate_kn_distribution(
    statement: &MsPublicStatement,
    strategy: SimulationStrategy,
) -> Result<KnSimulationArtifact, ZkSimulationError> {
    statement.validate_yes_instance()?;
    let candidates = public_candidate_pairs(statement);
    if candidates.is_empty() {
        return Err(ZkSimulationError::NoValidNoncePair);
    }

    match strategy {
        SimulationStrategy::DistributionCollapse => {
            let draw = hash_domain(
                DOMAIN_MS,
                &[
                    strategy.label(),
                    b"kn_sampler",
                    &statement.value.to_le_bytes(),
                    &statement.target.to_le_bytes(),
                    statement.binding_entropy.as_slice(),
                    statement.binding_context.as_slice(),
                    statement.context.as_slice(),
                ],
            );
            let idx = usize::from(u16::from_le_bytes([draw[0], draw[1]])) % candidates.len();
            let (n, k) = candidates[idx];
            Ok(KnSimulationArtifact {
                strategy,
                n,
                k,
                oracle_queries: 1,
                programmed_oracle_queries: 0,
            })
        }
        SimulationStrategy::ProgramSimulation => {
            let (n, k) = candidates[0];
            Ok(KnSimulationArtifact {
                strategy,
                n,
                k,
                oracle_queries: usize::from(n) + 1,
                programmed_oracle_queries: 1,
            })
        }
    }
}

pub fn simulate_commitment_opening(
    statement: &MsPublicStatement,
    strategy: SimulationStrategy,
    k: u8,
) -> Result<CommitmentOpeningArtifact, ZkSimulationError> {
    statement.validate_yes_instance()?;
    if usize::from(k) >= MS_BIT_COUNT {
        return Err(ZkSimulationError::NoValidNoncePair);
    }

    let bit_at_k = ((statement.value >> k) & 1) as u8;
    let seed = hash_domain(
        DOMAIN_MS,
        &[
            strategy.label(),
            b"opening_seed",
            &[k],
            &[bit_at_k],
            &statement.value.to_le_bytes(),
            &statement.target.to_le_bytes(),
            statement.binding_entropy.as_slice(),
            statement.binding_context.as_slice(),
            statement.context.as_slice(),
        ],
    );

    let salts: [[u8; 32]; MS_LEAF_COUNT] = std::array::from_fn(|leaf_index| {
        let idx = (leaf_index as u32).to_le_bytes();
        hash_domain(
            DOMAIN_MS,
            &[
                strategy.label(),
                b"sim_salt",
                seed.as_slice(),
                &idx,
                statement.binding_entropy.as_slice(),
                statement.binding_context.as_slice(),
            ],
        )
    });

    let mut leaves = Vec::with_capacity(MS_LEAF_COUNT);
    for i in 0u8..MS_BIT_COUNT as u8 {
        for bit in 0u8..=1 {
            let leaf_idx = 2 * usize::from(i) + usize::from(bit);
            leaves.push(ms_leaf(i, bit, &salts[leaf_idx], &statement.binding_entropy));
        }
    }

    let tree = PositionAwareTree::new(leaves)?;
    let leaf_index = 2 * usize::from(k) + usize::from(bit_at_k);
    let opened_salt = salts[leaf_index];
    let leaf = ms_leaf(k, bit_at_k, &opened_salt, &statement.binding_entropy);
    let path = tree.get_proof(leaf_index)?;

    Ok(CommitmentOpeningArtifact {
        strategy,
        root: tree.get_root(),
        opening: SimulatedOpening {
            leaf_index,
            bit_at_k,
            opened_salt,
            leaf,
            path,
        },
    })
}

pub fn simulate_ms_transcript(
    statement: &MsPublicStatement,
    strategy: SimulationStrategy,
) -> Result<TranscriptSimulationArtifact, ZkSimulationError> {
    let kn = simulate_kn_distribution(statement, strategy)?;
    let commitment = simulate_commitment_opening(statement, strategy, kn.k)?;
    let challenge = fs_challenge(
        &commitment.root,
        kn.n,
        kn.k,
        &statement.binding_entropy,
        statement.value,
        statement.target,
        &statement.context,
        &statement.binding_context,
    );

    Ok(TranscriptSimulationArtifact {
        transcript: SimulatedMsTranscript {
            strategy,
            root: commitment.root,
            k: kn.k,
            n: kn.n,
            challenge,
            opening: commitment.opening,
        },
        kn,
    })
}

#[must_use]
pub fn observe_simulated_ms_transcript(
    transcript: &SimulatedMsTranscript,
) -> TranscriptObservation {
    TranscriptObservation {
        n: transcript.n,
        k: transcript.k,
        bit_at_k: transcript.opening.bit_at_k,
        path_len: transcript.opening.path.len(),
    }
}

fn binding_rotation(binding_entropy: &[u8; 32]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&binding_entropy[..8]);
    u64::from_le_bytes(bytes)
}

fn harness_commitment_seed(statement: &MsPublicStatement, sample_idx: u32) -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[
            b"zk_empirical_real_seed_v1",
            &sample_idx.to_le_bytes(),
            &statement.target.to_le_bytes(),
            statement.binding_entropy.as_slice(),
            statement.binding_context.as_slice(),
            statement.context.as_slice(),
        ],
    )
}

fn statement_batch_for_ms_v2_alignment() -> Vec<MsPublicStatement> {
    let cases = [
        (u64::MAX, u64::MAX ^ 1),
        (u64::MAX, u64::MAX ^ (1u64 << 7)),
        (u64::MAX - 1, (u64::MAX - 1) ^ (1u64 << 13)),
        (u64::MAX - 3, (u64::MAX - 3) ^ (1u64 << 21)),
    ];
    cases
        .into_iter()
        .enumerate()
        .map(|(sample_idx, (value, target))| {
            let case_bytes = (sample_idx as u64).to_le_bytes();
            MsPublicStatement {
                value,
                target,
                binding_entropy: hash_domain(DOMAIN_MS, &[b"zk_ms_v2_binding_entropy", &case_bytes]),
                binding_context: hash_domain(
                    DOMAIN_MS,
                    &[b"zk_ms_v2_binding_context", &case_bytes],
                ),
                context: format!("ms_v2_alignment_case_{sample_idx}").into_bytes(),
            }
        })
        .collect()
}

fn rot_for_nonce(r: u64, n: u8) -> u64 {
    let h = hash_domain(DOMAIN_MS, &[b"rot_nonce", &r.to_le_bytes(), &[n]]);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&h[..8]);
    u64::from_le_bytes(bytes)
}

fn highest_differing_bit(a: u64, b: u64) -> Option<u8> {
    let mut k: u8 = 63;
    loop {
        let bit_a = (a >> k) & 1;
        let bit_b = (b >> k) & 1;
        if bit_a != bit_b {
            return Some(k);
        }
        if k == 0 {
            return None;
        }
        k -= 1;
    }
}

fn ms_leaf(i: u8, bit: u8, salt: &[u8; 32], binding_entropy: &[u8; 32]) -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[b"leaf", &[i], &[bit], salt.as_slice(), binding_entropy],
    )
}

#[allow(clippy::too_many_arguments)]
fn fs_challenge(
    root: &[u8; 32],
    n: u8,
    k: u8,
    binding_entropy: &[u8; 32],
    value: u64,
    target: u64,
    context: &[u8],
    binding_context: &[u8; 32],
) -> [u8; 32] {
    FiatShamirOracle::ms_bitness_challenge(
        DOMAIN_MS,
        root,
        n,
        k,
        binding_entropy,
        value,
        target,
        context,
        binding_context,
    )
}

fn empirical_distance<T>(left: &[T], right: &[T]) -> EmpiricalDistributionDistance
where
    T: Ord + Clone,
{
    if left.is_empty() && right.is_empty() {
        return EmpiricalDistributionDistance {
            support_size: 0,
            l1_distance: 0.0,
            total_variation_distance: 0.0,
            max_bucket_gap: 0.0,
        };
    }

    let mut support = BTreeMap::<T, (usize, usize)>::new();
    for item in left {
        support.entry(item.clone()).or_insert((0, 0)).0 += 1;
    }
    for item in right {
        support.entry(item.clone()).or_insert((0, 0)).1 += 1;
    }

    let left_total = left.len() as f64;
    let right_total = right.len() as f64;
    let mut l1_distance = 0.0;
    let mut max_bucket_gap: f64 = 0.0;

    for (left_count, right_count) in support.values() {
        let left_prob = if left_total == 0.0 {
            0.0
        } else {
            *left_count as f64 / left_total
        };
        let right_prob = if right_total == 0.0 {
            0.0
        } else {
            *right_count as f64 / right_total
        };
        let gap = (left_prob - right_prob).abs();
        l1_distance += gap;
        max_bucket_gap = max_bucket_gap.max(gap);
    }

    EmpiricalDistributionDistance {
        support_size: support.len(),
        l1_distance,
        total_variation_distance: 0.5 * l1_distance,
        max_bucket_gap,
    }
}
