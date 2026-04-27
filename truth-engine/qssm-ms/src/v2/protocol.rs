use super::internals::{
    bitness_query_digest, candidate_positions, clause_bit_indices, clause_public_points,
    comparison_query_digest, decode_commitment_points, decode_scalar, decompress_point,
    hash_query_to_scalar, hash_to_scalar, highest_differing_bit_u64, pedersen_commit, pedersen_h,
    prove_bitness_bit, simulated_schnorr_announcement, ChallengeOracle, HashChallengeOracle,
    ProgrammedChallengeOracle,
};
use super::types::{
    BitnessProofV2, ComparisonClauseProofV2, ComparisonProofV2, EqualitySubproofV2,
    PredicateOnlyProofV2, PredicateOnlySimulationV2, PredicateOnlyStatementV2, PredicateWitnessV2,
    ProgrammedOracleQueryV2, ValueCommitmentV2, V2_BIT_COUNT,
};
use crate::MsError;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use subtle::ConstantTimeEq;

pub fn commit_value_v2(
    value: u64,
    seed: [u8; 32],
    binding_entropy: [u8; 32],
) -> Result<(ValueCommitmentV2, PredicateWitnessV2), MsError> {
    let mut bit_commitments = Vec::with_capacity(V2_BIT_COUNT);
    let mut blinders = Vec::with_capacity(V2_BIT_COUNT);
    for bit_index in 0..V2_BIT_COUNT {
        let bit = ((value >> bit_index) & 1) as u8;
        let index_bytes = (bit_index as u32).to_le_bytes();
        let blinder = hash_to_scalar(
            b"predicate_only_v2_blinder",
            &[seed.as_slice(), binding_entropy.as_slice(), &index_bytes],
        );
        let commitment = pedersen_commit(bit, blinder).compress().to_bytes();
        bit_commitments.push(commitment);
        blinders.push(blinder.to_bytes());
    }
    Ok((
        ValueCommitmentV2::new(bit_commitments)?,
        PredicateWitnessV2::new(value, blinders)?,
    ))
}

pub fn predicate_relation_holds_v2(
    statement: &PredicateOnlyStatementV2,
    witness: &PredicateWitnessV2,
) -> Result<bool, MsError> {
    if witness.value() <= statement.target() {
        return Ok(false);
    }
    for bit_index in 0..V2_BIT_COUNT {
        let bit = ((witness.value() >> bit_index) & 1) as u8;
        let blinder = witness.blinder_scalar(bit_index)?;
        let expected = pedersen_commit(bit, blinder).compress().to_bytes();
        if statement.commitment().bit_commitments()[bit_index]
            .ct_eq(&expected)
            .unwrap_u8()
            == 0
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn prove_predicate_only_v2(
    statement: &PredicateOnlyStatementV2,
    witness: &PredicateWitnessV2,
    prover_seed: [u8; 32],
) -> Result<PredicateOnlyProofV2, MsError> {
    if !predicate_relation_holds_v2(statement, witness)? {
        return Err(MsError::UnsatisfiedPredicateRelation);
    }

    let statement_digest = statement.statement_digest();
    let commitment_points = decode_commitment_points(statement.commitment())?;
    let bitness_proofs = (0..V2_BIT_COUNT)
        .map(|bit_index| {
            prove_bitness_bit(
                &statement_digest,
                commitment_points[bit_index],
                ((witness.value() >> bit_index) & 1) as u8,
                witness.blinder_scalar(bit_index)?,
                &prover_seed,
                bit_index,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let clause_positions = candidate_positions(statement.target());
    if clause_positions.is_empty() {
        return Err(MsError::UnsatisfiedPredicateRelation);
    }
    let Some(true_position) = highest_differing_bit_u64(witness.value(), statement.target()) else {
        return Err(MsError::UnsatisfiedPredicateRelation);
    };

    let mut clauses = Vec::with_capacity(clause_positions.len());
    let mut simulated_sum = Scalar::ZERO;
    let true_clause_index = clause_positions
        .iter()
        .position(|position| *position == true_position)
        .ok_or(MsError::UnsatisfiedPredicateRelation)?;
    let mut true_clause_alphas = Vec::<Scalar>::new();

    for (clause_index, position) in clause_positions.iter().enumerate() {
        let public_points = clause_public_points(statement, &commitment_points, *position)?;
        if clause_index == true_clause_index {
            let mut subproofs = Vec::with_capacity(public_points.len());
            true_clause_alphas.clear();
            for subproof_index in 0..public_points.len() {
                let alpha = hash_to_scalar(
                    b"predicate_only_v2_true_clause_alpha",
                    &[
                        statement_digest.as_slice(),
                        prover_seed.as_slice(),
                        &(clause_index as u32).to_le_bytes(),
                        &(subproof_index as u32).to_le_bytes(),
                    ],
                );
                let announcement = (alpha * pedersen_h()).compress().to_bytes();
                subproofs.push(EqualitySubproofV2 {
                    announcement,
                    response: [0u8; 32],
                });
                true_clause_alphas.push(alpha);
            }
            clauses.push(ComparisonClauseProofV2 {
                challenge_share: [0u8; 32],
                subproofs,
            });
        } else {
            let challenge_share = hash_to_scalar(
                b"predicate_only_v2_sim_clause_challenge",
                &[
                    statement_digest.as_slice(),
                    prover_seed.as_slice(),
                    &(clause_index as u32).to_le_bytes(),
                ],
            );
            simulated_sum += challenge_share;
            let mut subproofs = Vec::with_capacity(public_points.len());
            for (subproof_index, point) in public_points.iter().enumerate() {
                let response = hash_to_scalar(
                    b"predicate_only_v2_sim_clause_response",
                    &[
                        statement_digest.as_slice(),
                        prover_seed.as_slice(),
                        &(clause_index as u32).to_le_bytes(),
                        &(subproof_index as u32).to_le_bytes(),
                    ],
                );
                let announcement =
                    simulated_schnorr_announcement(*point, response, challenge_share);
                subproofs.push(EqualitySubproofV2 {
                    announcement,
                    response: response.to_bytes(),
                });
            }
            clauses.push(ComparisonClauseProofV2 {
                challenge_share: challenge_share.to_bytes(),
                subproofs,
            });
        }
    }

    let comparison_query = comparison_query_digest(&statement_digest, &clauses);
    let comparison_challenge = hash_query_to_scalar(&comparison_query);
    let true_challenge = comparison_challenge - simulated_sum;
    let true_position = clause_positions[true_clause_index];
    let true_indices = clause_bit_indices(true_position);
    let mut true_subproofs = Vec::with_capacity(true_indices.len());
    for (subproof_index, bit_index) in true_indices.iter().enumerate() {
        let response = true_clause_alphas[subproof_index]
            + true_challenge * witness.blinder_scalar(*bit_index as usize)?;
        true_subproofs.push(EqualitySubproofV2 {
            announcement: clauses[true_clause_index].subproofs[subproof_index].announcement,
            response: response.to_bytes(),
        });
    }
    clauses[true_clause_index] = ComparisonClauseProofV2 {
        challenge_share: true_challenge.to_bytes(),
        subproofs: true_subproofs,
    };

    Ok(PredicateOnlyProofV2 {
        result: true,
        statement_digest,
        bitness_proofs,
        comparison_proof: ComparisonProofV2 { clauses },
    })
}

pub fn verify_predicate_only_v2(
    statement: &PredicateOnlyStatementV2,
    proof: &PredicateOnlyProofV2,
) -> Result<bool, MsError> {
    verify_predicate_only_v2_inner(statement, proof, &HashChallengeOracle)
}

pub fn simulate_predicate_only_v2(
    statement: &PredicateOnlyStatementV2,
    simulator_seed: [u8; 32],
) -> Result<PredicateOnlySimulationV2, MsError> {
    let statement_digest = statement.statement_digest();
    let commitment_points = decode_commitment_points(statement.commitment())?;
    let mut programmed_queries = Vec::with_capacity(V2_BIT_COUNT + 1);
    let mut bitness_proofs = Vec::with_capacity(V2_BIT_COUNT);

    for (bit_index, commitment) in commitment_points
        .iter()
        .copied()
        .enumerate()
        .take(V2_BIT_COUNT)
    {
        let point_zero = commitment;
        let point_one = commitment - RISTRETTO_BASEPOINT_POINT;
        let challenge_zero = hash_to_scalar(
            b"predicate_only_v2_sim_bit_c0",
            &[
                statement_digest.as_slice(),
                simulator_seed.as_slice(),
                &(bit_index as u32).to_le_bytes(),
            ],
        );
        let challenge_one = hash_to_scalar(
            b"predicate_only_v2_sim_bit_c1",
            &[
                statement_digest.as_slice(),
                simulator_seed.as_slice(),
                &(bit_index as u32).to_le_bytes(),
                b"one",
            ],
        );
        let response_zero = hash_to_scalar(
            b"predicate_only_v2_sim_bit_z0",
            &[
                statement_digest.as_slice(),
                simulator_seed.as_slice(),
                &(bit_index as u32).to_le_bytes(),
            ],
        );
        let response_one = hash_to_scalar(
            b"predicate_only_v2_sim_bit_z1",
            &[
                statement_digest.as_slice(),
                simulator_seed.as_slice(),
                &(bit_index as u32).to_le_bytes(),
                b"one",
            ],
        );
        let announce_zero =
            simulated_schnorr_announcement(point_zero, response_zero, challenge_zero);
        let announce_one = simulated_schnorr_announcement(point_one, response_one, challenge_one);
        let query_digest =
            bitness_query_digest(&statement_digest, bit_index, &announce_zero, &announce_one);
        programmed_queries.push(ProgrammedOracleQueryV2 {
            query_digest,
            challenge: (challenge_zero + challenge_one).to_bytes(),
        });
        bitness_proofs.push(BitnessProofV2 {
            announce_zero,
            announce_one,
            challenge_zero: challenge_zero.to_bytes(),
            challenge_one: challenge_one.to_bytes(),
            response_zero: response_zero.to_bytes(),
            response_one: response_one.to_bytes(),
        });
    }

    let clause_positions = candidate_positions(statement.target());
    let mut clauses = Vec::with_capacity(clause_positions.len());
    let mut comparison_challenge = Scalar::ZERO;
    for (clause_index, position) in clause_positions.iter().enumerate() {
        let public_points = clause_public_points(statement, &commitment_points, *position)?;
        let challenge_share = hash_to_scalar(
            b"predicate_only_v2_sim_cmp_ck",
            &[
                statement_digest.as_slice(),
                simulator_seed.as_slice(),
                &(clause_index as u32).to_le_bytes(),
            ],
        );
        comparison_challenge += challenge_share;
        let mut subproofs = Vec::with_capacity(public_points.len());
        for (subproof_index, point) in public_points.iter().enumerate() {
            let response = hash_to_scalar(
                b"predicate_only_v2_sim_cmp_z",
                &[
                    statement_digest.as_slice(),
                    simulator_seed.as_slice(),
                    &(clause_index as u32).to_le_bytes(),
                    &(subproof_index as u32).to_le_bytes(),
                ],
            );
            let announcement = simulated_schnorr_announcement(*point, response, challenge_share);
            subproofs.push(EqualitySubproofV2 {
                announcement,
                response: response.to_bytes(),
            });
        }
        clauses.push(ComparisonClauseProofV2 {
            challenge_share: challenge_share.to_bytes(),
            subproofs,
        });
    }

    let comparison_query = comparison_query_digest(&statement_digest, &clauses);
    programmed_queries.push(ProgrammedOracleQueryV2 {
        query_digest: comparison_query,
        challenge: comparison_challenge.to_bytes(),
    });

    Ok(PredicateOnlySimulationV2 {
        proof: PredicateOnlyProofV2 {
            result: true,
            statement_digest,
            bitness_proofs,
            comparison_proof: ComparisonProofV2 { clauses },
        },
        programmed_queries,
    })
}

pub fn verify_predicate_only_v2_with_programming(
    statement: &PredicateOnlyStatementV2,
    simulation: &PredicateOnlySimulationV2,
) -> Result<bool, MsError> {
    verify_predicate_only_v2_inner(
        statement,
        simulation.proof(),
        &ProgrammedChallengeOracle {
            queries: simulation.programmed_queries(),
        },
    )
}

fn verify_predicate_only_v2_inner(
    statement: &PredicateOnlyStatementV2,
    proof: &PredicateOnlyProofV2,
    oracle: &dyn ChallengeOracle,
) -> Result<bool, MsError> {
    if !proof.result {
        return Err(MsError::UnsatisfiedPredicateRelation);
    }
    let statement_digest = statement.statement_digest();
    if statement_digest.ct_eq(proof.statement_digest()).unwrap_u8() == 0 {
        return Err(MsError::InvalidV2ProofField("statement digest mismatch"));
    }

    let commitments = decode_commitment_points(statement.commitment())?;
    if proof.bitness_proofs.len() != V2_BIT_COUNT {
        return Err(MsError::InvalidV2ProofField(
            "bitness proof count must match commitment bit count",
        ));
    }

    for (bit_index, bitness) in proof.bitness_proofs.iter().enumerate() {
        let announce_zero = decompress_point(&bitness.announce_zero)?;
        let announce_one = decompress_point(&bitness.announce_one)?;
        let challenge_zero = decode_scalar(&bitness.challenge_zero)?;
        let challenge_one = decode_scalar(&bitness.challenge_one)?;
        let response_zero = decode_scalar(&bitness.response_zero)?;
        let response_one = decode_scalar(&bitness.response_one)?;
        let query_digest = bitness_query_digest(
            &statement_digest,
            bit_index,
            &bitness.announce_zero,
            &bitness.announce_one,
        );
        let expected = oracle.challenge(&query_digest)?;
        if challenge_zero + challenge_one != expected {
            return Err(MsError::InvalidV2ProofField(
                "bitness challenge split does not match oracle challenge",
            ));
        }

        let point_zero = commitments[bit_index];
        let point_one = commitments[bit_index] - RISTRETTO_BASEPOINT_POINT;
        if announce_zero != response_zero * pedersen_h() - challenge_zero * point_zero {
            return Err(MsError::InvalidV2ProofField(
                "bitness zero branch failed verification",
            ));
        }
        if announce_one != response_one * pedersen_h() - challenge_one * point_one {
            return Err(MsError::InvalidV2ProofField(
                "bitness one branch failed verification",
            ));
        }
    }

    let clause_positions = candidate_positions(statement.target());
    if proof.comparison_proof.clauses.len() != clause_positions.len() {
        return Err(MsError::InvalidV2ProofField(
            "comparison clause count does not match target candidate positions",
        ));
    }

    let comparison_query =
        comparison_query_digest(&statement_digest, &proof.comparison_proof.clauses);
    let expected_challenge = oracle.challenge(&comparison_query)?;
    let actual_challenge = proof.comparison_proof.global_challenge()?;
    if actual_challenge != expected_challenge {
        return Err(MsError::InvalidV2ProofField(
            "comparison challenge split does not match oracle challenge",
        ));
    }

    for (clause_index, position) in clause_positions.iter().enumerate() {
        let public_points = clause_public_points(statement, &commitments, *position)?;
        let clause = &proof.comparison_proof.clauses[clause_index];
        if clause.subproofs.len() != public_points.len() {
            return Err(MsError::InvalidV2ProofField(
                "comparison clause subproof count mismatch",
            ));
        }
        let challenge_share = decode_scalar(&clause.challenge_share)?;
        for (subproof, point) in clause.subproofs.iter().zip(public_points.iter()) {
            let announcement = decompress_point(&subproof.announcement)?;
            let response = decode_scalar(&subproof.response)?;
            if announcement != response * pedersen_h() - challenge_share * *point {
                return Err(MsError::InvalidV2ProofField(
                    "comparison subproof failed verification",
                ));
            }
        }
    }

    Ok(true)
}
