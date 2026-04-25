use crate::MsError;
use blake3::Hasher;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use qssm_utils::{hash_domain, DOMAIN_MS};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const V2_BIT_COUNT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgrammedOracleQueryV2 {
    query_digest: [u8; 32],
    challenge: [u8; 32],
}

impl ProgrammedOracleQueryV2 {
    #[must_use]
    pub fn query_digest(&self) -> &[u8; 32] {
        &self.query_digest
    }

    #[must_use]
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueCommitmentV2 {
    bit_commitments: Vec<[u8; 32]>,
}

impl ValueCommitmentV2 {
    pub fn new(bit_commitments: Vec<[u8; 32]>) -> Result<Self, MsError> {
        if bit_commitments.len() != V2_BIT_COUNT {
            return Err(MsError::InvalidV2CommitmentField(
                "bit_commitments must contain exactly 64 compressed points",
            ));
        }
        for point in &bit_commitments {
            decompress_point(point)?;
        }
        Ok(Self { bit_commitments })
    }

    #[must_use]
    pub fn bit_commitments(&self) -> &[[u8; 32]] {
        &self.bit_commitments
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(DOMAIN_MS.as_bytes());
        hasher.update(b"predicate_only_v2_value_commitment");
        for commitment in &self.bit_commitments {
            hasher.update(commitment);
        }
        *hasher.finalize().as_bytes()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PredicateWitnessV2 {
    value: u64,
    blinders: Vec<[u8; 32]>,
}

impl std::fmt::Debug for PredicateWitnessV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PredicateWitnessV2")
            .field("value", &"[REDACTED]")
            .field("blinders", &format_args!("[{} blinders]", self.blinders.len()))
            .finish()
    }
}

impl PredicateWitnessV2 {
    fn new(value: u64, blinders: Vec<[u8; 32]>) -> Result<Self, MsError> {
        if blinders.len() != V2_BIT_COUNT {
            return Err(MsError::InvalidV2CommitmentField(
                "witness blinders must contain exactly 64 scalars",
            ));
        }
        for scalar in &blinders {
            decode_scalar(scalar)?;
        }
        Ok(Self { value, blinders })
    }

    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn blinder_scalar(&self, index: usize) -> Result<Scalar, MsError> {
        let Some(bytes) = self.blinders.get(index) else {
            return Err(MsError::InvalidV2CommitmentField(
                "witness blinder index out of range",
            ));
        };
        decode_scalar(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateOnlyStatementV2 {
    commitment: ValueCommitmentV2,
    target: u64,
    binding_entropy: [u8; 32],
    binding_context: [u8; 32],
    context: Vec<u8>,
}

impl PredicateOnlyStatementV2 {
    #[must_use]
    pub fn new(
        commitment: ValueCommitmentV2,
        target: u64,
        binding_entropy: [u8; 32],
        binding_context: [u8; 32],
        context: Vec<u8>,
    ) -> Self {
        Self {
            commitment,
            target,
            binding_entropy,
            binding_context,
            context,
        }
    }

    #[must_use]
    pub fn commitment(&self) -> &ValueCommitmentV2 {
        &self.commitment
    }

    #[must_use]
    pub fn target(&self) -> u64 {
        self.target
    }

    #[must_use]
    pub fn binding_entropy(&self) -> &[u8; 32] {
        &self.binding_entropy
    }

    #[must_use]
    pub fn binding_context(&self) -> &[u8; 32] {
        &self.binding_context
    }

    #[must_use]
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    #[must_use]
    pub fn statement_digest(&self) -> [u8; 32] {
        hash_domain(
            DOMAIN_MS,
            &[
                b"predicate_only_v2_statement",
                self.commitment.digest().as_slice(),
                &self.target.to_le_bytes(),
                self.binding_entropy.as_slice(),
                self.binding_context.as_slice(),
                self.context.as_slice(),
            ],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitnessProofV2 {
    announce_zero: [u8; 32],
    announce_one: [u8; 32],
    challenge_zero: [u8; 32],
    challenge_one: [u8; 32],
    response_zero: [u8; 32],
    response_one: [u8; 32],
}

impl BitnessProofV2 {
    fn global_challenge(&self) -> Result<Scalar, MsError> {
        Ok(decode_scalar(&self.challenge_zero)? + decode_scalar(&self.challenge_one)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqualitySubproofV2 {
    announcement: [u8; 32],
    response: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonClauseProofV2 {
    challenge_share: [u8; 32],
    subproofs: Vec<EqualitySubproofV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonProofV2 {
    clauses: Vec<ComparisonClauseProofV2>,
}

impl ComparisonProofV2 {
    fn global_challenge(&self) -> Result<Scalar, MsError> {
        self.clauses.iter().try_fold(Scalar::ZERO, |acc, clause| {
            Ok(acc + decode_scalar(&clause.challenge_share)?)
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PredicateOnlyProofV2 {
    result: bool,
    statement_digest: [u8; 32],
    bitness_proofs: Vec<BitnessProofV2>,
    comparison_proof: ComparisonProofV2,
}

impl PredicateOnlyProofV2 {
    #[must_use]
    pub fn result(&self) -> bool {
        self.result
    }

    #[must_use]
    pub fn statement_digest(&self) -> &[u8; 32] {
        &self.statement_digest
    }

    #[must_use]
    pub fn bitness_proofs(&self) -> &[BitnessProofV2] {
        &self.bitness_proofs
    }

    #[must_use]
    pub fn comparison_proof(&self) -> &ComparisonProofV2 {
        &self.comparison_proof
    }

    pub fn bitness_global_challenges(&self) -> Result<Vec<[u8; 32]>, MsError> {
        self.bitness_proofs
            .iter()
            .map(|proof| Ok(proof.global_challenge()?.to_bytes()))
            .collect()
    }

    pub fn comparison_global_challenge(&self) -> Result<[u8; 32], MsError> {
        Ok(self.comparison_proof.global_challenge()?.to_bytes())
    }

    #[must_use]
    pub fn transcript_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(DOMAIN_MS.as_bytes());
        hasher.update(b"predicate_only_v2_proof");
        hasher.update(&self.statement_digest);
        hasher.update(&[u8::from(self.result)]);
        for proof in &self.bitness_proofs {
            hasher.update(&proof.announce_zero);
            hasher.update(&proof.announce_one);
            hasher.update(&proof.challenge_zero);
            hasher.update(&proof.challenge_one);
            hasher.update(&proof.response_zero);
            hasher.update(&proof.response_one);
        }
        for clause in &self.comparison_proof.clauses {
            hasher.update(&clause.challenge_share);
            for subproof in &clause.subproofs {
                hasher.update(&subproof.announcement);
                hasher.update(&subproof.response);
            }
        }
        *hasher.finalize().as_bytes()
    }
}

impl std::fmt::Debug for PredicateOnlyProofV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PredicateOnlyProofV2")
            .field("result", &self.result)
            .field("statement_digest", &self.statement_digest)
            .field("bitness_proof_count", &self.bitness_proofs.len())
            .field("comparison_clause_count", &self.comparison_proof.clauses.len())
            .field("transcript_digest", &self.transcript_digest())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateOnlySimulationV2 {
    proof: PredicateOnlyProofV2,
    programmed_queries: Vec<ProgrammedOracleQueryV2>,
}

impl PredicateOnlySimulationV2 {
    #[must_use]
    pub fn proof(&self) -> &PredicateOnlyProofV2 {
        &self.proof
    }

    #[must_use]
    pub fn programmed_queries(&self) -> &[ProgrammedOracleQueryV2] {
        &self.programmed_queries
    }
}

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

    for bit_index in 0..V2_BIT_COUNT {
        let commitment = commitment_points[bit_index];
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
        let announce_zero = simulated_schnorr_announcement(point_zero, response_zero, challenge_zero);
        let announce_one = simulated_schnorr_announcement(point_one, response_one, challenge_one);
        let query_digest = bitness_query_digest(&statement_digest, bit_index, &announce_zero, &announce_one);
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

    let comparison_query = comparison_query_digest(&statement_digest, &proof.comparison_proof.clauses);
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

fn pedersen_commit(bit: u8, blinder: Scalar) -> RistrettoPoint {
    Scalar::from(bit as u64) * RISTRETTO_BASEPOINT_POINT + blinder * pedersen_h()
}

fn pedersen_h() -> RistrettoPoint {
    hash_to_point(b"predicate_only_v2_pedersen_h")
}

fn decode_commitment_points(commitment: &ValueCommitmentV2) -> Result<Vec<RistrettoPoint>, MsError> {
    commitment
        .bit_commitments()
        .iter()
        .map(decompress_point)
        .collect()
}

fn prove_bitness_bit(
    statement_digest: &[u8; 32],
    commitment: RistrettoPoint,
    bit: u8,
    blinder: Scalar,
    prover_seed: &[u8; 32],
    bit_index: usize,
) -> Result<BitnessProofV2, MsError> {
    let point_zero = commitment;
    let point_one = commitment - RISTRETTO_BASEPOINT_POINT;
    let mut proof = BitnessProofV2 {
        announce_zero: [0u8; 32],
        announce_one: [0u8; 32],
        challenge_zero: [0u8; 32],
        challenge_one: [0u8; 32],
        response_zero: [0u8; 32],
        response_one: [0u8; 32],
    };

    let alpha = hash_to_scalar(
        b"predicate_only_v2_bitness_alpha",
        &[
            statement_digest.as_slice(),
            prover_seed.as_slice(),
            &(bit_index as u32).to_le_bytes(),
        ],
    );

    if bit == 0 {
        proof.announce_zero = (alpha * pedersen_h()).compress().to_bytes();
        let sim_challenge = hash_to_scalar(
            b"predicate_only_v2_bitness_sim_c1",
            &[
                statement_digest.as_slice(),
                prover_seed.as_slice(),
                &(bit_index as u32).to_le_bytes(),
            ],
        );
        let sim_response = hash_to_scalar(
            b"predicate_only_v2_bitness_sim_z1",
            &[
                statement_digest.as_slice(),
                prover_seed.as_slice(),
                &(bit_index as u32).to_le_bytes(),
                b"sim",
            ],
        );
        proof.challenge_one = sim_challenge.to_bytes();
        proof.response_one = sim_response.to_bytes();
        proof.announce_one = simulated_schnorr_announcement(point_one, sim_response, sim_challenge);
        let query_digest = bitness_query_digest(
            statement_digest,
            bit_index,
            &proof.announce_zero,
            &proof.announce_one,
        );
        let global_challenge = hash_query_to_scalar(&query_digest);
        let challenge_zero = global_challenge - sim_challenge;
        let response_zero = alpha + challenge_zero * blinder;
        proof.challenge_zero = challenge_zero.to_bytes();
        proof.response_zero = response_zero.to_bytes();
    } else {
        proof.announce_one = (alpha * pedersen_h()).compress().to_bytes();
        let sim_challenge = hash_to_scalar(
            b"predicate_only_v2_bitness_sim_c0",
            &[
                statement_digest.as_slice(),
                prover_seed.as_slice(),
                &(bit_index as u32).to_le_bytes(),
            ],
        );
        let sim_response = hash_to_scalar(
            b"predicate_only_v2_bitness_sim_z0",
            &[
                statement_digest.as_slice(),
                prover_seed.as_slice(),
                &(bit_index as u32).to_le_bytes(),
                b"sim",
            ],
        );
        proof.challenge_zero = sim_challenge.to_bytes();
        proof.response_zero = sim_response.to_bytes();
        proof.announce_zero = simulated_schnorr_announcement(point_zero, sim_response, sim_challenge);
        let query_digest = bitness_query_digest(
            statement_digest,
            bit_index,
            &proof.announce_zero,
            &proof.announce_one,
        );
        let global_challenge = hash_query_to_scalar(&query_digest);
        let challenge_one = global_challenge - sim_challenge;
        let response_one = alpha + challenge_one * blinder;
        proof.challenge_one = challenge_one.to_bytes();
        proof.response_one = response_one.to_bytes();
    }

    Ok(proof)
}

fn candidate_positions(target: u64) -> Vec<u8> {
    let mut positions = Vec::new();
    for bit_index in (0..V2_BIT_COUNT).rev() {
        if ((target >> bit_index) & 1) == 0 {
            positions.push(bit_index as u8);
        }
    }
    positions
}

fn clause_bit_indices(position: u8) -> Vec<u8> {
    let mut indices = Vec::new();
    for bit_index in ((position as usize + 1)..V2_BIT_COUNT).rev() {
        indices.push(bit_index as u8);
    }
    indices.push(position);
    indices
}

fn clause_public_points(
    statement: &PredicateOnlyStatementV2,
    commitments: &[RistrettoPoint],
    position: u8,
) -> Result<Vec<RistrettoPoint>, MsError> {
    let mut points = Vec::new();
    for bit_index in clause_bit_indices(position) {
        let expected_bit = if bit_index == position {
            1u8
        } else {
            ((statement.target() >> bit_index) & 1) as u8
        };
        points.push(commitments[bit_index as usize] - Scalar::from(expected_bit as u64) * RISTRETTO_BASEPOINT_POINT);
    }
    Ok(points)
}

fn bitness_query_digest(
    statement_digest: &[u8; 32],
    bit_index: usize,
    announce_zero: &[u8; 32],
    announce_one: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[
            b"predicate_only_v2_bitness_query",
            statement_digest.as_slice(),
            &(bit_index as u32).to_le_bytes(),
            announce_zero.as_slice(),
            announce_one.as_slice(),
        ],
    )
}

fn comparison_query_digest(
    statement_digest: &[u8; 32],
    clauses: &[ComparisonClauseProofV2],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(DOMAIN_MS.as_bytes());
    hasher.update(b"predicate_only_v2_comparison_query");
    hasher.update(statement_digest);
    for clause in clauses {
        for subproof in &clause.subproofs {
            hasher.update(&subproof.announcement);
        }
    }
    *hasher.finalize().as_bytes()
}

fn hash_query_to_scalar(query_digest: &[u8; 32]) -> Scalar {
    hash_to_scalar(b"predicate_only_v2_query_scalar", &[query_digest.as_slice()])
}

fn simulated_schnorr_announcement(
    point: RistrettoPoint,
    response: Scalar,
    challenge: Scalar,
) -> [u8; 32] {
    (response * pedersen_h() - challenge * point)
        .compress()
        .to_bytes()
}

fn highest_differing_bit_u64(left: u64, right: u64) -> Option<u8> {
    let mut bit_index: u8 = 63;
    loop {
        if ((left >> bit_index) & 1) != ((right >> bit_index) & 1) {
            return Some(bit_index);
        }
        if bit_index == 0 {
            return None;
        }
        bit_index -= 1;
    }
}

fn decompress_point(bytes: &[u8; 32]) -> Result<RistrettoPoint, MsError> {
    CompressedRistretto(*bytes)
        .decompress()
        .ok_or(MsError::InvalidV2CommitmentField(
            "compressed point failed to decompress",
        ))
}

fn decode_scalar(bytes: &[u8; 32]) -> Result<Scalar, MsError> {
    Scalar::from_canonical_bytes(*bytes)
        .into_option()
        .ok_or(MsError::InvalidV2ProofField(
            "scalar encoding is not canonical",
        ))
}

fn hash_to_point(label: &[u8]) -> RistrettoPoint {
    let reader = v2_xof(label, &[]);
    RistrettoPoint::from_uniform_bytes(&reader)
}

fn hash_to_scalar(label: &[u8], chunks: &[&[u8]]) -> Scalar {
    let wide = v2_xof(label, chunks);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn v2_xof(label: &[u8], chunks: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Hasher::new();
    hasher.update(DOMAIN_MS.as_bytes());
    hasher.update(label);
    for chunk in chunks {
        hasher.update(&(chunk.len() as u32).to_le_bytes());
        hasher.update(chunk);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 64];
    reader.fill(&mut out);
    out
}

trait ChallengeOracle {
    fn challenge(&self, query_digest: &[u8; 32]) -> Result<Scalar, MsError>;
}

struct HashChallengeOracle;

impl ChallengeOracle for HashChallengeOracle {
    fn challenge(&self, query_digest: &[u8; 32]) -> Result<Scalar, MsError> {
        Ok(hash_query_to_scalar(query_digest))
    }
}

struct ProgrammedChallengeOracle<'a> {
    queries: &'a [ProgrammedOracleQueryV2],
}

impl<'a> ChallengeOracle for ProgrammedChallengeOracle<'a> {
    fn challenge(&self, query_digest: &[u8; 32]) -> Result<Scalar, MsError> {
        let Some(query) = self
            .queries
            .iter()
            .find(|item| item.query_digest.ct_eq(query_digest).unwrap_u8() == 1)
        else {
            return Err(MsError::MissingProgrammedOracleQuery);
        };
        decode_scalar(query.challenge())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_statement(
        value: u64,
        target: u64,
        seed: [u8; 32],
        binding_entropy: [u8; 32],
        binding_context: [u8; 32],
        context: &[u8],
    ) -> (PredicateOnlyStatementV2, PredicateWitnessV2) {
        let (commitment, witness) = commit_value_v2(value, seed, binding_entropy).unwrap();
        (
            PredicateOnlyStatementV2::new(
                commitment,
                target,
                binding_entropy,
                binding_context,
                context.to_vec(),
            ),
            witness,
        )
    }

    #[test]
    fn relation_check_rejects_mismatched_witness() {
        let (statement, mut witness) = sample_statement(
            30,
            21,
            [1u8; 32],
            [7u8; 32],
            [9u8; 32],
            b"age_gate_21",
        );
        witness.value = 18;
        assert!(!predicate_relation_holds_v2(&statement, &witness).unwrap());
    }

    #[test]
    fn real_proof_roundtrip_verifies_under_hash_oracle() {
        let (statement, witness) = sample_statement(
            30,
            21,
            [1u8; 32],
            [7u8; 32],
            [9u8; 32],
            b"age_gate_21",
        );
        let proof = prove_predicate_only_v2(&statement, &witness, [3u8; 32]).unwrap();
        assert!(verify_predicate_only_v2(&statement, &proof).unwrap());
    }

    #[test]
    fn simulated_proof_verifies_only_with_programmed_oracle() {
        let (statement, _witness) = sample_statement(
            30,
            21,
            [1u8; 32],
            [7u8; 32],
            [9u8; 32],
            b"age_gate_21",
        );
        let simulation = simulate_predicate_only_v2(&statement, [5u8; 32]).unwrap();
        assert!(verify_predicate_only_v2_with_programming(&statement, &simulation).unwrap());
        assert!(verify_predicate_only_v2(&statement, simulation.proof()).is_err());
    }

    #[test]
    fn proof_observables_are_accessible_for_distribution_checks() {
        let (statement, witness) = sample_statement(
            45,
            21,
            [6u8; 32],
            [7u8; 32],
            [9u8; 32],
            b"age_gate_21",
        );
        let proof = prove_predicate_only_v2(&statement, &witness, [8u8; 32]).unwrap();
        assert_eq!(proof.bitness_global_challenges().unwrap().len(), 64);
        assert_ne!(proof.comparison_global_challenge().unwrap(), [0u8; 32]);
        assert_ne!(proof.transcript_digest(), [0u8; 32]);
    }
}