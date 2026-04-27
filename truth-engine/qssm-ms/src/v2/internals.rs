use super::types::{
    BitnessProofV2, ComparisonClauseProofV2, PredicateOnlyStatementV2, ProgrammedOracleQueryV2, ValueCommitmentV2,
    V2_BIT_COUNT,
};
use crate::MsError;
use blake3::Hasher;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use qssm_utils::{hash_domain, DOMAIN_MS};
use subtle::ConstantTimeEq;

pub(crate) fn pedersen_commit(bit: u8, blinder: Scalar) -> RistrettoPoint {
    Scalar::from(bit as u64) * RISTRETTO_BASEPOINT_POINT + blinder * pedersen_h()
}

pub(crate) fn pedersen_h() -> RistrettoPoint {
    hash_to_point(b"predicate_only_v2_pedersen_h")
}

pub(crate) fn decode_commitment_points(commitment: &ValueCommitmentV2) -> Result<Vec<RistrettoPoint>, MsError> {
    commitment
        .bit_commitments()
        .iter()
        .map(decompress_point)
        .collect()
}

pub(crate) fn prove_bitness_bit(
    statement_digest: &[u8; 32],
    commitment: RistrettoPoint,
    bit: u8,
    blinder: Scalar,
    prover_seed: &[u8; 32],
    bit_index: usize,
) -> Result<BitnessProofV2, MsError> {
    let point_zero = commitment;
    let point_one = commitment - RISTRETTO_BASEPOINT_POINT;
    let true_branch_is_zero = bit == 0;

    let alpha_true = hash_to_scalar(
        b"predicate_only_v2_bitness_alpha_true",
        &[
            statement_digest.as_slice(),
            prover_seed.as_slice(),
            &(bit_index as u32).to_le_bytes(),
        ],
    );
    let challenge_sim = hash_to_scalar(
        b"predicate_only_v2_bitness_challenge_sim",
        &[
            statement_digest.as_slice(),
            prover_seed.as_slice(),
            &(bit_index as u32).to_le_bytes(),
            b"sim",
        ],
    );
    let response_sim = hash_to_scalar(
        b"predicate_only_v2_bitness_response_sim",
        &[
            statement_digest.as_slice(),
            prover_seed.as_slice(),
            &(bit_index as u32).to_le_bytes(),
            b"sim",
        ],
    );

    let announce_true = (alpha_true * pedersen_h()).compress().to_bytes();
    let announce_sim = if true_branch_is_zero {
        simulated_schnorr_announcement(point_one, response_sim, challenge_sim)
    } else {
        simulated_schnorr_announcement(point_zero, response_sim, challenge_sim)
    };

    let (announce_zero, announce_one) = if true_branch_is_zero {
        (announce_true, announce_sim)
    } else {
        (announce_sim, announce_true)
    };

    let query_digest = bitness_query_digest(statement_digest, bit_index, &announce_zero, &announce_one);
    let challenge_global = hash_query_to_scalar(&query_digest);

    let (challenge_zero, challenge_one, response_zero, response_one) = if true_branch_is_zero {
        let challenge_true = challenge_global - challenge_sim;
        let response_true = alpha_true + challenge_true * blinder;
        (
            challenge_true.to_bytes(),
            challenge_sim.to_bytes(),
            response_true.to_bytes(),
            response_sim.to_bytes(),
        )
    } else {
        let challenge_true = challenge_global - challenge_sim;
        let response_true = alpha_true + challenge_true * blinder;
        (
            challenge_sim.to_bytes(),
            challenge_true.to_bytes(),
            response_sim.to_bytes(),
            response_true.to_bytes(),
        )
    };

    Ok(BitnessProofV2 {
        announce_zero,
        announce_one,
        challenge_zero,
        challenge_one,
        response_zero,
        response_one,
    })
}

pub(crate) fn candidate_positions(target: u64) -> Vec<u8> {
    let mut positions = Vec::new();
    for bit in (0..V2_BIT_COUNT).rev() {
        if ((target >> bit) & 1) == 0 {
            positions.push(bit as u8);
        }
    }
    positions
}

pub(crate) fn clause_bit_indices(position: u8) -> Vec<u8> {
    let mut indices = Vec::new();
    for bit_index in ((position as usize + 1)..V2_BIT_COUNT).rev() {
        indices.push(bit_index as u8);
    }
    indices.push(position);
    indices
}

pub(crate) fn clause_public_points(
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
        points.push(
            commitments[bit_index as usize] - Scalar::from(expected_bit as u64) * RISTRETTO_BASEPOINT_POINT,
        );
    }
    Ok(points)
}

pub(crate) fn bitness_query_digest(
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

pub(crate) fn comparison_query_digest(
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

pub(crate) fn hash_query_to_scalar(query_digest: &[u8; 32]) -> Scalar {
    hash_to_scalar(b"predicate_only_v2_query_scalar", &[query_digest.as_slice()])
}

pub(crate) fn simulated_schnorr_announcement(
    point: RistrettoPoint,
    response: Scalar,
    challenge: Scalar,
) -> [u8; 32] {
    (response * pedersen_h() - challenge * point).compress().to_bytes()
}

pub(crate) fn highest_differing_bit_u64(left: u64, right: u64) -> Option<u8> {
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

pub(crate) fn decompress_point(bytes: &[u8; 32]) -> Result<RistrettoPoint, MsError> {
    CompressedRistretto(*bytes)
        .decompress()
        .ok_or(MsError::InvalidV2CommitmentField(
            "compressed point failed to decompress",
        ))
}

pub(crate) fn decode_scalar(bytes: &[u8; 32]) -> Result<Scalar, MsError> {
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

pub(crate) fn hash_to_scalar(label: &[u8], chunks: &[&[u8]]) -> Scalar {
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

pub(crate) trait ChallengeOracle {
    fn challenge(&self, query_digest: &[u8; 32]) -> Result<Scalar, MsError>;
}

pub(crate) struct HashChallengeOracle;

impl ChallengeOracle for HashChallengeOracle {
    fn challenge(&self, query_digest: &[u8; 32]) -> Result<Scalar, MsError> {
        Ok(hash_query_to_scalar(query_digest))
    }
}

pub(crate) struct ProgrammedChallengeOracle<'a> {
    pub(crate) queries: &'a [ProgrammedOracleQueryV2],
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
