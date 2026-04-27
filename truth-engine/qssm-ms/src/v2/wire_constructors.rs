use super::types::{
    BitnessProofV2, ComparisonClauseProofV2, ComparisonProofV2, EqualitySubproofV2,
    PredicateOnlyProofV2, V2_BIT_COUNT,
};
use crate::MsError;

impl EqualitySubproofV2 {
    #[must_use]
    pub fn from_wire(announcement: [u8; 32], response: [u8; 32]) -> Self {
        Self {
            announcement,
            response,
        }
    }

    #[must_use]
    pub fn announcement_bytes(&self) -> &[u8; 32] {
        &self.announcement
    }
    #[must_use]
    pub fn response_bytes(&self) -> &[u8; 32] {
        &self.response
    }
}

impl ComparisonClauseProofV2 {
    #[must_use]
    pub fn from_wire(challenge_share: [u8; 32], subproofs: Vec<EqualitySubproofV2>) -> Self {
        Self {
            challenge_share,
            subproofs,
        }
    }

    #[must_use]
    pub fn challenge_share_bytes(&self) -> &[u8; 32] {
        &self.challenge_share
    }
    #[must_use]
    pub fn subproofs_slice(&self) -> &[EqualitySubproofV2] {
        &self.subproofs
    }
}

impl ComparisonProofV2 {
    #[must_use]
    pub fn from_clauses(clauses: Vec<ComparisonClauseProofV2>) -> Self {
        Self { clauses }
    }

    #[must_use]
    pub fn clauses_slice(&self) -> &[ComparisonClauseProofV2] {
        &self.clauses
    }
}

impl BitnessProofV2 {
    #[must_use]
    pub fn from_wire(
        announce_zero: [u8; 32],
        announce_one: [u8; 32],
        challenge_zero: [u8; 32],
        challenge_one: [u8; 32],
        response_zero: [u8; 32],
        response_one: [u8; 32],
    ) -> Self {
        Self {
            announce_zero,
            announce_one,
            challenge_zero,
            challenge_one,
            response_zero,
            response_one,
        }
    }

    #[must_use]
    pub fn announce_zero_bytes(&self) -> &[u8; 32] {
        &self.announce_zero
    }
    #[must_use]
    pub fn announce_one_bytes(&self) -> &[u8; 32] {
        &self.announce_one
    }
    #[must_use]
    pub fn challenge_zero_bytes(&self) -> &[u8; 32] {
        &self.challenge_zero
    }
    #[must_use]
    pub fn challenge_one_bytes(&self) -> &[u8; 32] {
        &self.challenge_one
    }
    #[must_use]
    pub fn response_zero_bytes(&self) -> &[u8; 32] {
        &self.response_zero
    }
    #[must_use]
    pub fn response_one_bytes(&self) -> &[u8; 32] {
        &self.response_one
    }
}

fn candidate_positions_for_wire(target: u64) -> usize {
    let mut count = 0usize;
    for bit_index in (0..V2_BIT_COUNT).rev() {
        if ((target >> bit_index) & 1) == 0 {
            count += 1;
        }
    }
    count
}

impl PredicateOnlyProofV2 {
    /// Reconstruct a proof from decoded wire fields (layout must match `prove_predicate_only_v2`).
    pub fn from_wire_parts(
        result: bool,
        statement_digest: [u8; 32],
        bitness_proofs: Vec<BitnessProofV2>,
        comparison_proof: ComparisonProofV2,
        target_for_clause_layout: u64,
    ) -> Result<Self, MsError> {
        if bitness_proofs.len() != V2_BIT_COUNT {
            return Err(MsError::InvalidV2ProofField(
                "bitness proof count must be 64",
            ));
        }
        let expected_clauses = candidate_positions_for_wire(target_for_clause_layout);
        if comparison_proof.clauses.len() != expected_clauses {
            return Err(MsError::InvalidV2ProofField(
                "comparison clause count does not match target",
            ));
        }
        Ok(Self {
            result,
            statement_digest,
            bitness_proofs,
            comparison_proof,
        })
    }
}
