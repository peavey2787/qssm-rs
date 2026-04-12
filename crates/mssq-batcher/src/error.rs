use thiserror::Error;

#[derive(Debug, Error)]
pub enum BatcherError {
    #[error("batch contains duplicate transaction ids")]
    DuplicateTxId,
    #[error("leader election requires at least one candidate")]
    NoCandidates,
    #[error("leader attestation slot does not match anchor slot")]
    WrongSlot,
    #[error("declared parent block hash does not match anchor")]
    MismatchedParentBlockHash,
    #[error("declared QRNG value or epoch does not match anchor")]
    MismatchedQrng,
    #[error("claimed leader is not in the registered candidate set")]
    LeaderNotInCandidateSet,
    #[error("claimed leader is not the min-score winner for this Seed_k")]
    NotWinningLeader,
    #[error("ML-DSA public key encoding is invalid")]
    InvalidSigningKey,
    #[error("ML-DSA signature verification failed")]
    InvalidSignature,
    #[error("claimed_leader_id does not match hash of signing_public_key")]
    LeaderKeyIdMismatch,
    #[error("transaction proof did not verify for this rollup context")]
    ProofVerificationFailed,
}
