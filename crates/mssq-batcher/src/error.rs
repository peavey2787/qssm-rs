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
}
