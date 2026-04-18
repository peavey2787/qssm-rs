use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LeError {
    #[error("R1CS or witness input exceeds allowed size")]
    OversizedInput,
    #[error("shortness / rejection sampling bound violated")]
    RejectedSample,
    /// Reserved for future proving backends where ring multiplication may fail.
    #[allow(dead_code)]
    #[error("ring multiplication failed")]
    RingMul,
    #[error("prover rejected too many times (Lyubashevsky aborts)")]
    ProverAborted,
    #[error("verifier rejected proof: infinity norm exceeded bound")]
    InvalidNorm,
    #[error("verifier rejected proof: transcript domain/challenge mismatch")]
    DomainMismatch,
}
