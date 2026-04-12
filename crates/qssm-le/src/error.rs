use thiserror::Error;

#[derive(Debug, Error)]
pub enum LeError {
    #[error("R1CS or witness input exceeds allowed size")]
    OversizedInput,
    #[error("public message out of embeddable range")]
    MessageOutOfRange,
    #[error("shortness / rejection sampling bound violated")]
    RejectedSample,
    #[error("ring multiplication failed")]
    RingMul,
    #[error("prover rejected too many times (Lyubashevsky aborts)")]
    ProverAborted,
}
