//! SDK error types.

/// Errors from the SDK prove/verify calls.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ZkError {
    #[error("template predicate check failed: {0}")]
    PredicateFailed(#[from] template_lib::PredicateError),

    #[error("MS commit failed: {0}")]
    MsCommit(#[source] qssm_ms::MsError),

    #[error("MS prove failed (value={value}, target={target})")]
    MsProve {
        #[source]
        source: qssm_ms::MsError,
        value: u64,
        target: u64,
    },

    #[error("MS verification failed")]
    MsVerifyFailed,

    #[error("LE prove failed: {0}")]
    LeProve(#[source] qssm_le::LeError),

    #[error("LE verification failed: {0}")]
    LeVerify(#[source] qssm_le::LeError),

    #[error("LE verification returned false")]
    LeVerifyFailed,

    #[error("truth witness validation failed")]
    TruthWitnessInvalid,

    #[error("cross-engine binding failed: verifier-recomputed digest coefficients do not match LE public instance")]
    RebindingMismatch,
}
