// Exhaustive match on ZkError must fail because it is #[non_exhaustive].
use qssm_api::ZkError;

fn check(e: ZkError) {
    match e {
        ZkError::PredicateFailed(_) => {}
        ZkError::MsCommit(_) => {}
        ZkError::MsProve { .. } => {}
        ZkError::MsVerifyFailed => {}
        ZkError::LeProve(_) => {}
        ZkError::LeVerify(_) => {}
        ZkError::LeVerifyFailed => {}
        ZkError::TruthWitnessInvalid => {}
        ZkError::RebindingMismatch => {}
        // No wildcard arm — compiler must reject this.
    }
}

fn main() {}
