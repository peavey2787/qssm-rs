// Exhaustive match on WireFormatError must fail because it is #[non_exhaustive].
use zk_api::WireFormatError;

fn check(e: WireFormatError) {
    match e {
        WireFormatError::UnsupportedVersion(_) => {}
        WireFormatError::HexDecode { .. } => {}
        WireFormatError::BadLength { .. } => {}
        WireFormatError::BadCoeffCount { .. } => {}
        WireFormatError::InvalidMsProofField(_) => {}
        // No wildcard arm — compiler must reject this.
    }
}

fn main() {}
