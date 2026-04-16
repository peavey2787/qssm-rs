//! Batch posting sink (stubbed no-op until DA path is wired).

use qssm_traits::{Batch, Error, L1BatchSink};

/// Until DA path exists, posting is a no-op success (wire to `SubmitTransaction` etc.).
#[derive(Default)]
pub struct GrpcBatchSink {
    _priv: (),
}

impl L1BatchSink for GrpcBatchSink {
    fn post_batch(&mut self, _batch: &Batch) -> Result<(), Error> {
        Ok(())
    }
}
