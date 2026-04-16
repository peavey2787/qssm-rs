//! Shared L2 types and finalized L1 trait surfaces.
#![forbid(unsafe_code)]

mod chain;
mod error;
mod types;

pub use chain::l1_anchor::{L1Anchor, L1BatchSink, SovereignAnchor};
pub use chain::rollup::{rollup_context_from_l1, RollupState};
pub use error::Error;
pub use types::{Batch, L2Transaction, SmtRoot, StorageLease};
