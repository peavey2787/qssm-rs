//! Shared L2 types and finalized L1 trait surfaces.
#![forbid(unsafe_code)]

mod error;
mod l1_anchor;
mod rollup;
mod types;

pub use error::Error;
pub use l1_anchor::{L1Anchor, L1BatchSink, SovereignAnchor};
pub use rollup::{rollup_context_from_l1, RollupState};
pub use types::{Batch, L2Transaction, SmtRoot, StorageLease};
