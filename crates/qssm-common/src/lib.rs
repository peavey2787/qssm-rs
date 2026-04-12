//! Shared L2 types, finalized L1 [`L1Anchor`], and mock Kaspa adapter.
#![forbid(unsafe_code)]

mod error;
mod l1_anchor;
mod mock;
mod rollup;
mod types;

pub use error::Error;
pub use l1_anchor::{L1Anchor, L1BatchSink, SovereignAnchor};
pub use mock::MockKaspaAdapter;
pub use rollup::{rollup_context_from_l1, RollupState};
pub use types::{Batch, L2Transaction, SmtRoot};
