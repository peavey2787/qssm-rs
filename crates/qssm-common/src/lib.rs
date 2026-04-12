//! Shared L2 types and the `SovereignAnchor` abstraction (mock Kaspa implementation).
#![forbid(unsafe_code)]

mod anchor;
mod error;
mod mock;
mod types;

pub use anchor::SovereignAnchor;
pub use error::Error;
pub use mock::MockKaspaAdapter;
pub use types::{Batch, L2Transaction, SmtRoot};
