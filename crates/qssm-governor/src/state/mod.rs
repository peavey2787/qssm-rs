//! Peer/governor judgement layer.
//!
//! Ownership boundary:
//! - `types`: externally visible policy states/actions.
//! - `classify`: auditable threshold logic converting tracker memory into states.

mod classify;
mod types;

pub(crate) use classify::{classify_from, classify_peek, try_recover_with};
pub use types::{GovernorState, PeerAction, PeerState};
