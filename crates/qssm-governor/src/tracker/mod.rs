//! Sliding-window memory stores used by the governor.
//!
//! Ownership boundary:
//! - `entropy`: network-wide moving density memory.
//! - `peer_stats`: per-peer moving score/rejection memory.

pub mod entropy;
pub mod peer_stats;
