//! Kaspa BlockDAG anchor for rollup `L1Anchor` (production: gRPC; default: typed stub).
//!
//! Enable `kaspa-grpc` and wire real RPCs to finalized headers / blue score. The default
//! [`GrpcKaspaAnchor`] returns conservative placeholders until connected.
#![forbid(unsafe_code)]

pub mod adapter;
pub mod grpc;

mod anchor;
mod sink;

pub use adapter::mock::MockKaspaAdapter;
pub use anchor::GrpcKaspaAnchor;
pub use sink::GrpcBatchSink;
