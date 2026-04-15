//! `mssq-net`: production-oriented libp2p swarm glue for MSSQ.
//!
//! - **`stack`**: transport + `MeshBehaviour` + discovery helpers.
//! - **`connectivity`**: NAT/relay state and on-disk peer address cache.
//! - **`protocol`**: heartbeat gossip and reputation.
//! - **`common`**: `NetError` and small shared helpers.
//! - **`node`**: Tokio orchestration (`start_node`, snapshots).
//! - Example dashboard: `examples/mssq_node.rs`.

#![forbid(unsafe_code)]

pub mod common;
pub mod connectivity;
pub mod protocol;
pub mod stack;

mod node;

pub use common::error::NetError;
pub use node::{snapshot_to_json, start_node, NodeConfig, NodeHandle, NodeSnapshot};
pub use protocol::pulse::{heartbeat_topic, HeartbeatEnvelope};
