//! `mssq-net`: production-oriented libp2p swarm glue for MSSQ.
//!
//! - Multi-transport stack (QUIC priority, TCP+Noise+Yamux fallback, WebSocket).
//! - Mesh behaviours (Gossipsub, Kademlia, mDNS, AutoNAT, DCUtR, Relay client).
//! - QSSM-HE pulse generation/validation with density gating + peer reputation.
//! - Tokio runtime + example dashboard in `examples/mssq_node.rs`.

#![forbid(unsafe_code)]

mod behaviour;
mod discovery;
mod error;
mod node;
mod peer_cache;
mod pulse;
mod relay;
mod reputation;
mod transport;

pub use error::NetError;
pub use node::{snapshot_to_json, start_node, NodeConfig, NodeHandle, NodeSnapshot};
pub use pulse::{HeartbeatEnvelope, HEARTBEAT_TOPIC};
