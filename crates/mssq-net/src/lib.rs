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
mod pulse;
mod relay;
mod reputation;
mod transport;

pub use error::NetError;
pub use node::{snapshot_to_json, start_node, NodeConfig, NodeHandle, NodeSnapshot};
pub use pulse::{HeartbeatEnvelope, HEARTBEAT_TOPIC};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn node_start_shutdown_smoke() {
        let h = start_node(NodeConfig::default()).await.expect("start");
        h.shutdown().await;
    }

    #[test]
    fn density_gate_rejects_flat_payload() {
        assert!(!qssm_he::verify_density(&vec![0u8; 1024]));
    }
}
