use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("libp2p build failed: {0}")]
    Build(String),
    #[error("listen failed for {addr}: {reason}")]
    Listen { addr: String, reason: String },
    #[error("heartbeat harvest failed: {0}")]
    Heartbeat(String),
    #[error("gossip message encode/decode failed: {0}")]
    GossipCodec(String),
}
