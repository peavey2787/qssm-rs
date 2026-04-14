use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use qssm_he::{harvest, Heartbeat, HarvestConfig};

use crate::error::NetError;

pub fn heartbeat_topic(network_id: u32) -> String {
    format!("qssm.he.heartbeat.v1.net-{network_id}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatEnvelope {
    pub peer_id: String,
    pub timestamp_ns: u64,
    pub seed_hex: String,
    pub raw_jitter: Vec<u8>,
    pub sensor_entropy: Vec<u8>,
}

impl HeartbeatEnvelope {
    #[must_use]
    pub fn from_heartbeat(peer_id: PeerId, hb: &Heartbeat) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            timestamp_ns: hb.timestamp,
            seed_hex: hex_seed(&hb.to_seed()),
            raw_jitter: hb.raw_jitter.clone(),
            sensor_entropy: hb.sensor_entropy.as_ref().to_vec(),
        }
    }
}

pub fn collect_local_heartbeat() -> Result<Heartbeat, NetError> {
    let cfg = HarvestConfig::default();
    harvest(&cfg).map_err(|e| NetError::Heartbeat(e.to_string()))
}

fn hex_seed(seed: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in seed {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}
