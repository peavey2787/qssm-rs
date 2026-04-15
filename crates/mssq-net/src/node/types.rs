//! Node configuration, live snapshot, and internal control / wire messages.

use std::collections::VecDeque;
use std::time::Duration;

/// Swarm + pulse cadence configuration for a single MSSQ network instance.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub network_id: u32,
    pub heartbeat_every: Duration,
    pub startup_peer_cache_probe: usize,
    pub startup_merit_query_size: usize,
    pub history_archive: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network_id: 1,
            heartbeat_every: Duration::from_secs(30),
            startup_peer_cache_probe: 5,
            startup_merit_query_size: 10,
            history_archive: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NodeSnapshot {
    pub network_id: u32,
    pub network_label: String,
    pub peer_id: String,
    pub nat_status: String,
    pub public_addr: Option<String>,
    pub active_transports: Vec<String>,
    pub connected_peers: usize,
    pub active_relays: usize,
    pub pulses: VecDeque<String>,
    pub global_density_avg_milli: i64,
    pub real_density_avg_milli: i64,
    pub is_bootstrap_mode: bool,
    pub current_t_min_milli: i64,
    pub top_deficit_peers: Vec<String>,
    pub primary_peers: Vec<String>,
    pub governor_state: String,
    pub local_merit_tier: String,
    pub uptime_secs: u64,
    pub smt_root_hex: String,
    pub active_leases: Vec<String>,
    pub history_archive: bool,
    pub repair_peer_id: Option<String>,
    pub repair_root_hex: Option<String>,
    pub repair_proof_hex: Option<String>,
    pub fraud_alert_message: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum MeritMessage {
    Query { limit: usize },
    Response { peers: Vec<String> },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum BranchMessage {
    ReqMerkleBranch { peer_id: String },
    MerkleBranch {
        peer_id: String,
        root_hex: String,
        proof_hex: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum NodeControl {
    RequestBranch { peer_id: String },
}

pub(crate) fn network_label(network_id: u32) -> String {
    if network_id == 0 {
        "MAINNET".to_string()
    } else {
        format!("TESTNET-{network_id}")
    }
}
