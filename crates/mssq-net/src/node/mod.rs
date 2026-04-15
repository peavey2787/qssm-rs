//! MSSQ node: libp2p swarm + pulse loop, split into `types`, `events`, and `archive`.

mod archive;
mod events;
mod types;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use futures::StreamExt;
use libp2p::gossipsub::IdentTopic;
use libp2p::{PeerId, Swarm};
use mssq_batcher::{prune_state, RollupState};
use qssm_governor::Governor;
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};

use crate::common::error::NetError;
use crate::common::utils::unix_timestamp_ns;
use crate::connectivity::peer_cache;
use crate::connectivity::relay::RelayState;
use crate::protocol::pulse::{collect_local_heartbeat, heartbeat_topic, HeartbeatEnvelope};
use crate::protocol::reputation::ReputationStore;
use crate::stack::{build_swarm, seed_bootstrap, MeshBehaviour};

pub use types::{NodeConfig, NodeSnapshot};

use types::{network_label, BranchMessage, MeritMessage, NodeControl};

#[derive(Clone)]
pub struct NodeHandle {
    pub peer_id: PeerId,
    pub snapshot: Arc<Mutex<NodeSnapshot>>,
    shutdown_tx: mpsc::Sender<()>,
    control_tx: mpsc::UnboundedSender<NodeControl>,
}

impl NodeHandle {
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(()).await;
    }

    pub fn request_merkle_branch(&self, peer_id: String) -> Result<(), String> {
        self.control_tx
            .send(NodeControl::RequestBranch { peer_id })
            .map_err(|_| "control channel closed".to_string())
    }
}

pub async fn start_node(cfg: NodeConfig) -> Result<NodeHandle, NetError> {
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer = PeerId::from(local_key.public());
    let (mut swarm, transport_plan) = build_swarm(local_key, cfg.network_id).await?;

    let topic = IdentTopic::new(heartbeat_topic(cfg.network_id));
    let merit_topic = IdentTopic::new(format!("mssq/merit-query/net-{}", cfg.network_id));
    let merit_topic_hash = merit_topic.hash().clone();
    let branch_topic = IdentTopic::new(format!("mssq/req-merkle-branch/net-{}", cfg.network_id));
    let branch_topic_hash = branch_topic.hash().clone();
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&merit_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&branch_topic);
    let cached = peer_cache::load_last_addrs(cfg.startup_peer_cache_probe);
    seed_bootstrap(&mut swarm, &cached);

    let snapshot = Arc::new(Mutex::new(NodeSnapshot {
        network_id: cfg.network_id,
        network_label: network_label(cfg.network_id),
        peer_id: local_peer.to_string(),
        nat_status: "unknown".to_string(),
        public_addr: None,
        active_transports: transport_plan.active.iter().map(|s| s.to_string()).collect(),
        connected_peers: 0,
        active_relays: 0,
        pulses: VecDeque::new(),
        global_density_avg_milli: 950,
        real_density_avg_milli: 0,
        is_bootstrap_mode: true,
        current_t_min_milli: 1000,
        top_deficit_peers: Vec::new(),
        primary_peers: Vec::new(),
        governor_state: "Expanding".to_string(),
        local_merit_tier: "Seedling".to_string(),
        uptime_secs: 0,
        smt_root_hex: hex::encode([0u8; 32]),
        active_leases: Vec::new(),
        history_archive: cfg.history_archive,
        repair_peer_id: None,
        repair_root_hex: None,
        repair_proof_hex: None,
        fraud_alert_message: None,
    }));
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    let task_snapshot = Arc::clone(&snapshot);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(cfg.heartbeat_every);
        let mut rep = ReputationStore::default();
        let mut relay_state = RelayState::default();
        let mut governor = Governor::default();
        let mut rollup_state = RollupState::new();
        let mut archive_store: HashMap<String, Vec<u8>> = HashMap::new();
        let started_at = std::time::Instant::now();
        let mut primary_peers: HashSet<PeerId> = HashSet::new();
        let mut pulses_in_window: u32 = 0;
        let mut startup_queried = false;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if !startup_queried {
                        let payload = serde_json::to_vec(&MeritMessage::Query {
                            limit: cfg.startup_merit_query_size,
                        }).unwrap_or_default();
                        let _ = swarm.behaviour_mut().gossipsub.publish(merit_topic.clone(), payload);
                        startup_queried = true;
                    }
                    if let Ok(local_density_ok) = publish_heartbeat(&mut swarm, local_peer, &topic, &task_snapshot).await {
                        governor.observe_pulse(&local_peer.to_string(), local_density_ok, unix_timestamp_ns());
                        pulses_in_window = pulses_in_window.saturating_add(1);
                    }
                    governor.update_pressure(pulses_in_window, cfg.heartbeat_every.as_secs().max(1) as u32);
                    pulses_in_window = 0;
                    let connected = swarm.connected_peers().count();
                    refresh_immune_snapshot(&task_snapshot, &mut governor, connected).await;
                    let mut guard = task_snapshot.lock().await;
                    let uptime = started_at.elapsed().as_secs();
                    guard.uptime_secs = uptime;
                    guard.local_merit_tier = if uptime >= 7 * 24 * 3600 {
                        "Boosted".to_string()
                    } else if uptime >= 24 * 3600 {
                        "Mature".to_string()
                    } else {
                        "Seedling".to_string()
                    };
                    guard.active_leases = primary_peers
                        .iter()
                        .take(3)
                        .enumerate()
                        .map(|(i, p)| format!("lease-{:02} provider={} rent_due={} pulses", i + 1, p, 1024))
                        .collect();
                    rep.tick_decay();
                    if !cfg.history_archive {
                        prune_state(&mut rollup_state, 4096);
                    }
                }
                maybe_shutdown = shutdown_rx.recv() => {
                    // `Some(())` = graceful shutdown; `None` = all `shutdown_tx` senders dropped — exit either way.
                    let _ = maybe_shutdown;
                    break;
                }
                ctrl = control_rx.recv() => {
                    if let Some(NodeControl::RequestBranch { peer_id }) = ctrl {
                        let payload = serde_json::to_vec(&BranchMessage::ReqMerkleBranch { peer_id }).unwrap_or_default();
                        let _ = swarm.behaviour_mut().gossipsub.publish(branch_topic.clone(), payload);
                    }
                }
                evt = swarm.select_next_some() => {
                    let accepted = events::handle_swarm_event(
                        evt,
                        &mut swarm,
                        &task_snapshot,
                        &mut rep,
                        &mut relay_state,
                        &mut governor,
                        &merit_topic_hash,
                        &merit_topic,
                        &mut primary_peers,
                        cfg.startup_merit_query_size,
                        &mut rollup_state,
                        cfg.history_archive,
                        &branch_topic_hash,
                        &branch_topic,
                        &mut archive_store,
                    ).await;
                    if accepted {
                        pulses_in_window = pulses_in_window.saturating_add(1);
                    }
                }
            }
        }
    });

    Ok(NodeHandle {
        peer_id: local_peer,
        snapshot,
        shutdown_tx,
        control_tx,
    })
}

async fn publish_heartbeat(
    swarm: &mut Swarm<MeshBehaviour>,
    local_peer: PeerId,
    topic: &IdentTopic,
    snapshot: &Arc<Mutex<NodeSnapshot>>,
) -> Result<bool, NetError> {
    let hb = match collect_local_heartbeat() {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(target: "mssq_net", "heartbeat skipped: {e}");
            return Ok(false);
        }
    };
    let local_density_ok = qssm_he::verify_density(&hb.raw_jitter);
    let env = HeartbeatEnvelope::from_heartbeat(local_peer, &hb);
    let payload = serde_json::to_vec(&env).map_err(|e| NetError::GossipCodec(e.to_string()))?;
    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload);
    let mut guard = snapshot.lock().await;
    push_pulse(&mut guard.pulses, format!("local {} {}", env.peer_id, env.seed_hex));
    Ok(local_density_ok)
}

pub(crate) fn push_pulse(buf: &mut VecDeque<String>, line: String) {
    buf.push_front(line);
    while buf.len() > 24 {
        let _ = buf.pop_back();
    }
}

pub fn snapshot_to_json(snapshot: &NodeSnapshot) -> Value {
    serde_json::json!({
        "peer_id": snapshot.peer_id,
        "network_id": snapshot.network_id,
        "network_label": snapshot.network_label,
        "nat_status": snapshot.nat_status,
        "public_addr": snapshot.public_addr,
        "active_transports": snapshot.active_transports,
        "connected_peers": snapshot.connected_peers,
        "active_relays": snapshot.active_relays,
        "pulses": snapshot.pulses,
        "global_density_avg_milli": snapshot.global_density_avg_milli,
        "real_density_avg_milli": snapshot.real_density_avg_milli,
        "is_bootstrap_mode": snapshot.is_bootstrap_mode,
        "current_t_min_milli": snapshot.current_t_min_milli,
        "top_deficit_peers": snapshot.top_deficit_peers,
        "primary_peers": snapshot.primary_peers,
        "governor_state": snapshot.governor_state,
        "local_merit_tier": snapshot.local_merit_tier,
        "uptime_secs": snapshot.uptime_secs,
        "smt_root_hex": snapshot.smt_root_hex,
        "active_leases": snapshot.active_leases,
        "history_archive": snapshot.history_archive,
        "repair_peer_id": snapshot.repair_peer_id,
        "repair_root_hex": snapshot.repair_root_hex,
        "repair_proof_hex": snapshot.repair_proof_hex,
        "fraud_alert_message": snapshot.fraud_alert_message,
    })
}

async fn refresh_immune_snapshot(
    snapshot: &Arc<Mutex<NodeSnapshot>>,
    governor: &mut Governor,
    connected_peers: usize,
) {
    let mut guard = snapshot.lock().await;
    refresh_immune_snapshot_locked(&mut guard, governor, connected_peers);
}

pub(crate) fn refresh_immune_snapshot_locked(
    snapshot: &mut NodeSnapshot,
    governor: &mut Governor,
    connected_peers: usize,
) {
    snapshot.global_density_avg_milli = governor.global_density_avg_milli(connected_peers);
    snapshot.real_density_avg_milli = governor.real_density_avg_milli();
    snapshot.is_bootstrap_mode = governor.is_bootstrap_mode(connected_peers);
    snapshot.current_t_min_milli = governor.current_t_min_milli();
    snapshot.top_deficit_peers = governor
        .top_deficit_peers(connected_peers, 5)
        .into_iter()
        .map(|row| {
            let whole = row.deficit_milli / 1000;
            let frac = row.deficit_milli.abs() % 1000;
            format!("{}: {}.{:03} {:?}", row.peer_id, whole, frac, row.state)
        })
        .collect();
    snapshot.governor_state = match governor.governor_state() {
        qssm_governor::GovernorState::Expanding => "Expanding".to_string(),
        qssm_governor::GovernorState::Defending => "Defending".to_string(),
    };
}

