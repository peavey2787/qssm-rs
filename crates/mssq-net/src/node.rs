use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::{IdentTopic, MessageAcceptance, MessageId};
use libp2p::swarm::SwarmEvent;
use libp2p::{PeerId, Swarm};
use qssm_governor::{verify_metabolic_gate, Governor, GovernorState, PeerAction};
use mssq_batcher::{apply_batch, prune_state, ProofError, RollupContext, RollupState, TxProofVerifier};
use qssm_common::{Batch, L2Transaction};
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};
use tracing::warn;

use crate::behaviour::{MeshBehaviour, MeshEvent};
use crate::discovery;
use crate::error::NetError;
use crate::pulse::{collect_local_heartbeat, heartbeat_topic, HeartbeatEnvelope};
use crate::peer_cache;
use crate::relay::{update_nat_state, RelayState};
use crate::reputation::ReputationStore;
use crate::transport::build_swarm;
use qssm_utils::hashing::hash_domain;

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

fn network_label(network_id: u32) -> String {
    if network_id == 0 {
        "MAINNET".to_string()
    } else {
        format!("TESTNET-{network_id}")
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
enum MeritMessage {
    Query { limit: usize },
    Response { peers: Vec<String> },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BranchMessage {
    ReqMerkleBranch { peer_id: String },
    MerkleBranch {
        peer_id: String,
        root_hex: String,
        proof_hex: String,
    },
}

#[derive(Debug, Clone)]
enum NodeControl {
    RequestBranch { peer_id: String },
}

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
    discovery::seed_bootstrap(&mut swarm, &cached);

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
                    let accepted = handle_swarm_event(
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

async fn handle_swarm_event(
    evt: SwarmEvent<MeshEvent>,
    swarm: &mut Swarm<MeshBehaviour>,
    snapshot: &Arc<Mutex<NodeSnapshot>>,
    rep: &mut ReputationStore,
    relay_state: &mut RelayState,
    governor: &mut Governor,
    merit_topic_hash: &libp2p::gossipsub::TopicHash,
    merit_topic: &IdentTopic,
    primary_peers: &mut HashSet<PeerId>,
    merit_query_size: usize,
    rollup_state: &mut RollupState,
    history_archive: bool,
    branch_topic_hash: &libp2p::gossipsub::TopicHash,
    branch_topic: &IdentTopic,
    archive_store: &mut HashMap<String, Vec<u8>>,
) -> bool {
    match evt {
        SwarmEvent::ConnectionEstablished { endpoint, .. } => {
            peer_cache::record_seen_addr(endpoint.get_remote_address());
            let mut guard = snapshot.lock().await;
            guard.connected_peers = swarm.connected_peers().count();
            guard.primary_peers = primary_peers.iter().map(ToString::to_string).collect();
            false
        }
        SwarmEvent::ConnectionClosed { .. } => {
            primary_peers.retain(|p| swarm.is_connected(p));
            let mut guard = snapshot.lock().await;
            guard.connected_peers = swarm.connected_peers().count();
            guard.primary_peers = primary_peers.iter().map(ToString::to_string).collect();
            false
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            let mut guard = snapshot.lock().await;
            guard.public_addr = Some(address.to_string());
            false
        }
        SwarmEvent::Behaviour(MeshEvent::AutoNat(ev)) => {
            update_nat_state(relay_state, &ev);
            let mut guard = snapshot.lock().await;
            guard.nat_status = format!("{ev:?}");
            if relay_state.behind_restrictive_nat && !relay_state.reservation_attempted {
                relay_state.reservation_attempted = true;
                guard.active_relays = 1;
            }
            false
        }
        SwarmEvent::Behaviour(MeshEvent::Gossipsub(gossipsub_ev)) => {
            if let libp2p::gossipsub::Event::Message { propagation_source, message, message_id } = gossipsub_ev {
                if message.topic == *merit_topic_hash {
                    return process_merit_message(
                        swarm,
                        propagation_source,
                        message.data,
                        snapshot,
                        rep,
                        merit_topic,
                        primary_peers,
                        merit_query_size,
                    ).await;
                }
                if message.topic == *branch_topic_hash {
                    return process_branch_message(
                        swarm,
                        propagation_source,
                        message.data,
                        snapshot,
                        rollup_state,
                        history_archive,
                        branch_topic,
                        archive_store,
                    )
                    .await;
                }
                process_inbound_heartbeat(
                    swarm,
                    propagation_source,
                    message_id,
                    message.data,
                    snapshot,
                    rep,
                    governor,
                    rollup_state,
                    history_archive,
                    archive_store,
                )
                .await
            } else {
                false
            }
        }
        SwarmEvent::Behaviour(ev) => {
            discovery::on_mesh_event(swarm, &ev);
            false
        }
        _ => false,
    }
}

async fn process_inbound_heartbeat(
    swarm: &mut Swarm<MeshBehaviour>,
    peer: PeerId,
    msg_id: MessageId,
    data: Vec<u8>,
    snapshot: &Arc<Mutex<NodeSnapshot>>,
    rep: &mut ReputationStore,
    governor: &mut Governor,
    rollup_state: &mut RollupState,
    history_archive: bool,
    archive_store: &mut HashMap<String, Vec<u8>>,
) -> bool {
    let connected_peers = swarm.connected_peers().count();
    let decision = governor.decision_for(&peer.to_string(), connected_peers);
    if matches!(decision.action, PeerAction::Drop) {
        warn!("governor dropped heartbeat from peer {}", peer);
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Reject);
        let mut guard = snapshot.lock().await;
        push_pulse(&mut guard.pulses, format!("peer {} dropped_by_governor", peer));
        refresh_immune_snapshot_locked(&mut guard, governor, connected_peers);
        return false;
    }

    let decoded = serde_json::from_slice::<HeartbeatEnvelope>(&data).ok();
    let valid = decoded
        .as_ref()
        .map(|m| verify_metabolic_gate(&m.raw_jitter) && qssm_he::verify_density(&m.raw_jitter))
        .unwrap_or(false);
    governor.observe_pulse(&peer.to_string(), valid, unix_timestamp_ns());
    if valid {
        rep.accept(peer);
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Accept);
        if let Some(m) = decoded {
            let key = hash_domain(
                "MSSQ-PULSE-LEAF-KEY-v1.0",
                &[m.peer_id.as_bytes(), m.seed_hex.as_bytes()],
            );
            let proof = rollup_state.smt.prove(&key).encode();
            let mut payload = vec![0x01];
            payload.extend_from_slice(&1_u64.to_le_bytes());
            let tx = L2Transaction {
                id: key,
                proof,
                payload,
            };
            let batch = Batch { txs: vec![tx] };
            let ctx = RollupContext {
                finalized_block_hash: [0u8; 32],
                finalized_blue_score: rollup_state.pulse_height,
                qrng_epoch: 0,
                qrng_value: [0u8; 32],
            };
            let _ = apply_batch(rollup_state, &batch, &ctx, &AllowAllProofs);
            let mut guard = snapshot.lock().await;
            push_pulse(&mut guard.pulses, format!("peer {} {}", m.peer_id, m.seed_hex));
            guard.smt_root_hex = hex::encode(rollup_state.root());
            refresh_immune_snapshot_locked(&mut guard, governor, connected_peers);
            if history_archive {
                let encoded = rollup_state.smt.prove(&key).encode();
                archive_store.insert(m.peer_id.clone(), encoded.clone());
                archive_branch(rollup_state, &key, &encoded);
            }
        }
        true
    } else {
        rep.penalize_density(peer);
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Reject);
        let mut guard = snapshot.lock().await;
        push_pulse(&mut guard.pulses, format!("peer {} rejected_density", peer));
        refresh_immune_snapshot_locked(&mut guard, governor, connected_peers);
        false
    }
}

async fn process_merit_message(
    swarm: &mut Swarm<MeshBehaviour>,
    peer: PeerId,
    data: Vec<u8>,
    snapshot: &Arc<Mutex<NodeSnapshot>>,
    rep: &mut ReputationStore,
    merit_topic: &IdentTopic,
    primary_peers: &mut HashSet<PeerId>,
    merit_query_size: usize,
) -> bool {
    let msg = match serde_json::from_slice::<MeritMessage>(&data) {
        Ok(v) => v,
        Err(_) => return false,
    };
    match msg {
        MeritMessage::Query { limit } => {
            let peers = rep
                .top_merit_holders(limit.min(merit_query_size))
                .into_iter()
                .filter(|p| swarm.is_connected(p))
                .map(|p| p.to_string())
                .collect::<Vec<_>>();
            let payload = serde_json::to_vec(&MeritMessage::Response { peers }).unwrap_or_default();
            let _ = swarm.behaviour_mut().gossipsub.publish(merit_topic.clone(), payload);
            false
        }
        MeritMessage::Response { peers } => {
            primary_peers.clear();
            for p in peers.into_iter().take(merit_query_size) {
                if let Ok(peer_id) = p.parse::<PeerId>() {
                    if swarm.is_connected(&peer_id) {
                        let _ = primary_peers.insert(peer_id);
                    }
                }
            }
            // Always include the respondent if connected to avoid empty primary set early.
            if swarm.is_connected(&peer) {
                let _ = primary_peers.insert(peer);
            }
            let mut guard = snapshot.lock().await;
            guard.primary_peers = primary_peers.iter().map(ToString::to_string).collect();
            let primary_len = guard.primary_peers.len();
            push_pulse(
                &mut guard.pulses,
                format!("welcome_crew updated {} primary peers", primary_len),
            );
            false
        }
    }
}

async fn process_branch_message(
    swarm: &mut Swarm<MeshBehaviour>,
    propagation_source: PeerId,
    data: Vec<u8>,
    snapshot: &Arc<Mutex<NodeSnapshot>>,
    rollup_state: &mut RollupState,
    history_archive: bool,
    branch_topic: &IdentTopic,
    archive_store: &mut HashMap<String, Vec<u8>>,
) -> bool {
    let msg = match serde_json::from_slice::<BranchMessage>(&data) {
        Ok(v) => v,
        Err(_) => return false,
    };
    match msg {
        BranchMessage::ReqMerkleBranch { peer_id } => {
            if !history_archive {
                return false;
            }
            if let Some(proof) = archive_store.get(&peer_id) {
                let payload = serde_json::to_vec(&BranchMessage::MerkleBranch {
                    peer_id,
                    root_hex: hex::encode(rollup_state.root()),
                    proof_hex: hex::encode(proof),
                })
                .unwrap_or_default();
                let _ = swarm.behaviour_mut().gossipsub.publish(branch_topic.clone(), payload);
            }
            false
        }
        BranchMessage::MerkleBranch {
            peer_id,
            root_hex,
            proof_hex,
        } => {
            let Ok(root_vec) = hex::decode(root_hex) else {
                return false;
            };
            if root_vec.len() != 32 {
                return false;
            }
            let mut root = [0u8; 32];
            root.copy_from_slice(&root_vec);
            let Ok(proof_bytes) = hex::decode(&proof_hex) else {
                return false;
            };
            let Some(proof) = qssm_utils::SparseMerkleProof::decode(&proof_bytes) else {
                return false;
            };
            let verified = qssm_utils::StateMirrorTree::verify_proof(root, &proof);
            let mut guard = snapshot.lock().await;
            if verified {
                push_pulse(
                    &mut guard.pulses,
                    format!("merkle_branch_synced peer={} via={}", peer_id, propagation_source),
                );
                guard.repair_peer_id = Some(peer_id);
                guard.repair_root_hex = Some(hex::encode(root));
                guard.repair_proof_hex = Some(proof_hex);
                guard.fraud_alert_message = None;
            } else {
                push_pulse(
                    &mut guard.pulses,
                    format!("merkle_branch_invalid peer={} via={}", peer_id, propagation_source),
                );
                guard.fraud_alert_message = Some(format!(
                    "Invalid Data Received from Peer {}. Searching for honest Librarian...",
                    peer_id
                ));
            }
            verified
        }
    }
}

fn push_pulse(buf: &mut VecDeque<String>, line: String) {
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

fn refresh_immune_snapshot_locked(
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
        GovernorState::Expanding => "Expanding".to_string(),
        GovernorState::Defending => "Defending".to_string(),
    };
}

fn unix_timestamp_ns() -> u64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_nanos() as u64)
        .unwrap_or_default()
}

struct AllowAllProofs;

impl TxProofVerifier for AllowAllProofs {
    fn verify_tx(&self, _tx: &L2Transaction, _ctx: &RollupContext) -> Result<(), ProofError> {
        Ok(())
    }
}

fn archive_branch(state: &RollupState, key: &[u8; 32], encoded_proof: &[u8]) {
    let line = serde_json::json!({
        "key_hex": hex::encode(key),
        "root_hex": hex::encode(state.root()),
        "proof_hex": hex::encode(encoded_proof),
        "pulse_height": state.pulse_height,
    });
    if let Ok(mut p) = std::env::current_dir() {
        p.push("history_archive_merkle.jsonl");
        if let Ok(s) = serde_json::to_string(&line) {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{s}");
            }
        }
    }
}
