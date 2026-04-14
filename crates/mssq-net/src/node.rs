use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::{IdentTopic, MessageAcceptance, MessageId};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};
use serde_json::Value;
use tokio::sync::{mpsc, Mutex};

use crate::behaviour::{MeshBehaviour, MeshEvent};
use crate::discovery;
use crate::error::NetError;
use crate::pulse::{collect_local_heartbeat, HeartbeatEnvelope, HEARTBEAT_TOPIC};
use crate::relay::{update_nat_state, RelayState};
use crate::reputation::ReputationStore;
use crate::transport::build_swarm;

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub bootstrap_addrs: Vec<Multiaddr>,
    pub heartbeat_every: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bootstrap_addrs: Vec::new(),
            heartbeat_every: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NodeSnapshot {
    pub peer_id: String,
    pub nat_status: String,
    pub public_addr: Option<String>,
    pub active_transports: Vec<String>,
    pub connected_peers: usize,
    pub active_relays: usize,
    pub pulses: VecDeque<String>,
}

#[derive(Clone)]
pub struct NodeHandle {
    pub peer_id: PeerId,
    pub snapshot: Arc<Mutex<NodeSnapshot>>,
    shutdown_tx: mpsc::Sender<()>,
}

impl NodeHandle {
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(()).await;
    }
}

pub async fn start_node(cfg: NodeConfig) -> Result<NodeHandle, NetError> {
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer = PeerId::from(local_key.public());
    let (mut swarm, transport_plan) = build_swarm(local_key).await?;

    let topic = IdentTopic::new(HEARTBEAT_TOPIC);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);
    discovery::seed_bootstrap(&mut swarm, &cfg.bootstrap_addrs);

    let snapshot = Arc::new(Mutex::new(NodeSnapshot {
        peer_id: local_peer.to_string(),
        nat_status: "unknown".to_string(),
        public_addr: None,
        active_transports: transport_plan.active.iter().map(|s| s.to_string()).collect(),
        connected_peers: 0,
        active_relays: 0,
        pulses: VecDeque::new(),
    }));
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    let task_snapshot = Arc::clone(&snapshot);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(cfg.heartbeat_every);
        let mut rep = ReputationStore::default();
        let mut relay_state = RelayState::default();
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let _ = publish_heartbeat(&mut swarm, local_peer, &topic, &task_snapshot).await;
                    rep.tick_decay();
                }
                maybe_shutdown = shutdown_rx.recv() => {
                    if maybe_shutdown.is_some() {
                        break;
                    }
                }
                evt = swarm.select_next_some() => {
                    handle_swarm_event(evt, &mut swarm, &task_snapshot, &mut rep, &mut relay_state).await;
                }
            }
        }
    });

    Ok(NodeHandle {
        peer_id: local_peer,
        snapshot,
        shutdown_tx,
    })
}

async fn publish_heartbeat(
    swarm: &mut Swarm<MeshBehaviour>,
    local_peer: PeerId,
    topic: &IdentTopic,
    snapshot: &Arc<Mutex<NodeSnapshot>>,
) -> Result<(), NetError> {
    let hb = collect_local_heartbeat()?;
    let env = HeartbeatEnvelope::from_heartbeat(local_peer, &hb);
    let payload = serde_json::to_vec(&env).map_err(|e| NetError::GossipCodec(e.to_string()))?;
    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload);
    let mut guard = snapshot.lock().await;
    push_pulse(&mut guard.pulses, format!("local {} {}", env.peer_id, env.seed_hex));
    Ok(())
}

async fn handle_swarm_event(
    evt: SwarmEvent<MeshEvent>,
    swarm: &mut Swarm<MeshBehaviour>,
    snapshot: &Arc<Mutex<NodeSnapshot>>,
    rep: &mut ReputationStore,
    relay_state: &mut RelayState,
) {
    match evt {
        SwarmEvent::ConnectionEstablished { .. } | SwarmEvent::ConnectionClosed { .. } => {
            let mut guard = snapshot.lock().await;
            guard.connected_peers = swarm.connected_peers().count();
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            let mut guard = snapshot.lock().await;
            guard.public_addr = Some(address.to_string());
        }
        SwarmEvent::Behaviour(MeshEvent::AutoNat(ev)) => {
            update_nat_state(relay_state, &ev);
            let mut guard = snapshot.lock().await;
            guard.nat_status = format!("{ev:?}");
            if relay_state.behind_restrictive_nat && !relay_state.reservation_attempted {
                relay_state.reservation_attempted = true;
                guard.active_relays = 1;
            }
        }
        SwarmEvent::Behaviour(MeshEvent::Gossipsub(gossipsub_ev)) => {
            if let libp2p::gossipsub::Event::Message { propagation_source, message, message_id } = gossipsub_ev {
                process_inbound_heartbeat(swarm, propagation_source, message_id, message.data, snapshot, rep).await;
            }
        }
        SwarmEvent::Behaviour(ev) => {
            discovery::on_mesh_event(swarm, &ev);
        }
        _ => {}
    }
}

async fn process_inbound_heartbeat(
    swarm: &mut Swarm<MeshBehaviour>,
    peer: PeerId,
    msg_id: MessageId,
    data: Vec<u8>,
    snapshot: &Arc<Mutex<NodeSnapshot>>,
    rep: &mut ReputationStore,
) {
    let decoded = serde_json::from_slice::<HeartbeatEnvelope>(&data).ok();
    let valid = decoded
        .as_ref()
        .map(|m| qssm_he::verify_density(&m.raw_jitter))
        .unwrap_or(false);
    if valid {
        rep.accept(peer);
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Accept);
        if let Some(m) = decoded {
            let mut guard = snapshot.lock().await;
            push_pulse(&mut guard.pulses, format!("peer {} {}", m.peer_id, m.seed_hex));
        }
    } else {
        rep.penalize_density(peer);
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Reject);
        let mut guard = snapshot.lock().await;
        push_pulse(&mut guard.pulses, format!("peer {} rejected_density", peer));
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
        "nat_status": snapshot.nat_status,
        "public_addr": snapshot.public_addr,
        "active_transports": snapshot.active_transports,
        "connected_peers": snapshot.connected_peers,
        "active_relays": snapshot.active_relays,
        "pulses": snapshot.pulses,
    })
}
