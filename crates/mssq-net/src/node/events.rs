//! Swarm event dispatch and gossipsub message handlers (merit query, branch repair, heartbeats).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use libp2p::gossipsub::{IdentTopic, MessageAcceptance, MessageId};
use libp2p::swarm::SwarmEvent;
use libp2p::{PeerId, Swarm};
use mssq_batcher::{apply_batch, ProofError, RollupContext, RollupState, TxProofVerifier};
use qssm_common::{Batch, L2Transaction};
use qssm_governor::{verify_metabolic_gate, Governor, PeerAction};
use tokio::sync::Mutex;
use tracing::warn;

use crate::connectivity::peer_cache;
use crate::connectivity::relay::{update_nat_state, RelayState};
use crate::protocol::pulse::HeartbeatEnvelope;
use crate::protocol::sovereign_gossip::GossipMessage;
use crate::protocol::reputation::ReputationStore;
use crate::stack::{on_mesh_event, MeshBehaviour, MeshEvent};
use qssm_utils::hashing::hash_domain;

use super::archive::archive_branch;
use super::sovereign_verify;
use super::types::{BranchMessage, MeritMessage, NodeSnapshot};
use super::{push_pulse, refresh_immune_snapshot_locked};

struct AllowAllProofs;

impl TxProofVerifier for AllowAllProofs {
    fn verify_tx(&self, _tx: &L2Transaction, _ctx: &RollupContext) -> Result<(), ProofError> {
        Ok(())
    }
}

pub(crate) async fn handle_swarm_event(
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
    sovereign_topic_hash: Option<&libp2p::gossipsub::TopicHash>,
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
            if let libp2p::gossipsub::Event::Message {
                propagation_source,
                message,
                message_id,
            } = gossipsub_ev
            {
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
                    )
                    .await;
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
                if let Some(th) = sovereign_topic_hash {
                    if message.topic == *th {
                        return process_sovereign_gossip_message(
                            swarm,
                            propagation_source,
                            message_id,
                            &message.data,
                            snapshot,
                            governor,
                        )
                        .await;
                    }
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
            on_mesh_event(swarm, &ev);
            false
        }
        _ => false,
    }
}

async fn process_sovereign_gossip_message(
    swarm: &mut Swarm<MeshBehaviour>,
    peer: PeerId,
    msg_id: MessageId,
    data: &[u8],
    snapshot: &Arc<Mutex<NodeSnapshot>>,
    governor: &mut Governor,
) -> bool {
    let connected_peers = swarm.connected_peers().count();
    let decision = governor.decision_for(&peer.to_string(), connected_peers);
    if matches!(decision.action, PeerAction::Drop) {
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Reject);
        return false;
    }

    let msg: GossipMessage = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => {
            swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Reject);
            return false;
        }
    };

    let (jsonl_line, primary_targets, template_script) = match msg {
        GossipMessage::SovereignStepV1 {
            jsonl_line,
            primary_targets,
            template_script,
            ..
        } => (jsonl_line, primary_targets, template_script),
    };

    if jsonl_line.is_empty() {
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Reject);
        return false;
    }

    if let Err(e) =
        sovereign_verify::verify_sovereign_jsonl_with_templates(&jsonl_line, template_script.as_ref())
    {
        warn!(
            target: "mssq_net",
            "sovereign_step rejected from {}: {}",
            peer,
            e
        );
        swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Reject);
        return false;
    }

    swarm
        .behaviour_mut()
        .gossipsub
        .report_message_validation_result(&msg_id, &peer, MessageAcceptance::Accept);

    let preview: String = jsonl_line.chars().take(48).collect();
    let mut guard = snapshot.lock().await;
    push_pulse(
        &mut guard.pulses,
        format!(
            "sovereign_step <-{} targets={} line={preview}",
            peer,
            primary_targets.len()
        ),
    );
    false
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
        push_pulse(
            &mut guard.pulses,
            format!("peer {} dropped_by_governor", peer),
        );
        refresh_immune_snapshot_locked(&mut guard, governor, connected_peers);
        return false;
    }

    let decoded = serde_json::from_slice::<HeartbeatEnvelope>(&data).ok();
    let valid = decoded
        .as_ref()
        .map(|m| verify_metabolic_gate(&m.raw_jitter) && qssm_he::verify_density(&m.raw_jitter))
        .unwrap_or(false);
    governor.observe_pulse(
        &peer.to_string(),
        valid,
        crate::common::utils::unix_timestamp_ns(),
    );
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
            push_pulse(
                &mut guard.pulses,
                format!("peer {} {}", m.peer_id, m.seed_hex),
            );
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
            let _ = swarm
                .behaviour_mut()
                .gossipsub
                .publish(merit_topic.clone(), payload);
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
                let _ = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(branch_topic.clone(), payload);
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
                    format!(
                        "merkle_branch_synced peer={} via={}",
                        peer_id, propagation_source
                    ),
                );
                guard.repair_peer_id = Some(peer_id);
                guard.repair_root_hex = Some(hex::encode(root));
                guard.repair_proof_hex = Some(proof_hex);
                guard.fraud_alert_message = None;
            } else {
                push_pulse(
                    &mut guard.pulses,
                    format!(
                        "merkle_branch_invalid peer={} via={}",
                        peer_id, propagation_source
                    ),
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
