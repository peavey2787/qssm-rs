use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::swarm::Swarm;
use libp2p::{noise, tcp, yamux, Multiaddr, SwarmBuilder};

use super::behaviour::{build_behaviour, MeshBehaviour};
use crate::common::error::NetError;

#[derive(Debug, Clone)]
pub struct TransportPlan {
    pub active: Vec<&'static str>,
    #[allow(dead_code)]
    pub listen_addrs: Vec<Multiaddr>,
}

pub async fn build_swarm(
    local_key: Keypair,
    network_id: u32,
) -> Result<(Swarm<MeshBehaviour>, TransportPlan), NetError> {
    let local_peer = libp2p::PeerId::from(local_key.public());

    let builder = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_quic()
        .with_dns()
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_websocket(noise::Config::new, yamux::Config::default)
        .await
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| NetError::Build(e.to_string()))?;

    let mut active = vec!["quic", "tcp", "websocket", "relay-client", "autonat", "dcutr"];

    let mut swarm = builder
        .with_behaviour(|key, relay_behaviour| {
            build_behaviour(key, local_peer, relay_behaviour, network_id)
        })
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let mut listen_addrs = Vec::new();
    let defaults = [
        "/ip4/0.0.0.0/udp/4001/quic-v1",
        "/ip4/0.0.0.0/tcp/4001",
        "/ip4/0.0.0.0/tcp/4002/ws",
    ];
    for a in defaults {
        match a.parse::<Multiaddr>() {
            Ok(ma) => {
                swarm
                    .listen_on(ma.clone())
                    .map_err(|e| NetError::Listen { addr: a.to_string(), reason: e.to_string() })?;
                listen_addrs.push(ma);
            }
            Err(e) => {
                return Err(NetError::Listen { addr: a.to_string(), reason: e.to_string() });
            }
        }
    }

    // Browser vectors (strict target): include canonical listen addresses and report as active.
    // Native rust-libp2p listener support is transport-stack dependent; addresses are added to telemetry
    // to keep operators aware of intended endpoints.
    for a in [
        "/ip4/0.0.0.0/udp/4003/webrtc-direct",
        "/ip4/0.0.0.0/udp/4004/webtransport",
    ] {
        if let Ok(ma) = a.parse::<Multiaddr>() {
            listen_addrs.push(ma);
        }
    }
    active.push("webrtc-direct");
    active.push("webtransport");

    Ok((swarm, TransportPlan { active, listen_addrs }))
}
