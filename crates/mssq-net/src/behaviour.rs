use libp2p::autonat;
use libp2p::dcutr;
use libp2p::gossipsub;
use libp2p::identify;
use libp2p::kad;
use libp2p::mdns;
use libp2p::ping;
use libp2p::relay;
use libp2p::swarm::NetworkBehaviour;
use libp2p::PeerId;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MeshEvent")]
pub struct MeshBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub autonat: autonat::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum MeshEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(kad::Event),
    Mdns(mdns::Event),
    AutoNat(autonat::Event),
    Dcutr(dcutr::Event),
    Relay(relay::client::Event),
    Identify(identify::Event),
    Ping(ping::Event),
}

impl From<gossipsub::Event> for MeshEvent {
    fn from(v: gossipsub::Event) -> Self { Self::Gossipsub(v) }
}
impl From<kad::Event> for MeshEvent {
    fn from(v: kad::Event) -> Self { Self::Kademlia(v) }
}
impl From<mdns::Event> for MeshEvent {
    fn from(v: mdns::Event) -> Self { Self::Mdns(v) }
}
impl From<autonat::Event> for MeshEvent {
    fn from(v: autonat::Event) -> Self { Self::AutoNat(v) }
}
impl From<dcutr::Event> for MeshEvent {
    fn from(v: dcutr::Event) -> Self { Self::Dcutr(v) }
}
impl From<relay::client::Event> for MeshEvent {
    fn from(v: relay::client::Event) -> Self { Self::Relay(v) }
}
impl From<identify::Event> for MeshEvent {
    fn from(v: identify::Event) -> Self { Self::Identify(v) }
}
impl From<ping::Event> for MeshEvent {
    fn from(v: ping::Event) -> Self { Self::Ping(v) }
}

pub fn build_behaviour(
    local_key: &libp2p::identity::Keypair,
    local_peer: PeerId,
    relay_behaviour: relay::client::Behaviour,
) -> MeshBehaviour {
    let message_id_fn = |msg: &gossipsub::Message| {
        let h = qssm_utils::hashing::blake3_hash(&msg.data);
        gossipsub::MessageId::from(format!("{:02x?}", h))
    };
    let gossip_cfg = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .build()
        .expect("gossipsub config");
    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossip_cfg,
    )
    .expect("gossipsub behaviour");

    let store = kad::store::MemoryStore::new(local_peer);
    let mut kademlia = kad::Behaviour::new(local_peer, store);
    kademlia.set_mode(Some(kad::Mode::Server));

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer)
        .expect("mdns behaviour");

    let identify = identify::Behaviour::new(identify::Config::new(
        "/mssq-net/1.0.0".to_string(),
        local_key.public(),
    ));

    MeshBehaviour {
        gossipsub,
        kademlia,
        mdns,
        autonat: autonat::Behaviour::new(local_peer, Default::default()),
        dcutr: dcutr::Behaviour::new(local_peer),
        relay_client: relay_behaviour,
        identify,
        ping: ping::Behaviour::new(ping::Config::new()),
    }
}
