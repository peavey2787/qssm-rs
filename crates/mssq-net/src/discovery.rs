use libp2p::kad;
use libp2p::swarm::Swarm;
use libp2p::Multiaddr;

use crate::behaviour::{MeshBehaviour, MeshEvent};

pub fn seed_bootstrap(swarm: &mut Swarm<MeshBehaviour>, addrs: &[Multiaddr]) {
    for addr in addrs {
        let _ = swarm.dial(addr.clone());
    }
    let _ = swarm.behaviour_mut().kademlia.bootstrap();
}

pub fn on_mesh_event(swarm: &mut Swarm<MeshBehaviour>, event: &MeshEvent) {
    match event {
        MeshEvent::Mdns(libp2p::mdns::Event::Discovered(list)) => {
            for (peer, addr) in list {
                swarm.behaviour_mut().kademlia.add_address(peer, addr.clone());
            }
        }
        MeshEvent::Kademlia(kad::Event::OutboundQueryProgressed { .. }) => {}
        _ => {}
    }
}
