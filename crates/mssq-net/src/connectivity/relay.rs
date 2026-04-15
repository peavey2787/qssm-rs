use libp2p::autonat;

#[derive(Debug, Clone, Default)]
pub struct RelayState {
    pub behind_restrictive_nat: bool,
    pub reservation_attempted: bool,
}

pub fn update_nat_state(state: &mut RelayState, event: &autonat::Event) {
    match event {
        autonat::Event::StatusChanged { old: _, new } => {
            state.behind_restrictive_nat = matches!(
                new,
                autonat::NatStatus::Private | autonat::NatStatus::Unknown
            );
        }
        _ => {}
    }
}
