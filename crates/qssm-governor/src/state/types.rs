//! Policy state/action enums exported for consumers and audit surfaces.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernorState {
    Expanding,
    Defending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Warmup,
    Healthy,
    Watch,
    Throttled,
    Blacklisted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAction {
    Accept,
    Throttle { max_msgs_per_sec: u32 },
    Drop,
}
