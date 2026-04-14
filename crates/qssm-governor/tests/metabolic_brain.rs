use qssm_governor::{Governor, PeerState};

#[test]
fn laggard_transitions_healthy_watch_blacklisted() {
    let mut gov = Governor::default();

    // Warm up network with high-density peers so baseline stays high.
    for i in 0..24_u64 {
        gov.observe_pulse("peer-good-1", true, i);
        gov.observe_pulse("peer-good-2", true, i + 1000);
    }

    // Warm up laggard with good pulses so it starts as Healthy.
    for i in 0..16_u64 {
        gov.observe_pulse("peer-laggard", true, i + 2000);
    }
    let healthy = gov.decision_for("peer-laggard", 4);
    assert_eq!(healthy.state, PeerState::Healthy);

    // Push laggard below moving average; should degrade to Watch first.
    for i in 0..3_u64 {
        gov.observe_pulse("peer-laggard", false, i + 3000);
        gov.observe_pulse("peer-good-1", true, i + 4000);
        gov.observe_pulse("peer-good-2", true, i + 5000);
    }
    let watch = gov.decision_for("peer-laggard", 4);
    assert_eq!(watch.state, PeerState::Watch);

    // Continue rejected pulses until blacklist policy triggers.
    for i in 0..16_u64 {
        gov.observe_pulse("peer-laggard", false, i + 6000);
        gov.observe_pulse("peer-good-1", true, i + 7000);
        gov.observe_pulse("peer-good-2", true, i + 8000);
    }
    let blacklisted = gov.decision_for("peer-laggard", 4);
    assert_eq!(blacklisted.state, PeerState::Blacklisted);
}

#[test]
fn flood_raises_t_min() {
    let mut gov = Governor::default();
    let baseline = gov.current_t_min_milli();

    // Simulate network burst: 100 pulses in 1 second.
    gov.update_pressure(100, 1);
    let fever = gov.current_t_min_milli();

    assert!(fever > baseline, "expected T_min to rise under flood");
}

#[test]
fn sovereign_mode_prevents_small_network_collapse() {
    let mut gov = Governor::default();

    // Two-node setup with mostly healthy baseline.
    for i in 0..6_u64 {
        gov.observe_pulse("node-a", true, i);
        gov.observe_pulse("node-b", true, i + 1000);
    }

    let before = gov.global_density_avg_milli(2);
    gov.observe_pulse("node-b", false, 5000);
    let after = gov.global_density_avg_milli(2);
    let decision = gov.decision_for("node-b", 2);

    // Bootstrap floor should hold global average in small-network mode.
    assert_eq!(before, 950);
    assert_eq!(after, 950);
    // One failed pulse in sovereign mode should not instant-blacklist.
    assert_ne!(decision.state, PeerState::Blacklisted);
}
