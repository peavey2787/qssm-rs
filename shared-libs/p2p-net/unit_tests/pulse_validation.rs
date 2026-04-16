use p2p_net::HeartbeatEnvelope;

#[test]
fn valid_pulse_density_accepts() {
    let hb = qssm_he::harvest(&qssm_he::HarvestConfig::default()).expect("harvest");
    let env = HeartbeatEnvelope::from_heartbeat(libp2p::PeerId::random(), &hb);
    assert!(qssm_he::verify_density(&env.raw_jitter));
}

#[test]
fn synthetic_pulse_density_rejects() {
    assert!(!qssm_he::verify_density(&vec![0u8; 1024]));
}
