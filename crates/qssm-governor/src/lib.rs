//! Deterministic metabolic governor for entropy merit and peer filtering.
#![forbid(unsafe_code)]

mod engine;
mod state;
mod tracker;
mod utils;

use std::collections::HashMap;

use rust_decimal::Decimal;

use engine::MetabolicEngine;
use state::{classify_from, classify_peek, try_recover_with};
pub use state::{GovernorState, PeerAction, PeerState};
use tracker::entropy::EntropyTracker;
use tracker::peer_stats::PeerStats;
pub use utils::verify_metabolic_gate;
use utils::{d, milli};

#[derive(Debug, Clone)]
pub struct GovernorConfig {
    pub n: usize,
    pub n_min: usize,
    pub w_secs: u32,
    pub r_met: Decimal,
    pub lambda: Decimal,
    pub alpha: Decimal,
    pub t_base: Decimal,
    pub t_cap: Decimal,
    pub theta_w: Decimal,
    pub theta_t: Decimal,
    pub theta_b: Decimal,
    pub m: u32,
    pub b: usize,
    pub cooldown_ticks: u64,
    pub n_rec: usize,
    pub epsilon: Decimal,
    pub throttle_msgs_per_sec: u32,
    pub bootstrap_peer_threshold: usize,
    pub bootstrap_global_density: Decimal,
    pub base_hardware_entropy_floor: Decimal,
    pub target_nodes: u32,
    pub target_adjust_interval: u64,
    pub saturation_low: Decimal,
    pub saturation_high: Decimal,
    pub surge_spike_threshold: Decimal,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        let t_base = d(100, 2);
        Self {
            n: 128,
            n_min: 16,
            w_secs: 30,
            r_met: d(40, 0),
            lambda: d(15, 2),
            alpha: d(20, 1),
            t_base,
            t_cap: t_base * d(4, 0),
            theta_w: d(10, 2),
            theta_t: d(20, 2),
            theta_b: d(35, 2),
            m: 6,
            b: 12,
            cooldown_ticks: 20,
            n_rec: 32,
            epsilon: d(5, 2),
            throttle_msgs_per_sec: 5,
            bootstrap_peer_threshold: 2,
            bootstrap_global_density: d(95, 2),
            base_hardware_entropy_floor: t_base,
            target_nodes: 128,
            target_adjust_interval: 1024,
            saturation_low: d(25, 2),
            saturation_high: d(75, 2),
            surge_spike_threshold: d(20, 2),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernorDecision {
    pub peer_id: String,
    pub action: PeerAction,
    pub state: PeerState,
    pub deficit_milli: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeficitPeer {
    pub peer_id: String,
    pub deficit_milli: i64,
    pub state: PeerState,
}

#[derive(Debug, Clone)]
pub struct Governor {
    cfg: GovernorConfig,
    entropy: EntropyTracker,
    metabolic: MetabolicEngine,
    peers: HashMap<String, PeerStats>,
    tick: u64,
}

impl Default for Governor {
    fn default() -> Self {
        Self::new(GovernorConfig::default())
    }
}

impl Governor {
    pub fn new(cfg: GovernorConfig) -> Self {
        Self {
            metabolic: MetabolicEngine::new(cfg.clone()),
            entropy: EntropyTracker::new(),
            peers: HashMap::new(),
            tick: 0,
            cfg,
        }
    }

    pub fn observe_pulse(&mut self, peer_id: &str, density_ok: bool, _timestamp_ns: u64) {
        self.tick = self.tick.saturating_add(1);
        let score = if density_ok {
            Decimal::ONE
        } else {
            Decimal::ZERO
        };
        self.entropy.push_score(score, self.cfg.n);
        let entry = self.peers.entry(peer_id.to_string()).or_default();
        entry.push(score, density_ok, self.cfg.n);
    }

    pub fn update_pressure(&mut self, pulses_in_window: u32, window_secs: u32) {
        self.metabolic
            .update_pressure(pulses_in_window, window_secs);
    }

    pub fn current_t_min_milli(&self) -> i64 {
        milli(self.metabolic.t_min())
    }

    pub fn governor_state(&self) -> GovernorState {
        self.metabolic.state()
    }

    pub fn global_density_avg_milli(&self, connected_peers: usize) -> i64 {
        milli(self.global_density_avg(connected_peers))
    }

    pub fn real_density_avg_milli(&self) -> i64 {
        milli(self.entropy.mean())
    }

    pub fn is_bootstrap_mode(&self, connected_peers: usize) -> bool {
        connected_peers <= self.cfg.bootstrap_peer_threshold && self.entropy.len() < self.cfg.n_min
    }

    pub fn decision_for(&mut self, peer_id: &str, connected_peers: usize) -> GovernorDecision {
        let global_avg = self.global_density_avg(connected_peers);
        let cfg = self.cfg.clone();
        let tick = self.tick;
        let stats = self.peers.entry(peer_id.to_string()).or_default();
        let mut state = classify_from(&cfg, tick, stats, global_avg);
        if state == PeerState::Blacklisted {
            let recovered = try_recover_with(&cfg, stats, global_avg);
            if recovered {
                state = PeerState::Watch;
            }
        }
        let deficit = global_avg - stats.mean();
        let action = match state {
            PeerState::Healthy | PeerState::Watch | PeerState::Warmup => PeerAction::Accept,
            PeerState::Throttled => PeerAction::Throttle {
                max_msgs_per_sec: self.cfg.throttle_msgs_per_sec,
            },
            PeerState::Blacklisted => PeerAction::Drop,
        };
        GovernorDecision {
            peer_id: peer_id.to_string(),
            action,
            state,
            deficit_milli: milli(deficit),
        }
    }

    pub fn top_deficit_peers(&mut self, connected_peers: usize, limit: usize) -> Vec<DeficitPeer> {
        let global_avg = self.global_density_avg(connected_peers);
        let tick = self.tick;
        let mut rows: Vec<DeficitPeer> = self
            .peers
            .iter()
            .map(|(peer_id, stats)| DeficitPeer {
                peer_id: peer_id.clone(),
                deficit_milli: milli(global_avg - stats.mean()),
                state: classify_peek(&self.cfg, tick, stats, global_avg),
            })
            .collect();
        rows.sort_by(|a, b| {
            b.deficit_milli
                .cmp(&a.deficit_milli)
                .then(a.peer_id.cmp(&b.peer_id))
        });
        rows.into_iter().take(limit).collect()
    }

    fn global_density_avg(&self, connected_peers: usize) -> Decimal {
        if connected_peers <= self.cfg.bootstrap_peer_threshold
            && self.entropy.len() < self.cfg.n_min
        {
            return self.cfg.bootstrap_global_density;
        }
        let observed = self.entropy.mean();
        if observed == Decimal::ZERO && self.entropy.len() == 0 {
            return self.cfg.bootstrap_global_density;
        }
        observed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warmup_does_not_blacklist_new_peer() {
        let mut gov = Governor::default();
        for i in 0..10_u64 {
            gov.observe_pulse("peer-a", false, i);
        }
        let dec = gov.decision_for("peer-a", 1);
        assert_eq!(dec.state, PeerState::Warmup);
        assert_ne!(dec.action, PeerAction::Drop);
    }

    #[test]
    fn bootstrap_mode_uses_floor_density() {
        let mut gov = Governor::default();
        gov.observe_pulse("peer-a", false, 1);
        let avg = gov.global_density_avg_milli(1);
        assert_eq!(avg, 950);
    }

    #[test]
    fn blacklist_after_sustained_deficit() {
        let mut gov = Governor::default();
        for i in 0..32_u64 {
            gov.observe_pulse("good", true, i);
            gov.observe_pulse("bad", false, i + 1000);
            let _ = gov.decision_for("bad", 6);
        }
        let dec = gov.decision_for("bad", 6);
        assert_eq!(dec.state, PeerState::Blacklisted);
        assert_eq!(dec.action, PeerAction::Drop);
    }
}
