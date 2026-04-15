use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;

#[derive(Debug, Clone)]
pub struct ReputationEntry {
    pub score: i32,
    pub invalid_density: u64,
    pub accepted: u64,
    pub last_updated: Instant,
}

impl Default for ReputationEntry {
    fn default() -> Self {
        Self {
            score: 0,
            invalid_density: 0,
            accepted: 0,
            last_updated: Instant::now(),
        }
    }
}

#[derive(Debug, Default)]
pub struct ReputationStore {
    by_peer: HashMap<PeerId, ReputationEntry>,
}

impl ReputationStore {
    pub fn accept(&mut self, peer: PeerId) {
        let ent = self.by_peer.entry(peer).or_default();
        ent.accepted += 1;
        ent.score += 1;
        ent.last_updated = Instant::now();
    }

    pub fn penalize_density(&mut self, peer: PeerId) {
        let ent = self.by_peer.entry(peer).or_default();
        ent.invalid_density += 1;
        ent.score -= 5;
        ent.last_updated = Instant::now();
    }

    pub fn tick_decay(&mut self) {
        let now = Instant::now();
        for ent in self.by_peer.values_mut() {
            if now.duration_since(ent.last_updated) >= Duration::from_secs(60) {
                if ent.score < 0 {
                    ent.score += 1;
                } else if ent.score > 0 {
                    ent.score -= 1;
                }
                ent.last_updated = now;
            }
        }
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn snapshot(&self) -> Vec<(PeerId, ReputationEntry)> {
        self.by_peer
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    #[must_use]
    pub fn top_merit_holders(&self, limit: usize) -> Vec<PeerId> {
        let mut ranked: Vec<_> = self.by_peer.iter().collect();
        ranked.sort_by(|a, b| {
            b.1.score
                .cmp(&a.1.score)
                .then_with(|| b.1.accepted.cmp(&a.1.accepted))
                .then_with(|| a.1.invalid_density.cmp(&b.1.invalid_density))
        });
        ranked
            .into_iter()
            .take(limit)
            .map(|(peer, _)| *peer)
            .collect()
    }
}
