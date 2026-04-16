//! Per-peer rolling memory used by state classification.
//!
//! Ownership boundary:
//! - Maintains only peer-local windows/counters.
//! - Does not decide `PeerState`; classifiers consume this data.

use std::collections::VecDeque;

use rust_decimal::Decimal;

#[derive(Debug, Default, Clone)]
pub struct PeerStats {
    scores: VecDeque<Decimal>,
    rejected: VecDeque<bool>,
    pub(crate) over_b_streak: u32,
    pub(crate) accepted_since_blacklist: usize,
    pub(crate) blacklisted_until_tick: Option<u64>,
}

impl PeerStats {
    pub(crate) fn push(&mut self, score: Decimal, accepted: bool, n: usize) {
        self.scores.push_back(score);
        self.rejected.push_back(!accepted);
        while self.scores.len() > n {
            let _ = self.scores.pop_front();
        }
        while self.rejected.len() > n {
            let _ = self.rejected.pop_front();
        }
    }

    pub(crate) fn mean(&self) -> Decimal {
        if self.scores.is_empty() {
            return Decimal::ZERO;
        }
        let sum: Decimal = self.scores.iter().copied().sum();
        sum / Decimal::from(self.scores.len() as u32)
    }

    pub(crate) fn rejected_count(&self) -> usize {
        self.rejected.iter().filter(|v| **v).count()
    }

    pub(crate) fn scores_len(&self) -> usize {
        self.scores.len()
    }
}
