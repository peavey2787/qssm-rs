use std::collections::VecDeque;

use rust_decimal::Decimal;

#[derive(Debug, Default, Clone)]
pub struct EntropyTracker {
    global_scores: VecDeque<Decimal>,
}

impl EntropyTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push_score(&mut self, score: Decimal, n: usize) {
        self.global_scores.push_back(score);
        while self.global_scores.len() > n {
            let _ = self.global_scores.pop_front();
        }
    }

    pub(crate) fn mean(&self) -> Decimal {
        if self.global_scores.is_empty() {
            return Decimal::ZERO;
        }
        let sum: Decimal = self.global_scores.iter().copied().sum();
        sum / Decimal::from(self.global_scores.len() as u32)
    }

    pub(crate) fn len(&self) -> usize {
        self.global_scores.len()
    }
}
