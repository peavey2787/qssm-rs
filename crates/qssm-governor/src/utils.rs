//! Shared helpers and lightweight gates.
//!
//! Ownership boundary:
//! - Decimal conversion helpers (`d`, `milli`) shared by orchestration and engine.
//! - `verify_metabolic_gate` provides a fast entropy-quality prefilter independent of policy state.

use rust_decimal::Decimal;

pub(crate) fn d(num: i64, scale: u32) -> Decimal {
    Decimal::new(num, scale)
}

pub(crate) fn milli(v: Decimal) -> i64 {
    (v * d(1000, 0)).round_dp(0).to_i64().unwrap_or(0)
}

pub fn verify_metabolic_gate(raw_entropy: &[u8]) -> bool {
    if raw_entropy.len() < 128 {
        return false;
    }
    let mut counts = [0usize; 256];
    for b in raw_entropy {
        counts[*b as usize] += 1;
    }
    let used: Vec<usize> = counts.iter().copied().filter(|c| *c > 0).collect();
    if used.len() < 64 {
        return false;
    }
    let min = *used.iter().min().unwrap_or(&0);
    let max = *used.iter().max().unwrap_or(&0);
    // Reject "too perfect" near-flat synthetic distributions.
    if raw_entropy.len() >= 512 && max.saturating_sub(min) <= 1 {
        return false;
    }
    true
}

trait DecimalInt {
    fn to_i64(self) -> Option<i64>;
}

impl DecimalInt for Decimal {
    fn to_i64(self) -> Option<i64> {
        self.trunc().to_string().parse::<i64>().ok()
    }
}
