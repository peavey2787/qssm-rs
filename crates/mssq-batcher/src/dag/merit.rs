const HOUR: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeritTier {
    Seedling,
    Mature,
    Boosted,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MeritState {
    pub tier: MeritTier,
    pub multiplier: f64,
}

#[must_use]
pub fn merit_maturation(
    now_secs: u64,
    first_seen_secs: u64,
    last_online_secs: u64,
) -> MeritState {
    let age = now_secs.saturating_sub(first_seen_secs);
    let offline_gap = now_secs.saturating_sub(last_online_secs);
    if age < 4 * HOUR {
        return MeritState {
            tier: MeritTier::Seedling,
            multiplier: 0.0,
        };
    }
    if age < 24 * HOUR {
        let ramp = (age - 4 * HOUR) as f64 / (20 * HOUR) as f64;
        return MeritState {
            tier: MeritTier::Mature,
            multiplier: ramp.clamp(0.0, 1.0),
        };
    }
    if age >= 7 * 24 * HOUR && offline_gap <= 10 * 60 {
        return MeritState {
            tier: MeritTier::Boosted,
            multiplier: 1.15,
        };
    }
    MeritState {
        tier: MeritTier::Mature,
        multiplier: 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burn_in_then_ramp_then_boost() {
        let base = 1_000_000_u64;
        let s0 = merit_maturation(base + 3 * HOUR, base, base + 3 * HOUR);
        assert_eq!(s0.multiplier, 0.0);
        let s1 = merit_maturation(base + 14 * HOUR, base, base + 14 * HOUR);
        assert!(s1.multiplier > 0.0 && s1.multiplier < 1.0);
        let s2 = merit_maturation(base + 8 * 24 * HOUR, base, base + 8 * 24 * HOUR);
        assert_eq!(s2.multiplier, 1.15);
    }

    #[test]
    fn loyalty_resets_after_long_offline() {
        let base = 1_000_000_u64;
        let s = merit_maturation(base + 8 * 24 * HOUR, base, base + 8 * 24 * HOUR - 1200);
        assert_eq!(s.multiplier, 1.0);
    }
}
