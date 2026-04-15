use rust_decimal::Decimal;

use crate::tracker::peer_stats::PeerStats;
use crate::GovernorConfig;

use super::types::PeerState;

pub(crate) fn classify_from(
    cfg: &GovernorConfig,
    tick: u64,
    stats: &mut PeerStats,
    global_avg: Decimal,
) -> PeerState {
    if let Some(until_tick) = stats.blacklisted_until_tick {
        if tick < until_tick {
            return PeerState::Blacklisted;
        }
    }
    if stats.scores_len() < cfg.n_min {
        return PeerState::Warmup;
    }
    let deficit = global_avg - stats.mean();
    if deficit >= cfg.theta_b {
        stats.over_b_streak = stats.over_b_streak.saturating_add(1);
    } else {
        stats.over_b_streak = 0;
    }
    if stats.over_b_streak >= cfg.m || stats.rejected_count() >= cfg.b {
        stats.blacklisted_until_tick = Some(tick.saturating_add(cfg.cooldown_ticks));
        stats.accepted_since_blacklist = 0;
        return PeerState::Blacklisted;
    }
    if deficit >= cfg.theta_t {
        return PeerState::Throttled;
    }
    if deficit >= cfg.theta_w {
        return PeerState::Watch;
    }
    PeerState::Healthy
}

pub(crate) fn try_recover_with(cfg: &GovernorConfig, stats: &PeerStats, global_avg: Decimal) -> bool {
    if stats.scores_len() < cfg.n_rec {
        return false;
    }
    let mean = stats.mean();
    mean >= global_avg - cfg.epsilon
}

pub(crate) fn classify_peek(
    cfg: &GovernorConfig,
    tick: u64,
    stats: &PeerStats,
    global_avg: Decimal,
) -> PeerState {
    if let Some(until_tick) = stats.blacklisted_until_tick {
        if tick < until_tick {
            return PeerState::Blacklisted;
        }
    }
    if stats.scores_len() < cfg.n_min {
        return PeerState::Warmup;
    }
    let deficit = global_avg - stats.mean();
    if stats.over_b_streak >= cfg.m || stats.rejected_count() >= cfg.b || deficit >= cfg.theta_b {
        return PeerState::Blacklisted;
    }
    if deficit >= cfg.theta_t {
        return PeerState::Throttled;
    }
    if deficit >= cfg.theta_w {
        return PeerState::Watch;
    }
    PeerState::Healthy
}
