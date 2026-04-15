//! Metabolic control engine ("brain") for adaptive pressure response.
//!
//! Ownership boundary:
//! - Owns only rate/saturation smoothing and `t_min` derivation.
//! - Does not track peer histories or enforce peer policy tiers.

use rust_decimal::Decimal;

use crate::state::GovernorState;
use crate::utils::d;
use crate::GovernorConfig;

#[derive(Debug, Clone)]
pub struct MetabolicEngine {
    cfg: GovernorConfig,
    smoothed_overload: Decimal,
    target_nodes: Decimal,
    prev_current_nodes: Decimal,
    freeze_target: bool,
    pulse_counter: u64,
}

impl MetabolicEngine {
    pub(crate) fn new(cfg: GovernorConfig) -> Self {
        let target_nodes = Decimal::from(cfg.target_nodes);
        Self {
            cfg,
            smoothed_overload: Decimal::ZERO,
            target_nodes,
            prev_current_nodes: Decimal::ZERO,
            freeze_target: false,
            pulse_counter: 0,
        }
    }

    pub(crate) fn update_pressure(&mut self, pulses_in_window: u32, window_secs: u32) {
        if window_secs == 0 {
            return;
        }
        let current_nodes = Decimal::from(pulses_in_window);
        let r_k = current_nodes / Decimal::from(window_secs);
        let rho = if r_k > self.cfg.r_met {
            (r_k - self.cfg.r_met) / self.cfg.r_met
        } else {
            Decimal::ZERO
        };
        if self.prev_current_nodes > Decimal::ZERO {
            let spike = (current_nodes - self.prev_current_nodes) / self.prev_current_nodes;
            self.freeze_target = spike > self.cfg.surge_spike_threshold;
        }
        self.prev_current_nodes = current_nodes;
        self.smoothed_overload =
            (Decimal::ONE - self.cfg.lambda) * self.smoothed_overload + self.cfg.lambda * rho;
        self.pulse_counter = self.pulse_counter.saturating_add(u64::from(pulses_in_window));
        if self.pulse_counter >= self.cfg.target_adjust_interval {
            self.pulse_counter = 0;
            if !self.freeze_target {
                let saturation = if self.target_nodes > Decimal::ZERO {
                    current_nodes / self.target_nodes
                } else {
                    Decimal::ONE
                };
                let adjust = d(5, 2);
                if saturation < self.cfg.saturation_low {
                    self.target_nodes *= Decimal::ONE - adjust;
                } else if saturation > self.cfg.saturation_high {
                    self.target_nodes *= Decimal::ONE + adjust;
                }
            }
        }
    }

    pub(crate) fn t_min(&self) -> Decimal {
        let candidate = self.cfg.t_base * (Decimal::ONE + self.cfg.alpha * self.smoothed_overload);
        candidate
            .max(self.cfg.base_hardware_entropy_floor)
            .min(self.cfg.t_cap)
    }

    pub(crate) fn state(&self) -> GovernorState {
        if self.freeze_target {
            GovernorState::Defending
        } else {
            GovernorState::Expanding
        }
    }
}
