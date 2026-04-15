### Documentation map

* [README](../../README.md) — Project home
* [Extended narrative (legacy path)](../qssm-governor.md)
* [Crates overview](../01-architecture/crates-overview.md)
* **This document** — `qssm-governor`: metabolic policy and reputation math (code-accurate)

---

# QSSM-Governor — metabolic policy (`qssm-governor`)

Crate: `crates/qssm-governor`. **Single dependency:** `rust_decimal`. Pure deterministic policy — **no** I/O.

> **Separation:** This crate does **not** implement MSSQ **leader election** or batch semantics; those live in **`mssq-batcher`**. The governor drives **per-peer actions** (accept / throttle / drop) and **metabolic pressure** (`T_min`) from observed pulse rates and density scores.

## Types (`src/lib.rs`)

### `GovernorConfig`

Struct with **Decimal** fields including (non-exhaustive; see source for full list): `n`, `n_min`, `w_secs`, `r_met`, `lambda`, `alpha`, `t_base`, `t_cap`, `theta_w`, `theta_t`, `theta_b`, `m`, `b`, `cooldown_ticks`, `n_rec`, `epsilon`, `throttle_msgs_per_sec`, `bootstrap_peer_threshold`, `bootstrap_global_density`, `base_hardware_entropy_floor`, `target_nodes`, `target_adjust_interval`, `saturation_low`, `saturation_high`, `surge_spike_threshold`.

**`Default`** uses e.g. **`n = 128`**, **`n_min = 16`**, **`bootstrap_global_density = 0.95`**, **`t_base = 1.00`**, **`lambda = 0.15`**, **`alpha = 2.0`**, **`theta_w = 0.10`**, **`theta_t = 0.20`**, **`theta_b = 0.35`**, **`m = 6`**, **`b = 12`**, **`cooldown_ticks = 20`**, **`throttle_msgs_per_sec = 5`**, **`bootstrap_peer_threshold = 2`**, **`target_nodes = 128`**, **`target_adjust_interval = 1024`**, **`r_met = 40`**, etc.

### `GovernorState`

**`Expanding`** | **`Defending`** — from **`MetabolicEngine::state()`**: **Defending** when **`freeze_target`** is true (surge spike), else Expanding.

### `PeerState`

**`Warmup`** (fewer than `n_min` samples) → **Healthy** → **Watch** → **Throttled** → **Blacklisted** (with recovery path back toward Watch via **`try_recover_with`**).

### `PeerAction`

**`Accept`**, **`Throttle { max_msgs_per_sec }`**, **`Drop`**.

### `GovernorDecision` / `DeficitPeer`

Expose `peer_id`, `action`, `state`, **`deficit_milli`** (global average minus peer mean, scaled ×1000 as `i64` via **`milli()`**).

## Score model

- Each **pulse** observation: **`density_ok: bool`** → score **`Decimal::ONE`** or **`Decimal::ZERO`**.
- **`EntropyTracker`**: deque of last **`n`** global scores; **`mean()`** = simple average.
- **`PeerStats`**: per-peer deque of last **`n`** scores + parallel **`rejected`** deque (density failed); **`mean()`**, **`rejected_count()`**, **`over_b_streak`**, **`blacklisted_until_tick`**.

## Metabolic engine

**`update_pressure(pulses_in_window, window_secs)`** (skip if `window_secs == 0`):

- `current_nodes = pulses_in_window` as Decimal.
- **`r_k = current_nodes / window_secs`**; **`rho = max(0, (r_k - r_met) / r_met)`** if `r_k > r_met`, else 0.
- **Spike:** if `prev_current_nodes > 0`, **`spike = (current_nodes - prev_current_nodes) / prev_current_nodes`**; **`freeze_target = spike > surge_spike_threshold`**.
- **`smoothed_overload = (1 - lambda) * smoothed_overload + lambda * rho`**.
- Every **`target_adjust_interval`** pulses, optionally multiplies **`target_nodes`** by `1 ± 0.05` if saturation below **`saturation_low`** or above **`saturation_high`**, unless **`freeze_target`**.

**`t_min()`** = **`clamp(t_base * (1 + alpha * smoothed_overload), base_hardware_entropy_floor, t_cap)`**.

**`current_t_min_milli()`** returns **`t_min`** × 1000 rounded.

## Peer classification (`classify_from`)

Uses **`global_avg`** (see below), thresholds **`theta_w`**, **`theta_t`**, **`theta_b`**, streak **`m`**, rejected count **`b`**, **`cooldown_ticks`**, **`n_min`**, **`n_rec`**, **`epsilon`**.

- **Blacklist** if **`over_b_streak >= m`** OR **`rejected_count() >= b`** → set **`blacklisted_until_tick = tick + cooldown_ticks`**.
- Else if **`deficit = global_avg - peer_mean >= theta_b`** increment streak (streak logic interacts with blacklist).
- **Throttle** if **`deficit >= theta_t`**.
- **Watch** if **`deficit >= theta_w`**.
- Else **Healthy** (if past warmup).

**`try_recover_with`**: after blacklist cooldown, recovery if peer has **`n_rec`** samples and **`mean >= global_avg - epsilon`**.

## Global density average

**`global_density_avg(connected_peers)`**:

- If **`connected_peers <= bootstrap_peer_threshold`** and **`entropy.len() < n_min`**: return **`bootstrap_global_density`**.
- If observed mean is zero and tracker empty: **`bootstrap_global_density`**.
- Else: **`entropy.mean()`** (tracker).

## `verify_metabolic_gate(raw_entropy: &[u8]) -> bool`

Standalone check **used by `mssq-net`** **in addition to** `qssm_he::verify_density`:

- Length **≥ 128**.
- Byte frequency histogram: require **≥ 64** distinct byte values with non-zero count.
- If length **≥ 512**, reject if **`max - min <= 1`** among non-zero buckets (“too perfect” flat distribution).

This is **not** identical to **`verify_density`** (different rules).

## Public API summary

- **`Governor::new` / `default`**
- **`observe_pulse(peer_id, density_ok, timestamp_ns)`** — increments **`tick`**, pushes global + per-peer scores.
- **`update_pressure`**, **`decision_for`**, **`top_deficit_peers`**
- **`global_density_avg_milli`**, **`real_density_avg_milli`**, **`is_bootstrap_mode`**, **`governor_state`**

## Integration

**`mssq-net`** (`crates/mssq-net/src/node/`): **`Governor`** is owned by the spawned task in **`node/mod.rs`** (**`observe_pulse`**, **`update_pressure`** on ticker ticks). **`node/events.rs`** calls **`decision_for`** on inbound heartbeats and rejects when action is **`Drop`**; accepted paths require **`verify_metabolic_gate` ∧ `qssm_he::verify_density`** on decoded envelopes.

## Extended prose

Older narrative formulas and tables live in **[`docs/qssm-governor.md`](../qssm-governor.md)**; where that file disagrees with **`crates/qssm-governor/src/lib.rs`**, **the code wins**.
