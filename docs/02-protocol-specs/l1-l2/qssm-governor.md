### Documentation map

* [README](../../README.md) � Project home
* [Architecture overview](../01-architecture/architecture-overview.md)
* [MSSQ � Egalitarian rollup](./mssq.md)
* [QSSM-LE � Engine A](./qssm-le-engine-a.md)
* [QSSM-MS � Engine B](./qssm-ms-engine-b.md)
* **This document** � QSSM Governor (Metabolic DAA)

---

# QSSM-Governor (The Brain)
### Metabolic DAA, entropy merit, and Sybil purging policy

---

## Abstract

`qssm-governor` defines the policy layer that adapts network pressure and peer merit using hardware-anchored entropy quality from `qssm-entropy`. It formalizes four core functions:

1. **Entropy density tracking** over a moving horizon of recent pulses/blocks.
2. **Metabolic DAA** that raises minimum work difficulty \(T_{min}\) when pulse throughput exceeds metabolic capacity.
3. **Sybil purging** through deterministic throttling/blacklisting of low-merit PeerIDs.
4. **Integration hooks** for `mssq-net` to drop/deprioritize packets from penalized peers.

This specification is intentionally deterministic and implementation-neutral: any compliant node should converge to the same penalty decisions under the same input stream.

---

## 1. Terms and observables

Let:

- \(p_i\): i-th pulse observed by a node.
- \(t_i\): local receive timestamp for pulse \(p_i\), in nanoseconds.
- \(d_i \in \{0,1\}\): pulse density verdict from `qssm_utils::verify_density(raw_jitter)`.
- \(s_i \in [0,1]\): scalar density score (normative mapping below).
- \(peer_i\): originating PeerID of pulse \(p_i\).
- \(N\): moving window length for density tracking.
- \(W\): wall-clock throughput window in seconds.
- \(\lambda\): exponential smoothing factor for pressure adaptation.

### Normative scalar score mapping

Baseline (`verify_density` is boolean in current code):

- If `verify_density(raw_jitter) == true`, set \(s_i = 1.0\).
- Else set \(s_i = 0.0\).

Forward-compatible extension (if qssm-entropy later emits a continuous score) may replace the mapping, but MUST preserve \(s_i=0\) for synthetic/rejected entropy.

---

## 2. Entropy density tracking

### 2.1 Global moving average

Maintain the last \(N\) scores:
\[
\mathcal{S}_N = \{s_{k-N+1}, ..., s_k\}
\]
with global moving average:
\[
\mu_k = \frac{1}{N} \sum_{j=k-N+1}^{k} s_j
\]

Recommended default: **\(N = 128\)** pulses.

### 2.2 Per-peer moving average

For each peer \(u\), maintain last \(N_u\) scores from that peer:
\[
\mu_k^{(u)} = \frac{1}{N_u} \sum s_j^{(u)}
\]
with \(N_u \le N\). If \(N_u < N_{min}\), peer is in warmup mode.

Recommended defaults:

- \(N_{min} = 16\) before hard sanctions.
- Warmup peers are throttled conservatively but not blacklisted.

### 2.3 Deficit metric

Define peer merit deficit against network baseline:
\[
\Delta_k^{(u)} = \mu_k - \mu_k^{(u)}
\]

- \(\Delta_k^{(u)} > 0\): peer entropy quality below network average.
- \(\Delta_k^{(u)} \le 0\): peer is at/above baseline.

---

## 3. Metabolic DAA and \(T_{min}\)

### 3.1 Throughput pressure

Let pulse throughput in last \(W\) seconds be:
\[
R_k = \frac{\#\{p_i \mid t_i \in [t_k - W, t_k]\}}{W}
\]

Let \(R_{met}\) be the metabolic threshold (target sustainable pulses/s).

Define normalized overload:
\[
\rho_k = \max\left(0, \frac{R_k - R_{met}}{R_{met}}\right)
\]

Recommended defaults:

- \(W = 30\) s
- \(R_{met} = 40\) pulses/s (tune per deployment)

### 3.2 Smoothed pressure

Use EMA smoothing:
\[
\bar{\rho}_k = (1 - \lambda)\bar{\rho}_{k-1} + \lambda \rho_k
\]

Recommended default: \(\lambda = 0.15\).

### 3.3 Difficulty function

Let \(T_{base}\) be baseline minimum work target. Define:
\[
T_{min,k} = T_{base} \cdot (1 + \alpha \bar{\rho}_k)
\]
with cap:
\[
T_{min,k} = \min(T_{cap}, T_{min,k})
\]

Recommended defaults:

- \(\alpha = 1.5\) (aggressiveness)
- \(T_{cap} = 4 \cdot T_{base}\)

Interpretation: when throughput exceeds metabolic capacity, nodes require higher effective work and reduce acceptance of low-merit traffic.

---

## 4. Sybil purging policy

Sybil defense is merit-driven and deterministic over \((\mu_k, \mu_k^{(u)}, \Delta_k^{(u)})\).

### 4.1 State machine

Each peer is in one state:

1. `Healthy`
2. `Watch`
3. `Throttled`
4. `Blacklisted`

### 4.2 Transition rules

Given thresholds \(\theta_w < \theta_t < \theta_b\):

- If \(\Delta_k^{(u)} < \theta_w\): `Healthy`.
- If \(\theta_w \le \Delta_k^{(u)} < \theta_t\): `Watch`.
- If \(\theta_t \le \Delta_k^{(u)} < \theta_b\): `Throttled`.
- If \(\Delta_k^{(u)} \ge \theta_b\) for \(M\) consecutive evaluation ticks OR rejected density count exceeds \(B\): `Blacklisted`.

Recommended defaults:

- \(\theta_w = 0.10\)
- \(\theta_t = 0.20\)
- \(\theta_b = 0.35\)
- \(M = 6\) ticks
- \(B = 12\) rejected pulses in window

### 4.3 Recovery

A blacklisted peer may recover only after cooldown \(C\) and proving quality >= baseline:

- cooldown: \(C = 10\) min recommended.
- require \(N_{rec}\) accepted pulses with \(\mu^{(u)} \ge \mu_k - \epsilon\).

Recommended defaults:

- \(N_{rec} = 32\)
- \(\epsilon = 0.05\)

---

## 5. Packet-level enforcement in mssq-net

`qssm-governor` must expose a pure policy API that `mssq-net` can call before admitting traffic.

### 5.1 Proposed API surface (normative intent)

```rust
pub enum PeerAction {
    Accept,
    Throttle { max_msgs_per_sec: u32 },
    Drop,
}

pub struct GovernorDecision {
    pub peer_id: libp2p::PeerId,
    pub action: PeerAction,
    pub deficit: f64,
    pub state: PeerState,
}
```

And evaluation entrypoints:

- `observe_pulse(peer_id, density_ok, timestamp)`
- `update_pressure(total_pulses_in_window, window_secs)`
- `decision_for(peer_id) -> GovernorDecision`
- `current_t_min() -> f64`

### 5.2 Integration points in mssq-net

At minimum, wire decision checks at these points:

1. **Gossipsub inbound validation**
   - Before acceptance, evaluate `decision_for(peer)`.
   - `Drop` => reject message and apply gossip penalty/report.
   - `Throttle` => rate-limit per-peer topic ingress.

2. **Connection manager / inbound streams**
   - For blacklisted peers, deny new inbound substreams.
   - For throttled peers, cap concurrent streams and message budget.

3. **Relay reservation policy**
   - Low-merit peers should not consume relay quota while in `Blacklisted`.

4. **Metrics and dashboard**
   - Export peer state counts, current \(T_{min}\), and global \(\mu_k\).

---

## 6. Determinism and anti-evasion constraints

- Use fixed-size windows and explicit tie-breaks; avoid floating ambiguity in comparisons by rounding to fixed precision (e.g., 1e-6).
- Process pulses in canonical order `(receive_ts, peer_id, message_id)` for window updates.
- Reject malformed pulse envelopes before scoring.
- A peer cannot improve merit via message volume alone; only accepted high-density pulses affect recovery.

---

## 7. Baseline parameters (v1.0)

| Parameter | Default |
|---|---:|
| `N` | 128 |
| `N_min` | 16 |
| `W` | 30 s |
| `R_met` | 40 pulses/s |
| `lambda` | 0.15 |
| `alpha` | 1.5 |
| `T_cap / T_base` | 4.0 |
| `theta_w` | 0.10 |
| `theta_t` | 0.20 |
| `theta_b` | 0.35 |
| `M` | 6 |
| `B` | 12 |
| `C` | 10 min |
| `N_rec` | 32 |
| `epsilon` | 0.05 |

All values are chain-configurable; defaults are operational starting points.

---

## 8. Implementation notes for qssm-governor crate

Planned crate responsibilities:

- maintain rolling windows and per-peer state maps,
- compute \(\mu_k\), \(\mu_k^{(u)}\), \(\Delta_k^{(u)}\), \(T_{min,k}\),
- emit deterministic `GovernorDecision` events,
- provide stateless serialization of decisions for dashboards and logs.

`qssm-governor` MUST remain framework-agnostic (no libp2p runtime dependency). `mssq-net` owns transport hooks and packet-drop execution.

---

## 9. Security posture

- **Primary signal:** hardware entropy density from `qssm-entropy`.
- **Primary objective:** suppress synthetic/Sybil pulse floods before they saturate gossip mesh.
- **Failure mode:** if global entropy quality degrades, governor raises \(T_{min}\) and tightens ingress budgets until conditions normalize.

This is the formal policy baseline for implementing The Brain (`qssm-governor`).
