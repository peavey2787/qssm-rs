### Documentation map

* [README](../../README.md) — Project home
* [Gadget Phase 8 (floor & NIST)](../03-crate-guides/qssm-gadget.md)
* **This document** — QSSM-Entropy: hardware entropy and raw harvest

---

# QSSM-Entropy — hardware entropy (`qssm-entropy`)

Crate: `crates/qssm-entropy`. This specification matches the **current Rust implementation** (`src/lib.rs`, `src/core/{harvest,density,pmk}.rs`, `src/backend/{sensor,time,windows_tsc}.rs`, `src/filter/harvest_gate.rs`).

## Purpose

**Hardware-anchored entropy**: platform-specific **raw jitter** collection, optional **accelerometer** payload, heuristic **density** screening, **BLAKE3** sovereign seed from a **`Heartbeat`**, and **Argon2id PMK** for backups — **distinct** from `qssm-gadget::entropy` (anchor + NIST HTTP), which is software/web beacon mixing.

## Harvest

### Platforms

- **Unix:** `openentropy_core::EntropyPool::auto()` and **`get_raw_bytes(n)`** — XOR-combined raw output (no DRBG path in that mode per upstream).
- **Windows x86_64:** TSC-based jitter (`windows_tsc` module, `_rdtsc`), **not** OS RNG.
- **Else:** `HeError::UnsupportedEntropyPlatform` from `platform_raw_jitter`.

### `HarvestConfig`

- Default **`raw_bytes`: 8192** (requested length for platform collector).

### API

- **`harvest(config)`** → `Heartbeat` with `SensorEntropy::none()`.
- **`harvest_with_sensor(config, sensor_entropy)`** — IMU/motion bytes attached.
- **`poll_raw_accelerometer_i16`** — packs i16 samples into `SensorEntropy`.
- **`guard_harvest_enabled()`** — if **`set_hardware_harvest_enabled(false)`**, harvest returns **`HeError::HarvestDisabled`** (desktop can pause collection).

### Minimum length

Harvest fails with **`InsufficientRawBytes`** if raw jitter length **&lt; `MIN_RAW_BYTES`** (**256**) after collection (see `density.rs`).

## Density gate (`verify_density`)

**Not** a full NIST SP 800-90B certification — **heuristic** parallel statistics on `raw_jitter`:

- Reject if length **&lt; 256**.
- Bit balance: reject if max bit frequency **&gt; 0.99**.
- Byte histogram: reject if any byte **&gt; 95%** of buffer.
- Bit transition rate **&gt; 0.98** (alternation).
- **`is_square_wave_bytes`** pattern rejection.

Uses **rayon** over 4096-byte chunks for bit counts.

**`MIN_RAW_BYTES`** = **256** (public).

## `Heartbeat`

Fields: **`raw_jitter`**, **`sensor_entropy`**, **`timestamp`** (`unix_timestamp_ns()`).

### Sovereign seed

**`to_seed()`**: BLAKE3 with domain **`DOMAIN_HEARTBEAT_SEED_V1`** = `b"QSSM-HE-HEARTBEAT-SEED-v1"`, then length-prefixed `raw_jitter`, length-prefixed sensor bytes, LE `timestamp`.

### Convenience

**`heartbeat.verify_density()`** calls **`verify_density(&self.raw_jitter)`**.

## PMK (`pmk.rs`)

**`generate_pmk(mnemonic_bytes, heartbeat)`** — Argon2id with BLAKE3-derived salt/password binding; constants **`PMK_BYTES`**, **`PMK_M_COST_KIB`**, **`PMK_P_COST`**, **`PMK_T_COST`** as in crate.

## Consumers (workspace)

- **`mssq-net`**: `protocol/pulse.rs` uses **`harvest`** for local heartbeats; inbound messages require **`verify_density(raw_jitter)`**.
- **`qssm-desktop`**: mnemonics from harvest, harvest toggle.

## Related

* **Phase 8 NIST / anchor floor:** [`qssm-gadget::entropy`](../03-crate-guides/qssm-gadget.md) — different code path (HTTP beacon, `entropy_floor`).
