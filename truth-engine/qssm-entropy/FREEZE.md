# QSSM-ENTROPY v1.0.0 — FROZEN FOR INSTITUTIONAL USE

**Crate:** `qssm-entropy`
**Version:** 1.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Pure harvesting + `to_seed()` crate for device- and user-origin entropy only.

- **Role:** Hardware-anchored raw jitter collection, optional accelerometer payload, and BLAKE3 sovereign seed derivation via `Heartbeat::to_seed()`
- **Platforms:** Unix (OpenEntropy raw capture), Windows x86_64 (TSC delta harvester), other targets return `HeError::UnsupportedEntropyPlatform`
- **Consumers:** `qssm-local-prover`, `qssm-api`, `qssm-desktop`, `zk-examples`, and `mssq-net` (pulse generation)

### Permanently out of scope

These remain permanently out of `qssm-entropy`'s contract: **PMK derivation**, **application/UI policy toggles** (harvest gate), **density-helper ownership** (owned by `qssm-utils`), **key schedules**.

## Frozen Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

### Harvest invariants

- `harvest(config)` returns a `Heartbeat` with `SensorEntropy::none()`
- `harvest_with_sensor(config, sensor_entropy)` returns a `Heartbeat` with the attached sensor payload
- `HarvestConfig` is `#[non_exhaustive]`; default `raw_bytes` is 8192
- Harvest fails with `HeError::InsufficientRawBytes` if raw jitter length < `MIN_RAW_BYTES` (256, defined in `qssm-utils`)
- `poll_raw_accelerometer_i16` packs i16 axis readings into `SensorEntropy`

### Heartbeat invariants (protected carrier)

- `Heartbeat` has **private fields**, accessed via `raw_jitter()`, `sensor_entropy()`, `timestamp()`
- External code cannot construct a `Heartbeat`; instances come only from `harvest` / `harvest_with_sensor`
- `to_seed()` is BLAKE3 with domain `b"QSSM-HE-HEARTBEAT-SEED-v1"`, then length-prefixed raw_jitter, length-prefixed sensor bytes, LE timestamp
- `Heartbeat` is move-only (no `Clone`) and zeroizes jitter + sensor bytes on drop
- `Debug` is redacted: shows byte counts, never raw content

### Error model invariants

- `HeError` is `#[non_exhaustive]` with `thiserror`
- Variants: `OpenEntropy`, `Accelerometer`, `InsufficientRawBytes`, `JitterDensityRejected`, `UnsupportedEntropyPlatform`

### Unsafe exception: Windows TSC backend

- `unsafe` exists **only** in `src/backend/windows_tsc.rs`
- Uses `core::arch::x86_64::_rdtsc` for CPU timestamp counter reads
- Gated behind `#[cfg(all(windows, target_arch = "x86_64"))]`
- `_rdtsc` is side-effect-free aside from serializing instruction order
- This crate **cannot** claim `#![forbid(unsafe_code)]`; the TSC backend is frozen as a reviewed exception

Any change that violates these invariants requires a new security review, a major version bump, and synchronized updates to all downstream consumers.

## What Was Hardened for v1.0.0

### 1. Crate boundary narrowed to harvest-only

Removed `generate_pmk` and PMK constants (Argon2id), the process-global harvest gate (`set_hardware_harvest_enabled` / `hardware_harvest_enabled` / `HarvestDisabled`), and `verify_density` / `MIN_RAW_BYTES` re-exports. Density ownership remains in `qssm-utils`. Harvest gate moved into the desktop crate (application-level policy).

### 2. Heartbeat frozen as protected carrier

Fields made private with accessor methods. `Clone` removed. Redacted `Debug` implementation. `pub(crate) fn new(...)` constructor prevents external construction.

### 3. Secret lifecycle hardening

`Heartbeat` zeroizes `raw_jitter` (`zeroize` crate) and sensor bytes (`write_volatile`) on drop. `SensorEntropy` also zeroizes its inner `SmallVec` on drop. Timestamp zeroed on drop.

### 4. Semver safety

`#[non_exhaustive]` added to `HeError` and `HarvestConfig`. Removed error variants (`Argon2`, `HarvestDisabled`) that no longer apply. `DOMAIN_HEARTBEAT_SEED_V1` and `SENSOR_INLINE_CAP` made `pub(crate)`.

### 5. Timestamp hardened

`unix_timestamp_ns` made `pub(crate)` (not part of frozen public surface). Documented the `0` fallback for pre-epoch clocks.

### 6. Comprehensive test suite

17 tests covering: consecutive harvest uniqueness, Windows TSC density + uniqueness, synthetic uniqueness, to_seed determinism, to_seed field binding (timestamp, sensor), accessor correctness, redacted Debug, SensorEntropy construction variants, and HarvestConfig defaults.

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo check -p qssm-entropy --all-targets` | **Clean** |
| `cargo test -p qssm-entropy` | **17/17 passed** |
| `cargo check -p qssm-local-prover -p qssm-api -p qssm-local-verifier` | **Clean** |
| `cargo check --manifest-path desktop/src-tauri/Cargo.toml` | **Clean** |
| `cargo check -p zk-examples` | **Clean** |
| Stale references (`qssm_entropy::verify_density`, `generate_pmk`, `set_hardware_harvest_enabled`, etc.) | **0 matches** |
| `panic!`, `todo!`, `unimplemented!`, `unwrap()`, `expect()` in production src | **0 matches** |
| `unsafe` only in `src/backend/windows_tsc.rs` | **Confirmed** |
| Windows x86_64 TSC test (density + uniqueness) | **Passed** |

## Target Matrix

| Platform | Harvest path | Status |
|----------|-------------|--------|
| Unix (any arch) | OpenEntropy `get_raw_bytes` | Supported |
| Windows x86_64 | TSC delta jitter (`_rdtsc`) | Supported (reviewed unsafe) |
| Other | Returns `UnsupportedEntropyPlatform` | Graceful error |

## Dependencies (pinned at freeze)

| Crate | Source | Purpose |
|-------|--------|---------|
| `accelerometer` | workspace | `RawAccelerometer` trait for sensor polling |
| `blake3` | workspace | BLAKE3 hashing for `to_seed()` |
| `qssm-utils` | workspace | `MIN_RAW_BYTES` constant, `verify_density` (used in TSC backend) |
| `smallvec` | workspace | `SensorEntropy` inline buffer |
| `thiserror` | workspace | `HeError` derive |
| `zeroize` | local | Secret scrubbing for `Heartbeat::raw_jitter` |
| `openentropy-core` | workspace (Unix only) | Raw entropy pool on Unix |

## Versioning

`qssm-entropy` is consumed from the workspace root with an exact version pin (`=1.0.0`) to prevent accidental upgrades or semver drift.

## File Inventory

```
src/
  lib.rs                  — crate root, Heartbeat (protected carrier), re-exports, 17 tests
  error.rs                — HeError (#[non_exhaustive], thiserror)
  core/
    mod.rs                — module declarations
    harvest.rs            — harvest, harvest_with_sensor, poll_raw_accelerometer_i16, HarvestConfig
  backend/
    mod.rs                — module declarations
    sensor.rs             — SensorEntropy (zeroize-on-drop, redacted Debug)
    time.rs               — unix_timestamp_ns (pub(crate))
    windows_tsc.rs        — TSC jitter harvester (reviewed unsafe, Windows x86_64 only)
```
