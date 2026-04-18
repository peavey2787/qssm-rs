# qssm-entropy

Hardware-anchored raw entropy harvest, `Heartbeat`, and sovereign seed (`to_seed`).

**Version:** 1.0.0 (frozen)
**Status:** Frozen for institutional use — see [FREEZE.md](FREEZE.md)

## Role

Pure harvesting + `to_seed()` crate for device- and user-origin entropy only. Sits at **Layer 4** alongside `qssm-local-prover` in the six-layer Truth Engine stack.

## Public API

| Item | Kind | Description |
|------|------|-------------|
| `harvest` | fn | Harvest a `Heartbeat` with CPU/DRAM jitter only |
| `harvest_with_sensor` | fn | Harvest with attached IMU/motion payload |
| `poll_raw_accelerometer_i16` | fn | Pack i16 axis readings into `SensorEntropy` |
| `Heartbeat` | struct | Protected carrier: private fields, accessors, `to_seed()`, zeroize-on-drop |
| `SensorEntropy` | struct | Optional accelerometer payload, zeroize-on-drop |
| `HarvestConfig` | struct | `#[non_exhaustive]`, default `raw_bytes = 8192` |
| `HeError` | enum | `#[non_exhaustive]`, 5 variants |

## File Map

```
src/
  lib.rs              Heartbeat, re-exports, 17 tests
  error.rs            HeError
  core/
    harvest.rs        harvest, harvest_with_sensor, HarvestConfig
  backend/
    sensor.rs         SensorEntropy
    time.rs           unix_timestamp_ns (pub(crate))
    windows_tsc.rs    TSC jitter harvester (reviewed unsafe)
```

## Freeze Artifacts

- [FREEZE.md](FREEZE.md) — frozen contract, verification evidence, target matrix
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md) — production readiness checklist
