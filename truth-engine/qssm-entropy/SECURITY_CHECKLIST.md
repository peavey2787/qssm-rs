QSSM-ENTROPY "BANK-GRADE" PRODUCTION READINESS CHECKLIST

**Scope:** Pure harvesting + to_seed() crate (`truth-engine/qssm-entropy`)
**Modules:** `core/harvest`, `backend/sensor`, `backend/time`, `backend/windows_tsc`
**Date:** 2026-04-18 (rev 1 — v1.0.0 freeze)

---

**CONTRACT:** Any change that violates or bypasses an item in this checklist
requires a new security review and version bump. This crate is consumed by
`qssm-local-prover`, `qssm-api`, `qssm-desktop`, `zk-examples`, and `mssq-net`.

---

Explicitly confirm each item.

1. PUBLIC SURFACE & BOUNDARY SAFETY

Unsafe Code

[x] `unsafe` exists only in `src/backend/windows_tsc.rs`. This file is gated behind
    `#[cfg(all(windows, target_arch = "x86_64"))]` and uses only `core::arch::x86_64::_rdtsc`.
    It is frozen as a reviewed exception — see "Reviewed Unsafe Exception" section below.

[x] `unsafe` also appears in `src/backend/sensor.rs` for `core::ptr::write_volatile` in the
    `zeroize_inner` method. This prevents the optimizer from eliding zeroing of sensitive bytes.

[x] No other `unsafe` blocks exist in any other file. This crate cannot claim
    `#![forbid(unsafe_code)]` due to the above.

Public API Exposure

[x] The crate re-exports all public items through `lib.rs`. Public surface:
  - 1 struct: `Heartbeat` (protected carrier, private fields)
  - 1 struct: `SensorEntropy` (zeroize-on-drop)
  - 1 struct: `HarvestConfig` (`#[non_exhaustive]`)
  - 1 enum: `HeError` (`#[non_exhaustive]`, `thiserror`)
  - 3 functions: `harvest`, `harvest_with_sensor`, `poll_raw_accelerometer_i16`

[x] `HeError` is `#[non_exhaustive]`. Downstream crates cannot write exhaustive `match` arms.

[x] `HarvestConfig` is `#[non_exhaustive]`. External callers use `HarvestConfig::default()`.

[x] `Heartbeat` fields are private. Accessors: `raw_jitter()`, `sensor_entropy()`, `timestamp()`.
    No public constructor — instances come only from `harvest` / `harvest_with_sensor`.

[x] `DOMAIN_HEARTBEAT_SEED_V1` is `pub(crate)`. Not frozen in the public surface.

[x] `SENSOR_INLINE_CAP` is `pub(crate)`. Not frozen in the public surface.

[x] `unix_timestamp_ns` is `pub(crate)`. Not frozen in the public surface.

Error Handling

[x] No `unwrap()` or `expect()` in production code. All `unwrap()`/`expect()` calls are
    exclusively inside `#[cfg(test)]` modules.

[x] No `panic!`, `todo!`, or `unimplemented!` macros in production code.

[x] `unix_timestamp_ns()` returns `0` if the system clock reports a time before the Unix epoch.
    This is practically unreachable on any supported platform and is documented in the source.

2. HARVESTING BOUNDARY

[x] Unix harvest path uses `openentropy_core::EntropyPool::auto()` and `get_raw_bytes(n)` —
    XOR-combined raw hardware noise, no SHA-256 / DRBG conditioning.

[x] Windows x86_64 harvest path uses TSC delta sampling with spin/yield/sleep jitter.
    Includes density-aware retry loop (`MAX_DENSITY_PASSES = 12`).

[x] Other platforms return `HeError::UnsupportedEntropyPlatform` — no silent fallback.

[x] Harvest fails with `HeError::InsufficientRawBytes` if collected bytes < `MIN_RAW_BYTES` (256).

3. SECRET LIFECYCLE

[x] `Heartbeat` zeroizes `raw_jitter` on drop via `zeroize::Zeroize` (prevents optimizer elision).

[x] `Heartbeat` zeroizes sensor bytes on drop via `SensorEntropy::zeroize_inner()` using
    `core::ptr::write_volatile`.

[x] `Heartbeat` zeros `timestamp` on drop.

[x] `SensorEntropy` independently zeroizes its inner `SmallVec` on drop.

[x] `Heartbeat` does not implement `Clone`. It is move-only to prevent accidental copies
    of sensitive harvesting material.

[x] `Debug` for `Heartbeat` is redacted: shows `[N bytes]` for raw_jitter, never raw content.

[x] `Debug` for `SensorEntropy` is redacted: shows `SensorEntropy([N bytes])` or
    `SensorEntropy(none)`, never raw content.

[x] Best-effort note: `Vec<u8>` and `SmallVec` may leave residual copies in freed heap memory
    that is no longer owned by this crate. Callers requiring stronger guarantees (e.g., mlock,
    encrypted memory) must handle that at the allocator level.

4. PROTECTED CARRIER CONTRACT (Heartbeat)

[x] `Heartbeat` has private fields: `raw_jitter`, `sensor_entropy`, `timestamp`.

[x] Public accessors: `raw_jitter() -> &[u8]`, `sensor_entropy() -> &SensorEntropy`,
    `timestamp() -> u64`.

[x] `to_seed()` returns a 32-byte BLAKE3 digest with domain `b"QSSM-HE-HEARTBEAT-SEED-v1"`,
    binding all three fields with length prefixes.

[x] `to_seed()` is deterministic: same fields produce the same seed.

[x] External construction is not possible. `Heartbeat::new()` is `pub(crate)`.

5. REVIEWED UNSAFE EXCEPTION

[x] File: `src/backend/windows_tsc.rs`
[x] Gated: `#[cfg(all(windows, target_arch = "x86_64"))]`
[x] Intrinsic: `core::arch::x86_64::_rdtsc` — reads the CPU Time Stamp Counter
[x] Safety argument: `_rdtsc` is side-effect-free aside from serializing instruction order.
    The instruction exists on all x86_64 CPUs. No memory is written except local variables.
[x] Occurrences: 6 calls to `unsafe { _rdtsc() }` in `collect_tsc_bytes` and `stir_in_place_tsc_only`
[x] This is the sole production-unsafe boundary. Sensor zeroize uses `write_volatile` which is
    a separate, narrow unsafe for compiler-barrier zeroing.

6. PERMANENTLY OUT OF SCOPE

[x] PMK derivation — removed from this crate. If needed, reintroduce in a separate module.
[x] Application/UI harvest gate — moved to `qssm-desktop`. Not this crate's responsibility.
[x] Density-helper ownership — `verify_density` and `MIN_RAW_BYTES` are owned by `qssm-utils`.
[x] Key schedules — not part of harvesting.

7. TEST COVERAGE

[x] 17 inline tests in `lib.rs`:
  - `test_entropy_uniqueness_consecutive_harvests` — live consecutive harvests yield different seeds
  - `windows_tsc_harvest_passes_density_and_uniqueness` — TSC path density + uniqueness (Windows x86_64)
  - `test_entropy_uniqueness_synthetic` — different jitter → different seed
  - `to_seed_determinism` — same fields → same seed
  - `to_seed_binds_timestamp` — different timestamp → different seed
  - `to_seed_binds_sensor` — different sensor → different seed
  - `accessor_raw_jitter` — raw_jitter() returns correct slice
  - `accessor_sensor_entropy` — sensor_entropy() returns correct reference
  - `accessor_timestamp` — timestamp() returns correct value
  - `debug_redacts_raw_jitter` — Debug output hides raw bytes
  - `debug_redacts_sensor_bytes` — Debug output hides sensor bytes
  - `sensor_entropy_none_is_empty_ref` — none variant is empty
  - `sensor_entropy_from_smallvec_non_empty` — SmallVec construction
  - `sensor_entropy_from_slice_non_empty` — slice construction
  - `sensor_entropy_from_slice_empty` — empty slice → none
  - `sensor_entropy_default_is_none` — Default trait
  - `harvest_config_default_raw_bytes` — default is 8192

[x] All tests pass: `cargo test -p qssm-entropy` — **17/17 passed**.

8. FINAL CERTIFICATION

[x] `unsafe` confined to `windows_tsc.rs` (TSC reads) and `sensor.rs` (`write_volatile` for zeroing).
[x] `HeError` and `HarvestConfig` are `#[non_exhaustive]` with `thiserror`.
[x] No panics, no `todo!`, no `unimplemented!` in production code.
[x] No `unwrap()` or `expect()` in production code.
[x] `Heartbeat` is a protected carrier: private fields, move-only, zeroize-on-drop, redacted Debug.
[x] Secret lifecycle handled for jitter and sensor bytes (best-effort, documented).
[x] PMK, harvest gate, density re-exports permanently removed.
[x] All downstream consumers compile cleanly.
[x] Documentation updated: crate guide, architecture overview, protocol specs.
