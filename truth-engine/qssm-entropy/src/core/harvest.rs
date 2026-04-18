//! Harvest raw jitter from OpenEntropy (`get_raw_bytes`) on **Unix**, TSC deltas on **Windows x86_64**,
//! and optional IMU payloads.
//!
//! **Windows x86_64:** see [`crate::backend::windows_tsc`]—raw CPU jitter from [`core::arch::x86_64::_rdtsc`],
//! not OS-provided randomness.

#[cfg(unix)]
use openentropy_core::EntropyPool;

use accelerometer::{RawAccelerometer, Vector};
use smallvec::SmallVec;

use crate::backend::sensor::{SensorEntropy, SENSOR_INLINE_CAP};
use crate::backend::time::unix_timestamp_ns;
use qssm_utils::MIN_RAW_BYTES;
use crate::HeError;
use crate::Heartbeat;

/// Configuration for how many raw bytes to request from the hardware observatory.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HarvestConfig {
    /// Target byte count (Unix: [`EntropyPool::get_raw_bytes`]; Windows x86_64: TSC collector).
    pub raw_bytes: usize,
}

impl Default for HarvestConfig {
    fn default() -> Self {
        Self { raw_bytes: 8192 }
    }
}

/// Harvest a [`Heartbeat`] with CPU/DRAM jitter only (`sensor_entropy` empty).
///
/// On **Unix**, uses [`EntropyPool::auto`] and [`EntropyPool::get_raw_bytes`]: XOR-combined raw
/// source output without SHA-256 conditioning or a DRBG—see OpenEntropy docs.
///
/// On **Windows x86_64**, uses TSC-based hardware jitter (see module docs).
///
/// **Threading:** OpenEntropy may block during collection; call from a worker thread or
/// `spawn_blocking` in async apps to avoid stalling UI/network threads.
pub fn harvest(config: &HarvestConfig) -> Result<Heartbeat, HeError> {
    harvest_inner(config, SensorEntropy::none())
}

/// Same as [`harvest`], but attaches a packed IMU/motion payload (e.g. from [`poll_raw_accelerometer_i16`]).
pub fn harvest_with_sensor(
    config: &HarvestConfig,
    sensor_entropy: SensorEntropy,
) -> Result<Heartbeat, HeError> {
    harvest_inner(config, sensor_entropy)
}

fn harvest_inner(
    config: &HarvestConfig,
    sensor_entropy: SensorEntropy,
) -> Result<Heartbeat, HeError> {
    let raw_jitter = platform_raw_jitter(config.raw_bytes)?;
    if raw_jitter.len() < MIN_RAW_BYTES {
        return Err(HeError::InsufficientRawBytes {
            got: raw_jitter.len(),
            min: MIN_RAW_BYTES,
        });
    }
    Ok(Heartbeat::new(
        raw_jitter,
        sensor_entropy,
        unix_timestamp_ns(),
    ))
}

#[cfg(unix)]
fn platform_raw_jitter(n: usize) -> Result<Vec<u8>, HeError> {
    let pool = EntropyPool::auto();
    Ok(pool.get_raw_bytes(n))
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn platform_raw_jitter(n: usize) -> Result<Vec<u8>, HeError> {
    crate::backend::windows_tsc::harvest_tsc_jitter(n)
}

#[cfg(all(not(unix), not(all(windows, target_arch = "x86_64"))))]
fn platform_raw_jitter(n: usize) -> Result<Vec<u8>, HeError> {
    let _ = n;
    Err(HeError::UnsupportedEntropyPlatform)
}

/// Sample `count` raw i16 axis readings and pack little-endian into [`SensorEntropy`].
///
/// Intended for embedded drivers where [`RawAccelerometer`] reports `i16` components.
pub fn poll_raw_accelerometer_i16<V>(
    accel: &mut impl RawAccelerometer<V>,
    count: usize,
) -> Result<SensorEntropy, HeError>
where
    V: Vector<Component = i16>,
{
    let mut sv: SmallVec<[u8; SENSOR_INLINE_CAP]> = SmallVec::new();
    for _ in 0..count {
        let v = accel
            .accel_raw()
            .map_err(|e| HeError::Accelerometer(format!("{e:?}")))?;
        for c in v.to_array() {
            sv.extend_from_slice(&c.to_le_bytes());
        }
    }
    Ok(SensorEntropy::from_smallvec(sv))
}
