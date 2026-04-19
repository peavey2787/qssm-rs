//! # qssm-entropy — hardware-anchored entropy harvesting
//!
//! Pure harvesting + `to_seed()` crate for device- and user-origin entropy only.
//! **All entropy is derived from hardware jitter — no OS RNG, CSPRNG, or pseudorandomness.**
//!
//! **x86 / x86_64 (Windows, Linux, macOS):** Time Stamp Counter (TSC) delta sampling via
//! `_rdtsc` + spin / yield / short sleeps.
//!
//! **aarch64 (Linux, macOS, Windows):** `CNTVCT_EL0` virtual timer counter delta sampling,
//! same jitter algorithm.
//!
//! Other architectures return [`HeError::UnsupportedEntropyPlatform`].
//!
//! See [`backend::jitter`] for the collection algorithm.
//!
//! **Threading:** [`harvest`] runs synchronously. Offload to a worker thread or
//! `spawn_blocking` (Tokio) so UI / network I/O stay responsive.

mod backend;
mod core;
mod error;

pub use backend::sensor::SensorEntropy;
pub use core::harvest::{harvest, harvest_with_sensor, poll_raw_accelerometer_i16, HarvestConfig};
pub use error::HeError;

use blake3::Hasher;
use std::fmt;
use zeroize::Zeroize;

/// Domain tag for [`Heartbeat::to_seed`] (sovereign seed / BLAKE3 preimage).
pub(crate) const DOMAIN_HEARTBEAT_SEED_V1: &[u8] = b"QSSM-HE-HEARTBEAT-SEED-v1";

/// One hardware snapshot: raw jitter, optional IMU bytes, wall-clock binding.
///
/// Fields are private; use the accessor methods to inspect contents.
/// `Heartbeat` zeroizes sensitive bytes (jitter and sensor payload) on drop.
#[derive(PartialEq, Eq)]
pub struct Heartbeat {
    raw_jitter: Vec<u8>,
    sensor_entropy: SensorEntropy,
    timestamp: u64,
}

impl Heartbeat {
    /// Create a new `Heartbeat` (crate-internal only).
    pub(crate) fn new(raw_jitter: Vec<u8>, sensor_entropy: SensorEntropy, timestamp: u64) -> Self {
        Self {
            raw_jitter,
            sensor_entropy,
            timestamp,
        }
    }

    /// Raw jitter bytes from the hardware entropy source.
    #[must_use]
    pub fn raw_jitter(&self) -> &[u8] {
        &self.raw_jitter
    }

    /// Optional motion/accelerometer payload; empty on typical desktops.
    #[must_use]
    pub fn sensor_entropy(&self) -> &SensorEntropy {
        &self.sensor_entropy
    }

    /// Nanoseconds since Unix epoch captured at harvest time.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Consolidate fields into a 32-byte **Sovereign Seed** (BLAKE3).
    #[must_use]
    pub fn to_seed(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(DOMAIN_HEARTBEAT_SEED_V1);
        h.update(&(self.raw_jitter.len() as u64).to_le_bytes());
        h.update(&self.raw_jitter);
        h.update(&(self.sensor_entropy.as_ref().len() as u64).to_le_bytes());
        h.update(self.sensor_entropy.as_ref());
        h.update(&self.timestamp.to_le_bytes());
        *h.finalize().as_bytes()
    }
}

impl fmt::Debug for Heartbeat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Heartbeat")
            .field(
                "raw_jitter",
                &format_args!("[{} bytes]", self.raw_jitter.len()),
            )
            .field("sensor_entropy", &self.sensor_entropy)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.raw_jitter.zeroize();
        self.sensor_entropy.zeroize_inner();
        self.timestamp = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    #[test]
    fn test_entropy_uniqueness_consecutive_harvests() {
        let cfg = HarvestConfig::default();
        let a = harvest(&cfg).expect("harvest a");
        let b = harvest(&cfg).expect("harvest b");
        assert_ne!(a.to_seed(), b.to_seed());
    }

    /// Windows x86_64: hardware TSC path must pass density and yield distinct sovereign seeds.
    #[cfg(all(windows, target_arch = "x86_64"))]
    #[test]
    fn windows_tsc_harvest_passes_density_and_uniqueness() {
        let cfg = HarvestConfig { raw_bytes: 2048 };
        let h1 = harvest(&cfg).expect("tsc harvest");
        assert!(
            qssm_utils::verify_density(h1.raw_jitter()),
            "TSC raw jitter must satisfy verify_density heuristics"
        );
        let h2 = harvest(&cfg).expect("tsc harvest 2");
        assert!(qssm_utils::verify_density(h2.raw_jitter()));
        assert_ne!(h1.to_seed(), h2.to_seed());
    }

    #[test]
    fn test_entropy_uniqueness_synthetic() {
        let a = Heartbeat::new(vec![1u8; 1024], SensorEntropy::none(), 1);
        let b = Heartbeat::new(vec![2u8; 1024], SensorEntropy::none(), 1);
        assert_ne!(a.to_seed(), b.to_seed());
    }

    #[test]
    fn sensor_entropy_none_is_empty_ref() {
        let s = SensorEntropy::none();
        assert!(s.is_empty());
        assert!(s.as_ref().is_empty());
    }

    #[test]
    fn sensor_entropy_from_smallvec_non_empty() {
        let v = smallvec![1u8, 2, 3];
        let s = SensorEntropy::from_smallvec(v);
        assert_eq!(s.as_ref(), &[1, 2, 3]);
    }

    // --- Phase 3 freeze tests ---

    #[test]
    fn to_seed_determinism() {
        let a = Heartbeat::new(vec![42u8; 512], SensorEntropy::none(), 999);
        let b = Heartbeat::new(vec![42u8; 512], SensorEntropy::none(), 999);
        assert_eq!(
            a.to_seed(),
            b.to_seed(),
            "same fields must produce the same seed"
        );
    }

    #[test]
    fn to_seed_binds_timestamp() {
        let a = Heartbeat::new(vec![1u8; 512], SensorEntropy::none(), 1);
        let b = Heartbeat::new(vec![1u8; 512], SensorEntropy::none(), 2);
        assert_ne!(
            a.to_seed(),
            b.to_seed(),
            "different timestamp must yield different seed"
        );
    }

    #[test]
    fn to_seed_binds_sensor() {
        let a = Heartbeat::new(vec![1u8; 512], SensorEntropy::none(), 1);
        let b = Heartbeat::new(vec![1u8; 512], SensorEntropy::from_slice(&[0xAA; 16]), 1);
        assert_ne!(
            a.to_seed(),
            b.to_seed(),
            "different sensor payload must yield different seed"
        );
    }

    #[test]
    fn accessor_raw_jitter() {
        let jitter = vec![7u8; 64];
        let hb = Heartbeat::new(jitter.clone(), SensorEntropy::none(), 10);
        assert_eq!(hb.raw_jitter(), &jitter[..]);
    }

    #[test]
    fn accessor_sensor_entropy() {
        let se = SensorEntropy::from_slice(&[1, 2, 3]);
        let hb = Heartbeat::new(vec![0u8; 64], se.clone(), 10);
        assert_eq!(hb.sensor_entropy().as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn accessor_timestamp() {
        let hb = Heartbeat::new(vec![0u8; 64], SensorEntropy::none(), 42);
        assert_eq!(hb.timestamp(), 42);
    }

    #[test]
    fn debug_redacts_raw_jitter() {
        let hb = Heartbeat::new(vec![0xDE, 0xAD], SensorEntropy::none(), 1);
        let dbg = format!("{hb:?}");
        assert!(
            !dbg.contains("222") && !dbg.contains("0xDE") && !dbg.contains("dead"),
            "Debug must not leak raw jitter bytes: {dbg}"
        );
        assert!(
            dbg.contains("[2 bytes]"),
            "Debug must show byte count: {dbg}"
        );
    }

    #[test]
    fn debug_redacts_sensor_bytes() {
        let hb = Heartbeat::new(vec![0u8; 8], SensorEntropy::from_slice(&[0xBE, 0xEF]), 1);
        let dbg = format!("{hb:?}");
        assert!(
            !dbg.contains("190") && !dbg.contains("0xBE") && !dbg.contains("beef"),
            "Debug must not leak sensor bytes: {dbg}"
        );
        assert!(
            dbg.contains("2 bytes"),
            "Debug must show sensor byte count: {dbg}"
        );
    }

    #[test]
    fn sensor_entropy_from_slice_non_empty() {
        let s = SensorEntropy::from_slice(&[10, 20, 30]);
        assert_eq!(s.as_ref(), &[10, 20, 30]);
        assert!(!s.is_empty());
    }

    #[test]
    fn sensor_entropy_from_slice_empty() {
        let s = SensorEntropy::from_slice(&[]);
        assert!(s.is_empty());
    }

    #[test]
    fn sensor_entropy_default_is_none() {
        let s = SensorEntropy::default();
        assert!(s.is_empty());
    }

    #[test]
    fn harvest_config_default_raw_bytes() {
        let cfg = HarvestConfig::default();
        assert_eq!(cfg.raw_bytes, 8192);
    }
}
