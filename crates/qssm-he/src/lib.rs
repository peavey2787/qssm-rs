//! # QSSM-HE — hardware-anchored entropy
//!
//! **Harvest (Unix):** OpenEntropy [`EntropyPool::get_raw_bytes`] preserves XOR-combined **raw**
//! hardware noise (no SHA-256 / DRBG in that mode—see upstream docs).
//!
//! **Harvest (Windows x86_64):** TSC delta sampling via [`crate::windows_tsc`] (`_rdtsc` + spin /
//! yield / short sleeps)—**no OS RNG**. Other targets without a harvest path return
//! [`HeError::UnsupportedEntropyPlatform`].
//!
//! [`EntropyPool::get_raw_bytes`]: https://docs.rs/openentropy-core/latest/openentropy_core/pool/struct.EntropyPool.html#method.get_raw_bytes
//!
//! **Density:** [`verify_density`] is a **heuristic** screen (bit bias, dominant byte, alternation
//! patterns)—not a full NIST SP 800-90B certification.
//!
//! **Threading:** [`harvest`] and [`verify_density`] run synchronously; OpenEntropy may block during
//! collection. Offload to a worker thread or `spawn_blocking` (Tokio) so UI / network I/O stay responsive.
//!
//! **PMK:** [`generate_pmk`] uses Argon2id with a BLAKE3-derived salt/password binding; same mnemonic +
//! same [`Heartbeat`] yields deterministic output for reproducible backups.
//!

mod backend;
mod core;
mod error;
mod filter;

pub use backend::sensor::{SensorEntropy, SENSOR_INLINE_CAP};
pub use backend::time::unix_timestamp_ns;
pub use qssm_utils::{verify_density, MIN_RAW_BYTES};
pub use core::harvest::{harvest, harvest_with_sensor, poll_raw_accelerometer_i16, HarvestConfig};
pub use core::pmk::{generate_pmk, PMK_BYTES, PMK_M_COST_KIB, PMK_P_COST, PMK_T_COST};
pub use error::HeError;
pub use filter::harvest_gate::{hardware_harvest_enabled, set_hardware_harvest_enabled};

use blake3::Hasher;

/// Domain tag for [`Heartbeat::to_seed`] (sovereign seed / BLAKE3 preimage).
pub const DOMAIN_HEARTBEAT_SEED_V1: &[u8] = b"QSSM-HE-HEARTBEAT-SEED-v1";

/// One hardware snapshot: raw jitter, optional IMU bytes, wall-clock binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    /// Raw buffer from OpenEntropy [`get_raw_bytes`](openentropy_core::pool::EntropyPool::get_raw_bytes).
    pub raw_jitter: Vec<u8>,
    /// Optional motion/accelerometer payload; [`SensorEntropy::none`] on typical desktops.
    pub sensor_entropy: SensorEntropy,
    /// Nanoseconds since Unix epoch (see [`unix_timestamp_ns`]).
    pub timestamp: u64,
}

impl Heartbeat {
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

    /// Statistical density gate on [`Self::raw_jitter`] (see [`verify_density`]).
    #[must_use]
    pub fn verify_density(&self) -> bool {
        verify_density(&self.raw_jitter)
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
            h1.verify_density(),
            "TSC raw jitter must satisfy verify_density heuristics"
        );
        let h2 = harvest(&cfg).expect("tsc harvest 2");
        assert!(h2.verify_density());
        assert_ne!(h1.to_seed(), h2.to_seed());
    }

    #[test]
    fn test_entropy_uniqueness_synthetic() {
        let a = Heartbeat {
            raw_jitter: vec![1u8; 1024],
            sensor_entropy: SensorEntropy::none(),
            timestamp: 1,
        };
        let b = Heartbeat {
            raw_jitter: vec![2u8; 1024],
            sensor_entropy: SensorEntropy::none(),
            timestamp: 1,
        };
        assert_ne!(a.to_seed(), b.to_seed());
    }

    #[test]
    fn test_density_rejection() {
        let zeros = vec![0u8; 1024];
        assert!(!verify_density(&zeros));

        let mut alt = vec![0u8; 1024];
        for i in (0..1024).step_by(2) {
            alt[i] = 0xff;
        }
        assert!(!verify_density(&alt));
    }

    #[test]
    fn test_pmk_derivation() {
        let mnemonic = b"test mnemonic seed bytes";
        let hb = Heartbeat {
            raw_jitter: (0u8..200).collect::<Vec<_>>(),
            sensor_entropy: SensorEntropy::none(),
            timestamp: 42,
        };
        let p1 = generate_pmk(mnemonic, &hb).expect("pmk");
        let p2 = generate_pmk(mnemonic, &hb).expect("pmk");
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), PMK_BYTES);
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
}
