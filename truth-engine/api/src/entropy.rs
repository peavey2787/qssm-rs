//! Hardware entropy harvest helpers for sovereign proof seeds.

pub use qssm_he::{harvest, HarvestConfig, Heartbeat, HeError, SensorEntropy};

/// Harvest a 32-byte entropy seed from hardware jitter using default config.
///
/// Calls `qssm_he::harvest(&HarvestConfig::default())` and converts the
/// heartbeat into a domain-separated seed via `Heartbeat::to_seed()`.
///
/// Returns `HeError` if hardware entropy is unavailable on this platform.
pub fn harvest_entropy_seed() -> Result<[u8; 32], HeError> {
    let hb = harvest(&HarvestConfig::default())?;
    Ok(hb.to_seed())
}

/// Harvest with a custom config (e.g. different `raw_bytes` size or sensor list).
pub fn harvest_entropy_seed_with_config(config: &HarvestConfig) -> Result<[u8; 32], HeError> {
    let hb = harvest(config)?;
    Ok(hb.to_seed())
}
