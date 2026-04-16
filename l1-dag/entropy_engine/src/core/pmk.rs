//! Physical Master Key: Argon2id with deterministic salt from mnemonic + hardware snapshot.

use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;

use crate::Heartbeat;

/// PMK output size: 4096 bits (cold-storage backup blob).
pub const PMK_BYTES: usize = 512;

/// Argon2 memory cost (KiB). Tuned for backup at-rest; adjust for UX.
pub const PMK_M_COST_KIB: u32 = 32_768;
/// Argon2 time cost (iterations).
pub const PMK_T_COST: u32 = 4;
/// Argon2 parallelism (lanes).
pub const PMK_P_COST: u32 = 1;

/// Derive a deterministic **Physical Master Key** from the mnemonic and the current heartbeat material.
///
/// Salt is derived with BLAKE3 over a fixed domain so the same `(mnemonic, heartbeat)` yields the same
/// PMK (see tests). **Backups** should retain the mnemonic and, if you rely on hardware binding, a
/// persisted [`Heartbeat`] snapshot.
///
/// Uses Argon2id with [`PMK_M_COST_KIB`], [`PMK_T_COST`], [`PMK_P_COST`], output [`PMK_BYTES`].
pub fn generate_pmk(
    mnemonic_seed: &[u8],
    heartbeat: &Heartbeat,
) -> Result<Vec<u8>, crate::HeError> {
    // Fast Argon2 params when running this crate's unit tests; production uses [`PMK_M_COST_KIB`].
    let m_kib = if cfg!(test) { 256u32 } else { PMK_M_COST_KIB };
    let params = Params::new(m_kib, PMK_T_COST, PMK_P_COST, Some(PMK_BYTES))
        .map_err(|e| crate::HeError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut salt_hasher = Hasher::new();
    salt_hasher.update(b"qssm-he.pmk.salt.v1");
    salt_hasher.update(&(mnemonic_seed.len() as u64).to_le_bytes());
    salt_hasher.update(mnemonic_seed);
    salt_hasher.update(&(heartbeat.raw_jitter.len() as u64).to_le_bytes());
    salt_hasher.update(&heartbeat.raw_jitter);
    salt_hasher.update(heartbeat.sensor_entropy.as_ref());
    salt_hasher.update(&heartbeat.timestamp.to_le_bytes());
    let salt_digest = salt_hasher.finalize();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_digest.as_bytes()[..16]);

    let mut pwd_hasher = Hasher::new();
    pwd_hasher.update(b"qssm-he.pmk.pwd.v1");
    pwd_hasher.update(&(mnemonic_seed.len() as u64).to_le_bytes());
    pwd_hasher.update(mnemonic_seed);
    pwd_hasher.update(&(heartbeat.raw_jitter.len() as u64).to_le_bytes());
    pwd_hasher.update(&heartbeat.raw_jitter);
    pwd_hasher.update(heartbeat.sensor_entropy.as_ref());
    pwd_hasher.update(&heartbeat.timestamp.to_le_bytes());
    let pwd_digest = pwd_hasher.finalize();
    let password = pwd_digest.as_bytes();

    let mut out = vec![0u8; PMK_BYTES];
    argon2
        .hash_password_into(password, &salt, &mut out)
        .map_err(|e| crate::HeError::Argon2(e.to_string()))?;
    Ok(out)
}
