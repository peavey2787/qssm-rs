//! Phase 7 — **Lattice handshake**: sovereign digest coefficient-vector as the commitment target for Engine A (`qssm-le`).
//!
//! Normative constant **`BRIDGE_Q`** must match **`qssm_le::Q`** (verified in **`verify_handshake_with_le`** under **`lattice-bridge`**).

use std::fs;
use std::path::Path;

/// Must match **`qssm_le::Q`** — MLWE modulus for **`R_q = Z_q[X]/(X^256+1)`**.
pub const BRIDGE_Q: u32 = 8_380_417;
pub const DIGEST_COEFF_VECTOR_SIZE: usize = 64;

/// Exclusive upper bound for the legacy **30‑bit** limb (`2^30`, compatibility-only path).
pub const MAX_LIMB_EXCLUSIVE: u64 = 1u64 << 30;

#[derive(Debug, thiserror::Error)]
pub enum LatticeBridgeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing or invalid field {0}")]
    MissingField(&'static str),
    #[error("digest coeff vector mismatch between prover_package and sovereign witness")]
    DigestCoeffVectorMismatch,
    #[error("limb mismatch: prover_package has {pkg} but sovereign witness has {sov}")]
    LimbMismatch { pkg: u64, sov: u64 },
    #[error("nist_included mismatch: prover_package nist_beacon_included={pkg} but sovereign public.nist_included={sov}")]
    NistIncludedMismatch { pkg: bool, sov: bool },
    #[error("message limb {0} out of 30-bit range (must be < 2^30)")]
    LimbOutOfRange30(u64),
    #[error("message limb {0} is not canonically liftable below BRIDGE_Q (must be < {BRIDGE_Q})")]
    LimbNotInField(u64),
    #[error("RqPoly::embed_constant coeff0 mismatch: expected {expected}, got {got}")]
    EmbedCoeff0Mismatch { expected: u32, got: u32 },

    #[cfg(feature = "lattice-bridge")]
    #[error(transparent)]
    Le(#[from] qssm_le::LeError),
}

/// **`m ↦ coeff₀`** with **no modular reduction** when **`m < 2^30`** and **`m < BRIDGE_Q`**: then **`RqPoly::embed_constant(m).0[0] == m as u32`**.
#[must_use]
pub fn limb_to_q_coeff0(m: u64) -> Result<u32, LatticeBridgeError> {
    if m >= MAX_LIMB_EXCLUSIVE {
        return Err(LatticeBridgeError::LimbOutOfRange30(m));
    }
    if m >= u64::from(BRIDGE_Q) {
        return Err(LatticeBridgeError::LimbNotInField(m));
    }
    Ok(m as u32)
}

fn parse_digest_coeff_vector(v: &serde_json::Value, path: &'static str) -> Result<[u32; DIGEST_COEFF_VECTOR_SIZE], LatticeBridgeError> {
    let arr = v.as_array().ok_or(LatticeBridgeError::MissingField(path))?;
    if arr.len() != DIGEST_COEFF_VECTOR_SIZE {
        return Err(LatticeBridgeError::MissingField(path));
    }
    let mut out = [0u32; DIGEST_COEFF_VECTOR_SIZE];
    for (i, val) in arr.iter().enumerate() {
        out[i] = val.as_u64().ok_or(LatticeBridgeError::MissingField(path))? as u32;
    }
    Ok(out)
}

/// Load package/witness JSON and assert digest coefficient-vector equality plus legacy limb consistency.
pub fn verify_limb_binding_json(package_dir: &Path) -> Result<(), LatticeBridgeError> {
    let pkg_path = package_dir.join("prover_package.json");
    let pkg_raw = fs::read_to_string(&pkg_path)?;
    let pkg: serde_json::Value = serde_json::from_str(&pkg_raw)?;
    let limb_pkg = pkg["engine_a_public"]["message_limb_u30"].as_u64().ok_or(
        LatticeBridgeError::MissingField("engine_a_public.message_limb_u30"),
    )?;
    let rel = pkg["artifacts"]["sovereign_witness_json"].as_str().ok_or(
        LatticeBridgeError::MissingField("artifacts.sovereign_witness_json"),
    )?;
    let sovereign_path = package_dir.join(rel);
    let sov_raw = fs::read_to_string(&sovereign_path)?;
    let sov: serde_json::Value = serde_json::from_str(&sov_raw)?;
    let pkg_coeffs = parse_digest_coeff_vector(
        &pkg["engine_a_public"]["digest_coeff_vector_u4"],
        "engine_a_public.digest_coeff_vector_u4",
    )?;
    let sov_coeffs = parse_digest_coeff_vector(
        &sov["public"]["digest_coeff_vector_u4"],
        "public.digest_coeff_vector_u4",
    )?;
    if pkg_coeffs != sov_coeffs {
        return Err(LatticeBridgeError::DigestCoeffVectorMismatch);
    }
    let limb_sov = sov["public"]["message_limb_u30"]
        .as_u64()
        .ok_or(LatticeBridgeError::MissingField("public.message_limb_u30"))?;
    if limb_pkg != limb_sov {
        return Err(LatticeBridgeError::LimbMismatch {
            pkg: limb_pkg,
            sov: limb_sov,
        });
    }
    if limb_pkg >= MAX_LIMB_EXCLUSIVE {
        return Err(LatticeBridgeError::LimbOutOfRange30(limb_pkg));
    }
    if let Some(pkg_nist) = pkg.get("nist_beacon_included").and_then(|v| v.as_bool()) {
        let sov_nist = sov["public"]["nist_included"]
            .as_bool()
            .ok_or(LatticeBridgeError::MissingField("public.nist_included"))?;
        if pkg_nist != sov_nist {
            return Err(LatticeBridgeError::NistIncludedMismatch {
                pkg: pkg_nist,
                sov: sov_nist,
            });
        }
    }
    Ok(())
}

/// **`verify_limb_binding_json`** plus Engine A public-instance validation (**feature `lattice-bridge`**).
#[cfg(feature = "lattice-bridge")]
pub fn verify_handshake_with_le(package_dir: &Path) -> Result<(), LatticeBridgeError> {
    verify_limb_binding_json(package_dir)?;
    let pkg_path = package_dir.join("prover_package.json");
    let pkg: serde_json::Value = serde_json::from_str(&fs::read_to_string(&pkg_path)?)?;
    let coeffs = parse_digest_coeff_vector(
        &pkg["engine_a_public"]["digest_coeff_vector_u4"],
        "engine_a_public.digest_coeff_vector_u4",
    )?;
    debug_assert_eq!(BRIDGE_Q, qssm_le::Q, "BRIDGE_Q must track qssm_le::Q");
    qssm_le::PublicInstance::digest_coeffs(coeffs).validate()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_pkg_dir() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("qssm_gadget_bridge_test_{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn limb_to_q_coeff0_range() {
        assert!(limb_to_q_coeff0(1u64 << 30).is_err());
        assert!(limb_to_q_coeff0(u64::from(BRIDGE_Q)).is_err());
        let m = u64::from(BRIDGE_Q) - 1;
        assert_eq!(limb_to_q_coeff0(m).unwrap(), m as u32);
    }

    #[test]
    fn verify_limb_binding_json_happy_and_mismatch() {
        let d = temp_pkg_dir();
        std::fs::write(
            d.join("sovereign_witness.json"),
            serde_json::to_string_pretty(&json!({
                "kind": "SovereignWitnessV1",
                "public": {
                    "digest_coeff_vector_u4": vec![1u32; DIGEST_COEFF_VECTOR_SIZE],
                    "message_limb_u30": 42u64,
                    "root_hex": "",
                    "digest_hex": "",
                    "domain_tag": "QSSM-SOVEREIGN-LIMB-v2.0",
                    "nist_included": false,
                    "sovereign_entropy_hex": "",
                },
            }))
            .unwrap(),
        )
        .unwrap();
        let pkg = json!({
            "engine_a_public": {
                "message_limb_u30": 42u64,
                "digest_coeff_vector_u4": vec![1u32; DIGEST_COEFF_VECTOR_SIZE],
            },
            "nist_beacon_included": false,
            "artifacts": { "sovereign_witness_json": "sovereign_witness.json" },
        });
        std::fs::write(
            d.join("prover_package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
        verify_limb_binding_json(&d).unwrap();

        let pkg_bad = json!({
            "engine_a_public": {
                "message_limb_u30": 43u64,
                "digest_coeff_vector_u4": vec![1u32; DIGEST_COEFF_VECTOR_SIZE],
            },
            "nist_beacon_included": false,
            "artifacts": { "sovereign_witness_json": "sovereign_witness.json" },
        });
        std::fs::write(
            d.join("prover_package.json"),
            serde_json::to_string_pretty(&pkg_bad).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_limb_binding_json(&d),
            Err(LatticeBridgeError::LimbMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn verify_limb_binding_nist_mismatch() {
        let d = temp_pkg_dir();
        std::fs::write(
            d.join("sovereign_witness.json"),
            serde_json::to_string_pretty(&json!({
                "kind": "SovereignWitnessV1",
                "public": {
                    "digest_coeff_vector_u4": vec![2u32; DIGEST_COEFF_VECTOR_SIZE],
                    "message_limb_u30": 9u64,
                    "root_hex": "",
                    "digest_hex": "",
                    "domain_tag": "QSSM-SOVEREIGN-LIMB-v2.0",
                    "nist_included": false,
                    "sovereign_entropy_hex": "",
                },
            }))
            .unwrap(),
        )
        .unwrap();
        let pkg = json!({
            "engine_a_public": {
                "message_limb_u30": 9u64,
                "digest_coeff_vector_u4": vec![2u32; DIGEST_COEFF_VECTOR_SIZE],
            },
            "nist_beacon_included": true,
            "artifacts": { "sovereign_witness_json": "sovereign_witness.json" },
        });
        std::fs::write(
            d.join("prover_package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_limb_binding_json(&d),
            Err(LatticeBridgeError::NistIncludedMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(feature = "lattice-bridge")]
    #[test]
    fn verify_handshake_with_le_happy() {
        let d = temp_pkg_dir();
        let limb = 123_456u64;
        std::fs::write(
            d.join("sovereign_witness.json"),
            serde_json::to_string_pretty(&json!({
                "kind": "SovereignWitnessV1",
                "public": {
                    "digest_coeff_vector_u4": vec![3u32; DIGEST_COEFF_VECTOR_SIZE],
                    "message_limb_u30": limb,
                    "root_hex": "00",
                    "digest_hex": "00",
                    "domain_tag": "QSSM-SOVEREIGN-LIMB-v2.0",
                    "nist_included": false,
                    "sovereign_entropy_hex": "00",
                },
            }))
            .unwrap(),
        )
        .unwrap();
        let pkg = json!({
            "engine_a_public": {
                "message_limb_u30": limb,
                "digest_coeff_vector_u4": vec![3u32; DIGEST_COEFF_VECTOR_SIZE],
            },
            "nist_beacon_included": false,
            "artifacts": { "sovereign_witness_json": "sovereign_witness.json" },
        });
        std::fs::write(
            d.join("prover_package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
        verify_handshake_with_le(&d).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}
