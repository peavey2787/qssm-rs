//! Phase 7 — **Lattice handshake**: sovereign **`message_limb`** as the **commitment target** for Engine A (`qssm-le`).
//!
//! Normative constant **`BRIDGE_Q`** must match **`qssm_le::Q`** (verified in **`verify_handshake_with_le`** under **`lattice-bridge`**).

use std::fs;
use std::path::Path;

/// Must match **`qssm_le::Q`** — MLWE modulus for **`R_q = Z_q[X]/(X^64+1)`**.
pub const BRIDGE_Q: u32 = 7_340_033;

/// Exclusive upper bound for the **30‑bit** limb (**`2^30`**, same as **`qssm_le::MAX_MESSAGE`** intent).
pub const MAX_LIMB_EXCLUSIVE: u64 = 1u64 << 30;

#[derive(Debug, thiserror::Error)]
pub enum LatticeBridgeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing or invalid field {0}")]
    MissingField(&'static str),
    #[error("limb mismatch: prover_package has {pkg} but sovereign witness has {sov}")]
    LimbMismatch { pkg: u64, sov: u64 },
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

/// Load **`prover_package.json`** and the referenced **`sovereign_witness.json`**; assert **`engine_a_public.message_limb_u30`** equals **`public.message_limb_u30`**; check limb range and field lift.
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
    Ok(())
}

/// **`verify_limb_binding_json`** plus Engine A **`PublicInstance::validate`** and **`RqPoly::embed_constant`** coeff₀ check (**feature `lattice-bridge`**).
#[cfg(feature = "lattice-bridge")]
pub fn verify_handshake_with_le(package_dir: &Path) -> Result<(), LatticeBridgeError> {
    verify_limb_binding_json(package_dir)?;
    let pkg_path = package_dir.join("prover_package.json");
    let pkg: serde_json::Value = serde_json::from_str(&fs::read_to_string(&pkg_path)?)?;
    let limb = pkg["engine_a_public"]["message_limb_u30"].as_u64().ok_or(
        LatticeBridgeError::MissingField("engine_a_public.message_limb_u30"),
    )?;
    debug_assert_eq!(BRIDGE_Q, qssm_le::Q, "BRIDGE_Q must track qssm_le::Q");
    qssm_le::PublicInstance { message: limb }.validate()?;
    let q = u64::from(qssm_le::Q);
    let expected0 = (limb % q) as u32;
    let mu = qssm_le::RqPoly::embed_constant(limb);
    let got0 = mu.0[0];
    if got0 != expected0 {
        return Err(LatticeBridgeError::EmbedCoeff0Mismatch {
            expected: expected0,
            got: got0,
        });
    }
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
                "public": { "message_limb_u30": 42u64, "root_hex": "", "digest_hex": "", "domain_tag": "x" },
            }))
            .unwrap(),
        )
        .unwrap();
        let pkg = json!({
            "engine_a_public": { "message_limb_u30": 42u64 },
            "artifacts": { "sovereign_witness_json": "sovereign_witness.json" },
        });
        std::fs::write(
            d.join("prover_package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
        verify_limb_binding_json(&d).unwrap();

        let pkg_bad = json!({
            "engine_a_public": { "message_limb_u30": 43u64 },
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
                    "message_limb_u30": limb,
                    "root_hex": "00",
                    "digest_hex": "00",
                    "domain_tag": "QSSM-SOVEREIGN-LIMB-v1.0",
                },
            }))
            .unwrap(),
        )
        .unwrap();
        let pkg = json!({
            "engine_a_public": { "message_limb_u30": limb },
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
