//! Phase 7 — **Lattice handshake**: truth digest coefficient-vector as the commitment target for Engine A (`qssm-le`).

/// Must match **`qssm_le::Q`** — MLWE modulus for **`R_q = Z_q[X]/(X^256+1)`**.
pub const BRIDGE_Q: u32 = 8_380_417;

/// Exclusive upper bound for the legacy **30‑bit** limb (`2^30`, compatibility-only path).
pub const MAX_LIMB_EXCLUSIVE: u64 = 1u64 << 30;

#[derive(Debug, thiserror::Error)]
pub enum LatticeBridgeError {
    #[error("message limb {0} out of 30-bit range (must be < 2^30)")]
    LimbOutOfRange30(u64),
    #[error("message limb {0} is not canonically liftable below BRIDGE_Q (must be < {BRIDGE_Q})")]
    LimbNotInField(u64),
    #[error("RqPoly::embed_constant coeff0 mismatch: expected {expected}, got {got}")]
    EmbedCoeff0Mismatch { expected: u32, got: u32 },
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

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_le::Q as LE_Q;

    #[test]
    fn limb_to_q_coeff0_range() {
        assert!(limb_to_q_coeff0(1u64 << 30).is_err());
        assert!(limb_to_q_coeff0(u64::from(BRIDGE_Q)).is_err());
        let m = u64::from(BRIDGE_Q) - 1;
        assert_eq!(limb_to_q_coeff0(m).unwrap(), m as u32);
    }

    #[test]
    fn bridge_q_matches_qssm_le_q() {
        assert_eq!(BRIDGE_Q, LE_Q);
    }
}
