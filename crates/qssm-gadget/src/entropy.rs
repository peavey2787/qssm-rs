//! Phase 8 — **Opportunistic entropy**: **anchor leg** + local **floor**, optional NIST Randomness Beacon **booster** (strict timeout).
//!
//! The first **32** bytes of the floor preimage are an **entropy anchor** (Kaspa parent id, a static root, or a hashed timestamp). Kaspa is one [`EntropyAnchor`] variant, not a hard‑coded primitive.

use std::time::Duration;

use qssm_utils::hashing::blake3_hash;

/// **32‑byte leg** mixed with local entropy for [`entropy_floor`]. Kaspa finalized parent hash is [`Self::KaspaParentBlockHash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyAnchor {
    /// Kaspa (or other L1) **32‑byte** parent / finalized block id used as today’s floor limb.
    KaspaParentBlockHash([u8; 32]),
    /// Fixed **32‑byte** root (no blockchain): e.g. org‑published commitment or app session root.
    StaticRoot([u8; 32]),
    /// Wall‑clock (or agreed) **Unix seconds**; canonicalized to **32** bytes via domain‑separated BLAKE3.
    TimestampUnixSecs { unix_secs: u64 },
}

impl EntropyAnchor {
    /// **32** bytes fed into **`BLAKE3(leg ‖ local)`** (the entropy floor preimage’s first half).
    #[must_use]
    pub fn entropy_leg(&self) -> [u8; 32] {
        match self {
            Self::KaspaParentBlockHash(h) | Self::StaticRoot(h) => *h,
            Self::TimestampUnixSecs { unix_secs } => {
                let mut buf = [0u8; 8 + 32];
                buf[..32].copy_from_slice(b"QSSM-ENTROPY-ANCHOR-TIMESTAMP-v1");
                buf[32..].copy_from_slice(&unix_secs.to_le_bytes());
                blake3_hash(&buf)
            }
        }
    }
}

/// NIST Beacon **2.0** “last pulse” endpoint (JSON with **`pulse.outputValue`** hex, **64** bytes).
pub const NIST_BEACON_LAST_PULSE_URL: &str = "https://beacon.nist.gov/beacon/2.0/pulse/last";

/// Default ceiling for beacon fetch so high‑BPS Kaspa nodes never stall on a remote server.
pub const DEFAULT_NIST_TIMEOUT: Duration = Duration::from_millis(500);

/// Configurable opportunistic QRNG / resilience policy.
#[derive(Debug, Clone)]
pub struct EntropyProvider {
    /// Max time for the entire NIST HTTP round‑trip (connect + headers + body).
    pub nist_timeout: Duration,
    /// Skip HTTP entirely (offline / deterministic demo / simulated timeout).
    pub nist_disabled: bool,
    /// If set, use this **32‑byte** pulse instead of HTTP (simulated **200 OK** path).
    pub nist_pulse_override: Option<[u8; 32]>,
}

impl Default for EntropyProvider {
    fn default() -> Self {
        Self {
            nist_timeout: DEFAULT_NIST_TIMEOUT,
            nist_disabled: false,
            nist_pulse_override: None,
        }
    }
}

impl EntropyProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulated **NIST down** (network timeout / offline): floor only, second return **`false`**.
    #[must_use]
    pub fn simulate_nist_down() -> Self {
        Self {
            nist_disabled: true,
            ..Self::default()
        }
    }

    /// Simulated **NIST up**: **`pulse`** XORed into the floor as if a **200 OK** body was received.
    #[must_use]
    pub fn simulate_nist_up(pulse: [u8; 32]) -> Self {
        Self {
            nist_pulse_override: Some(pulse),
            nist_disabled: false,
            ..Self::default()
        }
    }

    /// **Floor** = **`BLAKE3(anchor_leg ‖ Local_Bytes)`**; if NIST succeeds, **Final** = **Floor ⊕ Pulse** (first **32** bytes of decoded **`outputValue`**).
    #[must_use]
    pub fn generate_sovereign_entropy_from_anchor(
        &self,
        anchor: &EntropyAnchor,
        local_bytes: [u8; 32],
    ) -> ([u8; 32], bool) {
        let floor = entropy_floor(anchor.entropy_leg(), local_bytes);
        let pulse = if self.nist_disabled {
            None
        } else if let Some(p) = self.nist_pulse_override {
            Some(p)
        } else {
            fetch_nist_pulse(self.nist_timeout)
        };
        match pulse {
            Some(p) => (xor32(floor, p), true),
            None => (floor, false),
        }
    }

    /// Same as [`Self::generate_sovereign_entropy_from_anchor`] with a Kaspa **32‑byte** parent id (backward compatible).
    #[must_use]
    pub fn generate_sovereign_entropy(
        &self,
        kaspa_hash: [u8; 32],
        local_bytes: [u8; 32],
    ) -> ([u8; 32], bool) {
        self.generate_sovereign_entropy_from_anchor(
            &EntropyAnchor::KaspaParentBlockHash(kaspa_hash),
            local_bytes,
        )
    }
}

/// **`BLAKE3(anchor_leg ‖ Local_Bytes)`** — entropy **floor** (no NIST). **`anchor_leg`** is [`EntropyAnchor::entropy_leg`].
#[must_use]
pub fn entropy_floor(anchor_leg: [u8; 32], local_bytes: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(&anchor_leg);
    preimage[32..].copy_from_slice(&local_bytes);
    blake3_hash(&preimage)
}

#[must_use]
fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// Fetch NIST pulse (**200 OK** only). **Strict timeout** via ureq; any failure → **`None`** (caller uses floor only).
#[must_use]
pub fn fetch_nist_pulse(timeout: Duration) -> Option<[u8; 32]> {
    let resp = ureq::get(NIST_BEACON_LAST_PULSE_URL)
        .timeout(timeout)
        .call()
        .ok()?;
    if resp.status() != 200 {
        return None;
    }
    let v: serde_json::Value = resp.into_json().ok()?;
    let hex_str = v["pulse"]["outputValue"].as_str()?;
    pulse_output_value_first_32(hex_str)
}

fn pulse_output_value_first_32(hex_str: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(hex_str.trim()).ok()?;
    if raw.len() < 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw[..32]);
    Some(out)
}

/// Same as [`EntropyProvider::default().generate_sovereign_entropy`](EntropyProvider::generate_sovereign_entropy).
#[must_use]
pub fn generate_sovereign_entropy(kaspa_hash: [u8; 32], local_bytes: [u8; 32]) -> ([u8; 32], bool) {
    EntropyProvider::default().generate_sovereign_entropy(kaspa_hash, local_bytes)
}

/// Floor + optional NIST with an arbitrary [`EntropyAnchor`].
#[must_use]
pub fn generate_sovereign_entropy_from_anchor(
    anchor: &EntropyAnchor,
    local_bytes: [u8; 32],
) -> ([u8; 32], bool) {
    EntropyProvider::default().generate_sovereign_entropy_from_anchor(anchor, local_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(entropy_floor(a, b), entropy_floor(a, b));
        assert_ne!(entropy_floor(a, b), entropy_floor(b, a));
    }

    #[test]
    fn timestamp_anchor_leg_deterministic() {
        let a = EntropyAnchor::TimestampUnixSecs { unix_secs: 1_700_000_000 };
        assert_eq!(a.entropy_leg(), a.entropy_leg());
        let b = EntropyAnchor::TimestampUnixSecs { unix_secs: 1_700_000_001 };
        assert_ne!(a.entropy_leg(), b.entropy_leg());
    }

    #[test]
    fn static_root_matches_raw_leg() {
        let h = [9u8; 32];
        assert_eq!(
            EntropyAnchor::StaticRoot(h).entropy_leg(),
            EntropyAnchor::KaspaParentBlockHash(h).entropy_leg()
        );
    }

    #[test]
    fn xor_booster_changes_output() {
        let k = [5u8; 32];
        let l = [6u8; 32];
        let floor = entropy_floor(k, l);
        let pulse = [0xFFu8; 32];
        let (out, nist) = EntropyProvider::simulate_nist_up(pulse).generate_sovereign_entropy(k, l);
        assert!(nist);
        let mut expect = floor;
        for i in 0..32 {
            expect[i] ^= pulse[i];
        }
        assert_eq!(out, expect);
    }

    #[test]
    fn nist_down_is_floor_only() {
        let k = [3u8; 32];
        let l = [4u8; 32];
        let (out, nist) = EntropyProvider::simulate_nist_down().generate_sovereign_entropy(k, l);
        assert!(!nist);
        assert_eq!(out, entropy_floor(k, l));
    }

    #[test]
    fn parse_sample_output_value() {
        let hex = "AE7932592BFF9D8CB67F901C7C2A4814B5E0069A4AA78E24CE8EE329BB18CBF1C9EDD6DF1E0AC8B402761EC8601D24FD8A28524499098BDFA3C3D672DCB18DEE";
        assert_eq!(hex.len(), 128, "sample is 64-byte NIST outputValue");
        let p = pulse_output_value_first_32(hex).expect("parse");
        assert_eq!(p[0], 0xAE);
        assert_eq!(p[1], 0x79);
    }
}
