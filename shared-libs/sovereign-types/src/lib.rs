//! Canonical versioned wire types for the QSSM sovereign handshake protocol.
//!
//! This crate is the **Single Source of Truth** for every schema type that crosses
//! crate boundaries between `qssm-gadget` (producer) and `qssm-wrapper` (consumer).
//! Both must depend on `sovereign-types` rather than duplicating struct definitions.
//!
//! # Protocol versioning
//!
//! [`PROTOCOL_VERSION`] is embedded in every [`SovereignProofBundle`] and
//! [`SovereignHandshakeProverPackageV1`]. When the lattice math, entropy harvesting,
//! or wire-format semantics change, bump this constant. Stream managers must
//! **fail-fast** when a proof with a mismatched version enters a stream—preventing
//! silent corruption of append-only logs.

#![forbid(unsafe_code)]

use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

// ── Protocol version ─────────────────────────────────────────────────
//
// Bump this when:
//   - lattice parameters (q, N, BETA) change,
//   - sovereign digest derivation changes,
//   - entropy harvesting semantics change,
//   - wire-format field names/nesting change.
//
// Consumers MUST reject payloads where `protocol_version != PROTOCOL_VERSION`.

/// Global QSSM sovereign protocol version.
///
/// Every [`SovereignProofBundle`] and [`SovereignHandshakeProverPackageV1`]
/// carries this version. Verification and stream-append code **must** reject
/// payloads whose version differs from the running binary's value.
pub const PROTOCOL_VERSION: u32 = 1;

// ── Prover package constants ─────────────────────────────────────────

/// Package discriminator written by `StepEnvelope` producers.
pub const SOVEREIGN_HANDSHAKE_PACKAGE_VERSION: &str = "qssm-sovereign-handshake-v1";

/// Must stay aligned with `qssm-gadget` / `qssm-utils` transcript map
/// (`LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`).
pub const SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION: u32 = 1;

/// Engine A digest coefficient count (4-bit nibbles; same as `qssm_le::PUBLIC_DIGEST_COEFFS`).
pub const DIGEST_COEFF_VECTOR_LEN: usize = 64;

/// Per-coefficient maximum for digest nibbles (sync with `qssm_le::PUBLIC_DIGEST_COEFF_MAX`).
pub const DIGEST_COEFF_MAX: u32 = 0x0f;

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ProverPackageError {
    #[error("package_version must be {expected:?}, got {got:?}")]
    WrongPackageVersion { expected: &'static str, got: String },
    #[error("engine_a_public.digest_coeff_vector_u4 must have length {expected}, got {got}")]
    WrongDigestCoeffLen { expected: usize, got: usize },
    #[error("digest coefficient {index} = {value} exceeds max {max}")]
    DigestCoeffOutOfRange {
        index: usize,
        value: u32,
        max: u32,
    },
    #[error("message_limb_u30 {0} must be < 2^30")]
    MessageLimbOutOfRange(u64),
    #[error("poly_ops.transcript_map_layout_version must be {expected}, got {got}")]
    WrongTranscriptMapVersion { expected: u32, got: u32 },
    #[error("protocol_version must be {expected}, got {got}")]
    WrongProtocolVersion { expected: u32, got: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum StepValidationError {
    #[error(transparent)]
    ProverPackage(#[from] ProverPackageError),
    #[error("wrapper engine_a_binding must match prover_package.engine_a_public")]
    EngineABindingMismatch,
}

// ── Prover package schema types ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProverEngineAPublicV1 {
    pub message_limb_u30: u64,
    pub digest_coeff_vector_u4: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProverArtifactsV1 {
    pub sovereign_witness_json: String,
    pub merkle_parent_witness_json: String,
    pub r1cs_merkle_manifest_txt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessWireCountsV1 {
    pub sovereign_private_bit_wires: u32,
    pub merkle_parent_private_bit_wires: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct R1csManifestSummaryV1 {
    pub constraint_line_count: u64,
    pub line_format: String,
    pub manifest_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolyOpsSummaryV1 {
    pub transcript_map_layout_version: u32,
    pub merkle_depth: u32,
    pub refresh_copy_count: u32,
    pub auto_refresh_merkle_xor: bool,
}

/// One R1CS copy-refresh record (matches gadget `CopyRefreshMeta` on the wire).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProverRefreshMetadataEntryV1 {
    pub new_idx: u32,
    pub old_idx: u32,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment: Option<String>,
    pub kind: String,
}

/// Typed `prover_package` for **`qssm-sovereign-handshake-v1`**.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SovereignHandshakeProverPackageV1 {
    pub package_version: String,
    pub protocol_version: u32,
    pub description: String,
    pub sim_anchor_hash_hex: String,
    pub merkle_leaf_left_hex: String,
    pub merkle_leaf_right_hex: String,
    pub rollup_state_root_hex: String,
    pub nist_beacon_included: bool,
    pub engine_a_public: ProverEngineAPublicV1,
    pub artifacts: ProverArtifactsV1,
    pub witness_wire_counts: WitnessWireCountsV1,
    pub r1cs: R1csManifestSummaryV1,
    pub poly_ops: PolyOpsSummaryV1,
    pub refresh_metadata: Vec<ProverRefreshMetadataEntryV1>,
    pub warnings: Vec<String>,
}

impl SovereignHandshakeProverPackageV1 {
    /// Structural rules for the sovereign handshake template (catch drift before hashing).
    pub fn validate(&self) -> Result<(), ProverPackageError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProverPackageError::WrongProtocolVersion {
                expected: PROTOCOL_VERSION,
                got: self.protocol_version,
            });
        }
        if self.package_version != SOVEREIGN_HANDSHAKE_PACKAGE_VERSION {
            return Err(ProverPackageError::WrongPackageVersion {
                expected: SOVEREIGN_HANDSHAKE_PACKAGE_VERSION,
                got: self.package_version.clone(),
            });
        }
        if self.poly_ops.transcript_map_layout_version != SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION {
            return Err(ProverPackageError::WrongTranscriptMapVersion {
                expected: SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION,
                got: self.poly_ops.transcript_map_layout_version,
            });
        }
        let n = self.engine_a_public.digest_coeff_vector_u4.len();
        if n != DIGEST_COEFF_VECTOR_LEN {
            return Err(ProverPackageError::WrongDigestCoeffLen {
                expected: DIGEST_COEFF_VECTOR_LEN,
                got: n,
            });
        }
        for (i, &c) in self.engine_a_public.digest_coeff_vector_u4.iter().enumerate() {
            if c > DIGEST_COEFF_MAX {
                return Err(ProverPackageError::DigestCoeffOutOfRange {
                    index: i,
                    value: c,
                    max: DIGEST_COEFF_MAX,
                });
            }
        }
        let limb = self.engine_a_public.message_limb_u30;
        if limb >= (1u64 << 30) {
            return Err(ProverPackageError::MessageLimbOutOfRange(limb));
        }
        Ok(())
    }
}

impl TryFrom<serde_json::Value> for SovereignHandshakeProverPackageV1 {
    type Error = serde_json::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_package() -> SovereignHandshakeProverPackageV1 {
        let mut coeffs = vec![0u32; 64];
        coeffs[0] = 1;
        coeffs[1] = 2;
        SovereignHandshakeProverPackageV1 {
            package_version: SOVEREIGN_HANDSHAKE_PACKAGE_VERSION.into(),
            protocol_version: PROTOCOL_VERSION,
            description: "test".into(),
            sim_anchor_hash_hex: "aa".into(),
            merkle_leaf_left_hex: "bb".into(),
            merkle_leaf_right_hex: "cc".into(),
            rollup_state_root_hex: "dd".into(),
            nist_beacon_included: false,
            engine_a_public: ProverEngineAPublicV1 {
                message_limb_u30: 42,
                digest_coeff_vector_u4: coeffs,
            },
            artifacts: ProverArtifactsV1 {
                sovereign_witness_json: "s.json".into(),
                merkle_parent_witness_json: "m.json".into(),
                r1cs_merkle_manifest_txt: "r.txt".into(),
            },
            witness_wire_counts: WitnessWireCountsV1 {
                sovereign_private_bit_wires: 32,
                merkle_parent_private_bit_wires: 259840,
            },
            r1cs: R1csManifestSummaryV1 {
                constraint_line_count: 65184,
                line_format: "xor|full_adder|equal with tab-separated var indices".into(),
                manifest_file: "r.txt".into(),
            },
            poly_ops: PolyOpsSummaryV1 {
                transcript_map_layout_version: SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION,
                merkle_depth: 7,
                refresh_copy_count: 0,
                auto_refresh_merkle_xor: false,
            },
            refresh_metadata: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn valid_package_passes_validation() {
        valid_package().validate().unwrap();
    }

    #[test]
    fn wrong_protocol_version_rejected() {
        let mut pkg = valid_package();
        pkg.protocol_version = 999;
        let err = pkg.validate().unwrap_err();
        assert!(err.to_string().contains("protocol_version"));
    }

    #[test]
    fn wrong_package_version_rejected() {
        let mut pkg = valid_package();
        pkg.package_version = "wrong".into();
        let err = pkg.validate().unwrap_err();
        assert!(err.to_string().contains("package_version"));
    }

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn round_trip_serde() {
        let pkg = valid_package();
        let json = serde_json::to_string(&pkg).unwrap();
        let pkg2: SovereignHandshakeProverPackageV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(pkg, pkg2);
    }
}
