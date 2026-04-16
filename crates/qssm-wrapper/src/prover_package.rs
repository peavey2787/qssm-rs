//! Strongly typed **`qssm-l2-handshake-v1`** `prover_package` mirror (ZK template surface).
//!
//! Field names and nesting match `ProverPackageBuilder` JSON so JCS step hashing stays stable.

use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

/// Package discriminator written by [`crate::StepEnvelope`] producers.
pub const L2_HANDSHAKE_PACKAGE_VERSION: &str = "qssm-l2-handshake-v1";

/// Must stay aligned with `qssm-gadget` / `qssm-utils` transcript map (`LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`).
pub const L2_TRANSCRIPT_MAP_LAYOUT_VERSION: u32 = 1;

/// Engine A digest coefficient count (4-bit nibbles; same as `qssm_le::PUBLIC_DIGEST_COEFFS`).
pub const DIGEST_COEFF_VECTOR_LEN: usize = 64;

/// Per-coefficient maximum for digest nibbles (sync with `qssm_le::PUBLIC_DIGEST_COEFF_MAX`).
pub const DIGEST_COEFF_MAX: u32 = 0x0f;

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
}

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

/// Typed `prover_package` for **`qssm-l2-handshake-v1`**.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct L2HandshakeProverPackageV1 {
    pub package_version: String,
    pub description: String,
    pub sim_kaspa_parent_block_id_hex: String,
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

impl L2HandshakeProverPackageV1 {
    /// Structural rules for the L2 handshake template (catch drift before hashing).
    pub fn validate(&self) -> Result<(), ProverPackageError> {
        if self.package_version != L2_HANDSHAKE_PACKAGE_VERSION {
            return Err(ProverPackageError::WrongPackageVersion {
                expected: L2_HANDSHAKE_PACKAGE_VERSION,
                got: self.package_version.clone(),
            });
        }
        if self.poly_ops.transcript_map_layout_version != L2_TRANSCRIPT_MAP_LAYOUT_VERSION {
            return Err(ProverPackageError::WrongTranscriptMapVersion {
                expected: L2_TRANSCRIPT_MAP_LAYOUT_VERSION,
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

impl TryFrom<serde_json::Value> for L2HandshakeProverPackageV1 {
    type Error = serde_json::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StepValidationError {
    #[error(transparent)]
    ProverPackage(#[from] ProverPackageError),
    #[error("wrapper engine_a_binding must match prover_package.engine_a_public")]
    EngineABindingMismatch,
}
