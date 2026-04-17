#![forbid(unsafe_code)]

mod prover_package;
mod stream;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

pub use prover_package::{
    SovereignHandshakeProverPackageV1, SOVEREIGN_HANDSHAKE_PACKAGE_VERSION, SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION,
    PolyOpsSummaryV1, ProverArtifactsV1, ProverEngineAPublicV1, ProverPackageError,
    ProverRefreshMetadataEntryV1, R1csManifestSummaryV1, StepValidationError,
    WitnessWireCountsV1, DIGEST_COEFF_MAX, DIGEST_COEFF_VECTOR_LEN,
};
pub use stream::{
    window_step_hashes_digest, AccumulatorCheckpoint, SovereignStreamManager, StreamError,
    DOMAIN_WINDOW_V1, WRAP_CONTEXT_DOMAIN, WRAP_SCHEMA_VERSION,
};

pub const DOMAIN_STEP_V1: &[u8] = b"QSSM-WRAP-STEP-v1";
pub const DOMAIN_ACC_V1: &[u8] = b"QSSM-WRAP-ACC-v1";
pub const DOMAIN_ACC_GENESIS_V1: &[u8] = b"QSSM-WRAP-ACC-GENESIS-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StepEnvelope {
    pub prover_package: SovereignHandshakeProverPackageV1,
    pub wrapper_v1: WrapperV1,
}

impl StepEnvelope {
    /// Enforce sovereign handshake template rules plus Engine A cross-layer consistency.
    pub fn validate_template_rules(&self) -> Result<(), StepValidationError> {
        self.prover_package.validate()?;
        let ep = &self.prover_package.engine_a_public;
        let wb = &self.wrapper_v1.engine_a_binding;
        if wb.engine_a_public_message_limb_u30 != ep.message_limb_u30
            || wb.engine_a_public_digest_coeff_vector_u4 != ep.digest_coeff_vector_u4
        {
            return Err(StepValidationError::EngineABindingMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WrapperV1 {
    pub binding_context_hex: String,
    pub context_domain: String,
    pub step_index: u64,
    pub ms_binding: MsBinding,
    pub seam_binding: SeamBinding,
    pub engine_a_binding: EngineABinding,
    pub artifact_hashes: ArtifactHashes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sovereign_law: Option<SovereignLawV1>,
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SovereignLawV1 {
    /// Lab-local law id (supports `id:param` pre-persistence; persisted as base id).
    pub template_id: String,
    /// Optional law document (VK/constraints descriptor).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_script: Option<serde_json::Value>,
    /// Blinded parameter commitment persisted in-step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blinded_parameter_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MsBinding {
    pub ms_root_hex: String,
    pub ms_fs_v2_challenge_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeamBinding {
    pub seam_commitment_digest_hex: String,
    pub seam_open_digest_hex: String,
    pub seam_binding_digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineABinding {
    pub engine_a_public_message_limb_u30: u64,
    pub engine_a_public_digest_coeff_vector_u4: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactHashes {
    pub sovereign_witness_json_blake3_hex: String,
    pub merkle_parent_witness_json_blake3_hex: String,
    pub r1cs_manifest_blake3_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum WrapperError {
    #[error("hex must start with 0x: {0}")]
    InvalidHexPrefix(String),
    #[error("hex length mismatch: expected {expected} bytes got {got}")]
    InvalidHexLength { expected: usize, got: usize },
    #[error("hex decode failed: {0}")]
    HexDecode(String),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

pub fn canonical_step_bytes(step: &StepEnvelope) -> Result<Vec<u8>, WrapperError> {
    serde_jcs::to_vec(step).map_err(|e| WrapperError::Canonicalization(e.to_string()))
}

pub fn step_hash(step: &StepEnvelope) -> Result<[u8; 32], WrapperError> {
    let canonical = canonical_step_bytes(step)?;
    let mut h = Hasher::new();
    h.update(DOMAIN_STEP_V1);
    h.update(&canonical);
    Ok(*h.finalize().as_bytes())
}

pub fn accumulator_genesis(binding_context: [u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_ACC_GENESIS_V1);
    h.update(&binding_context);
    *h.finalize().as_bytes()
}

pub fn accumulator_next(
    binding_context: [u8; 32],
    step_index: u64,
    prev_acc: [u8; 32],
    step_hash_bytes: [u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_ACC_V1);
    h.update(&binding_context);
    h.update(&step_index.to_le_bytes());
    h.update(&prev_acc);
    h.update(&step_hash_bytes);
    *h.finalize().as_bytes()
}

pub fn decode_hex32(hex_value: &str) -> Result<[u8; 32], WrapperError> {
    let raw = hex_value
        .strip_prefix("0x")
        .ok_or_else(|| WrapperError::InvalidHexPrefix(hex_value.into()))?;
    let bytes = hex::decode(raw).map_err(|e| WrapperError::HexDecode(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(WrapperError::InvalidHexLength {
            expected: 32,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn hex_lower_prefixed(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_digest_coeffs() -> Vec<u32> {
        let mut v = vec![0u32; 64];
        v[0] = 1;
        v[1] = 2;
        v[2] = 3;
        v[3] = 4;
        v
    }

    fn fixture_step(step_index: u64) -> StepEnvelope {
        let digest_coeff = fixture_digest_coeffs();
        StepEnvelope {
            prover_package: SovereignHandshakeProverPackageV1 {
                package_version: SOVEREIGN_HANDSHAKE_PACKAGE_VERSION.into(),
                description: "fixture".into(),
                sim_anchor_hash_hex: "0x01020304".into(),
                merkle_leaf_left_hex: "0x11".into(),
                merkle_leaf_right_hex: "0x22".into(),
                rollup_state_root_hex: "0x33".into(),
                nist_beacon_included: false,
                engine_a_public: ProverEngineAPublicV1 {
                    message_limb_u30: 74592577,
                    digest_coeff_vector_u4: digest_coeff.clone(),
                },
                artifacts: ProverArtifactsV1 {
                    sovereign_witness_json: "sovereign_witness.json".into(),
                    merkle_parent_witness_json: "merkle_parent_witness.json".into(),
                    r1cs_merkle_manifest_txt: "r1cs_merkle_parent.manifest.txt".into(),
                },
                witness_wire_counts: WitnessWireCountsV1 {
                    sovereign_private_bit_wires: 32,
                    merkle_parent_private_bit_wires: 259840,
                },
                r1cs: R1csManifestSummaryV1 {
                    constraint_line_count: 65184,
                    line_format: "xor|full_adder|equal with tab-separated var indices".into(),
                    manifest_file: "r1cs_merkle_parent.manifest.txt".into(),
                },
                poly_ops: PolyOpsSummaryV1 {
                    transcript_map_layout_version: SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION,
                    merkle_depth: 7,
                    refresh_copy_count: 0,
                    auto_refresh_merkle_xor: false,
                },
                refresh_metadata: vec![],
                warnings: vec![],
            },
            wrapper_v1: WrapperV1 {
                binding_context_hex:
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .into(),
                context_domain: "QSSM-WRAP-CONTEXT-v1".into(),
                step_index,
                ms_binding: MsBinding {
                    ms_root_hex:
                        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .into(),
                    ms_fs_v2_challenge_hex:
                        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                            .into(),
                },
                seam_binding: SeamBinding {
                    seam_commitment_digest_hex:
                        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                            .into(),
                    seam_open_digest_hex:
                        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                            .into(),
                    seam_binding_digest_hex:
                        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                            .into(),
                },
                engine_a_binding: EngineABinding {
                    engine_a_public_message_limb_u30: 74592577,
                    engine_a_public_digest_coeff_vector_u4: digest_coeff,
                },
                artifact_hashes: ArtifactHashes {
                    sovereign_witness_json_blake3_hex:
                        "0x1111111111111111111111111111111111111111111111111111111111111111"
                            .into(),
                    merkle_parent_witness_json_blake3_hex:
                        "0x2222222222222222222222222222222222222222222222222222222222222222"
                            .into(),
                    r1cs_manifest_blake3_hex:
                        "0x3333333333333333333333333333333333333333333333333333333333333333"
                            .into(),
                },
                sovereign_law: None,
                schema_version: "qssm-hybrid-wrapper-v1".into(),
            },
        }
    }

    #[test]
    fn golden_acc_99_matches_spec() {
        let ctx = decode_hex32(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("ctx hex");
        let mut acc = accumulator_genesis(ctx);
        for i in 0u64..100 {
            let step = fixture_step(i);
            let s = step_hash(&step).expect("step hash");
            acc = accumulator_next(ctx, i, acc, s);
        }
        let acc_99 = hex_lower_prefixed(&acc);
        // Keep this value synchronized with docs/02-protocol-specs/hybrid-wrapper-schema-v1.md.
        let expected = "0xc7fb700b81891b4d7249ca2c0f2dd7cd2ebc76390fb4feed1576289d95e4f5c0";
        assert_eq!(acc_99, expected);
    }
}
