#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use qssm_gadget::{
    CopyRefreshMeta, PolyOpContext, PolyOpError, DEFAULT_REFRESH_PRESSURE_WARN_RATIO,
    EngineAPublicJson, TruthPipeOutput, TRANSCRIPT_MAP_LAYOUT_VERSION,
    MerkleTruthPipe, MERKLE_DEPTH_MS,
};
use qssm_utils::hashing::blake3_hash as utils_blake3_hash;
use qssm_utils::validate_entropy_full;
use serde_json::json;

const TRUTH_PRIVATE_BIT_WIRES: usize = 32;
const MERKLE_PARENT_PRIVATE_BIT_WIRES: usize = 259_840;
const MERKLE_PARENT_CONSTRAINT_COUNT: usize = 65_184;

#[derive(Debug, Clone)]
pub struct TruthHandshakeArtifacts {
    pub anchor_hash: [u8; 32],
    pub leaf_left: [u8; 32],
    pub leaf_right: [u8; 32],
    pub external_entropy_included: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TruthBuildOptions {
    pub entropy_sample_for_audit: Option<Vec<u8>>,
    pub reject_weak_entropy_sample: bool,
    pub auto_refresh_merkle_xor: bool,
    pub refresh_pressure_warn_ratio: Option<f64>,
}

pub struct TruthHandshakePackageBuilder;

impl TruthHandshakePackageBuilder {
    pub fn build_truth_handshake_v1(
        assets_dir: &Path,
        pipe: &MerkleTruthPipe,
        meta: &TruthHandshakeArtifacts,
    ) -> Result<TruthPipeOutput, PolyOpError> {
        Self::build_truth_handshake_v1_with_options(
            assets_dir,
            pipe,
            meta,
            &TruthBuildOptions::default(),
        )
    }

    pub fn build_truth_handshake_v1_with_options(
        assets_dir: &Path,
        pipe: &MerkleTruthPipe,
        meta: &TruthHandshakeArtifacts,
        opts: &TruthBuildOptions,
    ) -> Result<TruthPipeOutput, PolyOpError> {
        if let Some(expected) = pipe.second.params.device_entropy_link {
            let raw = opts.entropy_sample_for_audit.as_deref().ok_or_else(|| {
                PolyOpError::Binding(
                    "entropy_sample_for_audit is required when device_entropy_link is set (prover entropy audit)"
                        .into(),
                )
            })?;
            if utils_blake3_hash(raw) != expected {
                return Err(PolyOpError::Binding(
                    "entropy_sample_for_audit must BLAKE3-hash to device_entropy_link".into(),
                ));
            }
            validate_entropy_full(raw)?;
        } else if opts.reject_weak_entropy_sample {
            if let Some(sample) = &opts.entropy_sample_for_audit {
                validate_entropy_full(sample)?;
            }
        }

        fs::create_dir_all(assets_dir)?;
        let mut ctx = PolyOpContext::new("truth_handshake_v1");
        ctx.set_auto_refresh_enabled(opts.auto_refresh_merkle_xor);
        let out = pipe.run_diagnostic(&mut ctx)?;
        let engine_public = EngineAPublicJson::from_witness(&out.truth_witness);
        engine_public.validate_transcript_map()?;

        fs::write(assets_dir.join("truth_witness.json"), out.truth_witness.to_prover_json()?)?;
        fs::write(
            assets_dir.join("merkle_parent_witness.json"),
            merkle_parent_hash_witness_to_prover_json_with_refresh(out.merkle.state_root.0, &out.refresh_metadata),
        )?;
        let refresh_ratio = (out.refresh_metadata.len() as f64)
            / (MERKLE_PARENT_CONSTRAINT_COUNT.max(1) as f64);
        let threshold = opts
            .refresh_pressure_warn_ratio
            .unwrap_or(DEFAULT_REFRESH_PRESSURE_WARN_RATIO);
        let warnings = if out.refresh_metadata.is_empty() || refresh_ratio < threshold {
            Vec::<String>::new()
        } else {
            vec![format!(
                "High degree pressure: copy-refresh count ({}) / R1CS constraint lines ({}) = {:.2}%",
                out.refresh_metadata.len(),
                MERKLE_PARENT_CONSTRAINT_COUNT,
                refresh_ratio * 100.0,
            )]
        };

        let package = json!({
            "package_version": "qssm-sovereign-handshake-v1",
            "protocol_version": 1,
            "description": "Truth handshake: Merkle parent (BLAKE3 compress witness) + truth limb for Engine A",
            "sim_anchor_hash_hex": hex::encode(meta.anchor_hash),
            "merkle_leaf_left_hex": hex::encode(meta.leaf_left),
            "merkle_leaf_right_hex": hex::encode(meta.leaf_right),
            "rollup_state_root_hex": hex::encode(out.merkle.state_root.0),
            "nist_beacon_included": meta.external_entropy_included,
            "engine_a_public": engine_public.to_ordered_json_value()?,
            "artifacts": {
                "truth_witness_json": "truth_witness.json",
                "merkle_parent_witness_json": "merkle_parent_witness.json"
            },
            "witness_wire_counts": {
                "truth_private_bit_wires": TRUTH_PRIVATE_BIT_WIRES,
                "merkle_parent_private_bit_wires": MERKLE_PARENT_PRIVATE_BIT_WIRES + out.refresh_metadata.len()
            },
            "constraint_counts": {
                "merkle_parent": MERKLE_PARENT_CONSTRAINT_COUNT
            },
            "poly_ops": {
                "transcript_map_layout_version": TRANSCRIPT_MAP_LAYOUT_VERSION,
                "merkle_depth": MERKLE_DEPTH_MS,
                "refresh_copy_count": out.refresh_metadata.len(),
                "auto_refresh_merkle_xor": opts.auto_refresh_merkle_xor
            },
            "refresh_metadata": serde_json::to_value(&out.refresh_metadata)?,
            "warnings": serde_json::to_value(&warnings)?
        });

        fs::write(
            assets_dir.join("prover_package.json"),
            serde_json::to_string_pretty(&package)?,
        )?;

        Ok(out)
    }
}

fn merkle_parent_hash_witness_to_prover_json_with_refresh(
    state_root: [u8; 32],
    refresh: &[CopyRefreshMeta],
) -> String {
    serde_json::to_string_pretty(&json!({
        "kind": "MerkleParentHashWitnessV1",
        "public": {
            "parent_digest_hex": hex::encode(state_root)
        },
        "r1cs_refresh_private_wires": refresh
    }))
    .expect("merkle parent witness json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_gadget::TruthWitness;
    use qssm_gadget::LatticePolyOp;
    use qssm_gadget::{MerkleParentBlake3Op, TruthLimbV2Params};
    use qssm_gadget::{ConstraintSystem, VarId, VarKind};
    use qssm_utils::hashing::{hash_domain, DOMAIN_MSSQ_ROLLUP_CONTEXT};

    #[derive(Debug, Default)]
    struct NoopConstraintSystem {
        next_var: u32,
    }

    impl ConstraintSystem for NoopConstraintSystem {
        fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
            let id = VarId(self.next_var);
            self.next_var = self.next_var.saturating_add(1);
            id
        }

        fn enforce_xor(&mut self, _x: VarId, _y: VarId, _and_xy: VarId, _z: VarId) {}

        fn enforce_full_adder(
            &mut self,
            _a: VarId,
            _b: VarId,
            _cin: VarId,
            _sum: VarId,
            _cout: VarId,
        ) {
        }

        fn enforce_equal(&mut self, _a: VarId, _b: VarId) {}
    }

    #[test]
    fn prover_build_device_link_requires_entropy_sample() {
        let dir = tempfile::tempdir().expect("tempdir");
        let left = utils_blake3_hash(b"x");
        let right = utils_blake3_hash(b"y");
        let pipe = qssm_gadget::merkle_truth_pipe(
            MerkleParentBlake3Op::new(left, right),
            TruthLimbV2Params {
                binding_context: [1u8; 32],
                n: 0,
                k: 0,
                bit_at_k: 0,
                challenge: [2u8; 32],
                external_entropy: [3u8; 32],
                external_entropy_included: false,
                device_entropy_link: Some([7u8; 32]),
            },
        );
        let result = TruthHandshakePackageBuilder::build_truth_handshake_v1_with_options(
            dir.path(),
            &pipe,
            &TruthHandshakeArtifacts {
                anchor_hash: [0u8; 32],
                leaf_left: left,
                leaf_right: right,
                external_entropy_included: false,
            },
            &TruthBuildOptions::default(),
        );
        match result {
            Err(PolyOpError::Binding(message)) => assert!(message.contains("entropy_sample_for_audit")),
            other => panic!("expected Binding error, got {other:?}"),
        }
    }

    #[test]
    fn prover_build_device_link_with_audit_sample_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let raw: Vec<u8> = (0u32..512)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 8) as u8)
            .collect();
        validate_entropy_full(&raw).expect("audit sample should pass");
        let link = utils_blake3_hash(&raw);
        let left = utils_blake3_hash(b"L_AUDIT");
        let right = utils_blake3_hash(b"R_AUDIT");
        let pipe = qssm_gadget::merkle_truth_pipe(
            MerkleParentBlake3Op::new(left, right),
            TruthLimbV2Params {
                binding_context: [5u8; 32],
                n: 0,
                k: 0,
                bit_at_k: 0,
                challenge: [6u8; 32],
                external_entropy: [7u8; 32],
                external_entropy_included: false,
                device_entropy_link: Some(link),
            },
        );
        TruthHandshakePackageBuilder::build_truth_handshake_v1_with_options(
            dir.path(),
            &pipe,
            &TruthHandshakeArtifacts {
                anchor_hash: [8u8; 32],
                leaf_left: left,
                leaf_right: right,
                external_entropy_included: false,
            },
            &TruthBuildOptions {
                entropy_sample_for_audit: Some(raw),
                ..Default::default()
            },
        )
        .expect("build with device link + audit raw");
    }

    #[test]
    fn polyops_engine_a_public_matches_direct_truth_bind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = [0xabu8; 32];
        let left = utils_blake3_hash(b"L2_ROLLUP_LEAF_LEFT");
        let right = utils_blake3_hash(b"L2_ROLLUP_LEAF_RIGHT");
        let rollup = hash_domain(DOMAIN_MSSQ_ROLLUP_CONTEXT, &[anchor.as_slice()]);
        let challenge = utils_blake3_hash(b"L2_FS_CHALLENGE_V1");
        let entropy = utils_blake3_hash(b"L2_LOCAL_ENTROPY_V1");

        let merkle = MerkleParentBlake3Op::new(left, right);
        let mut ctx = PolyOpContext::new("t");
        let mut cs = NoopConstraintSystem::default();
        let state_root = merkle
            .synthesize_with_context((), &mut cs, &mut ctx)
            .expect("merkle")
            .state_root;
        let direct = TruthWitness::bind(state_root.0, rollup, 7, 3, 1, challenge, entropy, false);

        let pipe = qssm_gadget::merkle_truth_pipe(
            MerkleParentBlake3Op::new(left, right),
            TruthLimbV2Params {
                binding_context: rollup,
                n: 7,
                k: 3,
                bit_at_k: 1,
                challenge,
                external_entropy: entropy,
                external_entropy_included: false,
                device_entropy_link: None,
            },
        );

        TruthHandshakePackageBuilder::build_truth_handshake_v1(
            dir.path(),
            &pipe,
            &TruthHandshakeArtifacts {
                anchor_hash: anchor,
                leaf_left: left,
                leaf_right: right,
                external_entropy_included: false,
            },
        )
        .expect("build");

        let package_raw = fs::read_to_string(dir.path().join("prover_package.json")).expect("read package");
        let package: serde_json::Value = serde_json::from_str(&package_raw).expect("parse package");
        let public = &package["engine_a_public"];
        assert_eq!(public["message_limb_u30"].as_u64().expect("limb"), direct.message_limb);
        assert_eq!(
            public["digest_coeff_vector_u4"].as_array().expect("coeffs").len(),
            direct.digest_coeff_vector.len()
        );
    }

    #[test]
    fn prover_package_refresh_arrays_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = [1u8; 32];
        let left = utils_blake3_hash(b"X");
        let right = utils_blake3_hash(b"Y");
        let rollup = hash_domain(DOMAIN_MSSQ_ROLLUP_CONTEXT, &[anchor.as_slice()]);
        let pipe = qssm_gadget::merkle_truth_pipe(
            MerkleParentBlake3Op::new(left, right),
            TruthLimbV2Params {
                binding_context: rollup,
                n: 0,
                k: 0,
                bit_at_k: 0,
                challenge: [2u8; 32],
                external_entropy: [3u8; 32],
                external_entropy_included: false,
                device_entropy_link: None,
            },
        );
        TruthHandshakePackageBuilder::build_truth_handshake_v1(
            dir.path(),
            &pipe,
            &TruthHandshakeArtifacts {
                anchor_hash: anchor,
                leaf_left: left,
                leaf_right: right,
                external_entropy_included: false,
            },
        )
        .expect("build");
        let raw = fs::read_to_string(dir.path().join("prover_package.json")).expect("read");
        let package: serde_json::Value = serde_json::from_str(&raw).expect("parse");
        assert!(package["refresh_metadata"].is_array());
        assert!(package["warnings"].is_array());
        let message_pos = raw.find("\"message_limb_u30\"").expect("message_limb");
        let digest_pos = raw.find("\"digest_coeff_vector_u4\"").expect("digest");
        assert!(message_pos < digest_pos);
    }
}
