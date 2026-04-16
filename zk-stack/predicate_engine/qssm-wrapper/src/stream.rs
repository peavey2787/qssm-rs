//! Append-only JSONL stream + rolling accumulator checkpoints (hybrid wrapper spec).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use qssm_gadget::{parametric_age_gate_vk, parametric_millionaires_duel_vk, parse_template_id_param};
use qssm_utils::hashing::hash_domain;
use serde::{Deserialize, Serialize};

use crate::{
    accumulator_genesis, accumulator_next, decode_hex32, hex_lower_prefixed, step_hash, StepEnvelope,
    StepValidationError, WrapperError,
};

/// Domain tag for rolling window integrity over consecutive step hashes.
pub const DOMAIN_WINDOW_V1: &[u8] = b"QSSM-WRAP-WINDOW-v1";

/// Normative context domain string (must match every [`crate::WrapperV1::context_domain`]).
pub const WRAP_CONTEXT_DOMAIN: &str = "QSSM-WRAP-CONTEXT-v1";

/// Normative wrapper schema version.
pub const WRAP_SCHEMA_VERSION: &str = "qssm-hybrid-wrapper-v1";

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error(transparent)]
    StepValidation(#[from] StepValidationError),
    #[error(transparent)]
    Wrapper(#[from] WrapperError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonicalization failed writing checkpoint: {0}")]
    CheckpointCanonical(String),
    #[error("rollup_context_digest mismatch (stream is bound to one context)")]
    RollupMismatch,
    #[error("expected step index {expected} got {got}")]
    StepIndexOutOfSequence { expected: u64, got: u64 },
    #[error("context_domain must be {expected:?}, got {got:?}")]
    BadContextDomain { expected: String, got: String },
    #[error("schema_version must be {expected:?}, got {got:?}")]
    BadSchemaVersion { expected: String, got: String },
    #[error("rollup_context_digest_hex does not decode or does not match stream digest")]
    RollupHexMismatch,
    #[error("checkpoint_every must be >= 1, got {0}")]
    InvalidCheckpointEvery(u64),
    #[error("internal: window buffer size {got} expected {expected} at checkpoint")]
    WindowInvariant { expected: usize, got: usize },
    #[error("sovereign law materialization failed: {0}")]
    SovereignLaw(String),
}

/// One line in `checkpoints/<rollup>.jsonl` (canonical JSON via JCS when written).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccumulatorCheckpoint {
    pub schema_version: String,
    pub rollup_context_digest_hex: String,
    pub context_domain: String,
    pub checkpoint_every: u64,
    pub checkpoint_step_index: u64,
    pub checkpoint_accumulator_hex: String,
    pub window_start_step_index: u64,
    pub window_end_step_index: u64,
    pub window_step_hashes_blake3_hex: String,
    pub created_unix_ms: u64,
}

#[must_use]
pub fn window_step_hashes_digest(step_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_WINDOW_V1);
    for sh in step_hashes {
        h.update(sh);
    }
    *h.finalize().as_bytes()
}

fn rollup_file_stem(digest: &[u8; 32]) -> String {
    hex::encode(digest)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Append-only [`StepEnvelope`] store with automatic [`AccumulatorCheckpoint`] emission.
#[derive(Debug)]
pub struct SovereignStreamManager {
    root_dir: PathBuf,
    rollup_context_digest: [u8; 32],
    checkpoint_every: u64,
    next_step_index: u64,
    current_accumulator: [u8; 32],
    /// Step hashes for the current incomplete window (cleared after each checkpoint).
    window_step_hashes: Vec<[u8; 32]>,
    secrets_path: PathBuf,
}

impl SovereignStreamManager {
    /// Opens a **new** stream under `root_dir` (creates `steps/` and `checkpoints/`).
    ///
    /// `checkpoint_every` defaults to **100** in [`Self::create`].
    pub fn create(
        root_dir: impl AsRef<Path>,
        rollup_context_digest: [u8; 32],
    ) -> Result<Self, StreamError> {
        Self::create_with_checkpoint_every(root_dir, rollup_context_digest, 100)
    }

    pub fn create_with_checkpoint_every(
        root_dir: impl AsRef<Path>,
        rollup_context_digest: [u8; 32],
        checkpoint_every: u64,
    ) -> Result<Self, StreamError> {
        if checkpoint_every < 1 {
            return Err(StreamError::InvalidCheckpointEvery(checkpoint_every));
        }
        let root_dir = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(root_dir.join("steps"))?;
        fs::create_dir_all(root_dir.join("checkpoints"))?;
        Ok(Self {
            root_dir: root_dir.clone(),
            rollup_context_digest,
            checkpoint_every,
            next_step_index: 0,
            current_accumulator: accumulator_genesis(rollup_context_digest),
            window_step_hashes: Vec::with_capacity(checkpoint_every as usize),
            secrets_path: root_dir.join("secrets.json"),
        })
    }

    fn persist_local_salt(&self, step_index: u64, salt: [u8; 32]) -> Result<(), StreamError> {
        let mut root: serde_json::Value = if self.secrets_path.exists() {
            let raw = fs::read_to_string(&self.secrets_path)?;
            serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };
        let obj = root.as_object_mut().ok_or_else(|| {
            StreamError::SovereignLaw("secrets.json root must be object".to_string())
        })?;
        let salts = obj
            .entry("sovereign_law_salts")
            .or_insert_with(|| serde_json::json!({}));
        let salts_obj = salts.as_object_mut().ok_or_else(|| {
            StreamError::SovereignLaw("secrets.json.sovereign_law_salts must be object".to_string())
        })?;
        salts_obj.insert(
            step_index.to_string(),
            serde_json::Value::String(hex_lower_prefixed(&salt)),
        );
        fs::write(
            &self.secrets_path,
            serde_json::to_string_pretty(&root).map_err(StreamError::Json)?,
        )?;
        Ok(())
    }

    fn materialize_step_for_persistence(&self, step: &StepEnvelope) -> Result<StepEnvelope, StreamError> {
        let mut out = step.clone();
        let Some(law) = out.wrapper_v1.sovereign_law.as_mut() else {
            return Ok(out);
        };
        let parsed = parse_template_id_param(&law.template_id);
        let Some(param) = parsed.param else {
            return Ok(out);
        };
        let salt = hash_domain(
            "QSSM-WRAP-SALT-v1",
            &[
                out.wrapper_v1.step_index.to_le_bytes().as_slice(),
                self.rollup_context_digest.as_slice(),
                law.template_id.as_bytes(),
            ],
        );
        let blinded = hash_domain("QSSM-WRAP-LAW-COMMIT-v1", &[salt.as_slice(), param.as_bytes()]);
        self.persist_local_salt(out.wrapper_v1.step_index, salt)?;
        law.template_id = parsed.base_id.clone();
        law.blinded_parameter_hash_hex = Some(hex_lower_prefixed(&blinded));
        if law.template_script.is_none() {
            law.template_script = Some(match parsed.base_id.as_str() {
                "age_gate_kaspa_zk_v1" => parametric_age_gate_vk(blinded),
                "millionaires_duel_zk_v1" => parametric_millionaires_duel_vk(blinded),
                "simple_math_zk_v1" => serde_json::json!({
                    "template_id": "simple_math_zk_v1",
                    "constraints": [
                        {
                            "kind": "zk_field_comparison",
                            "lhs_field": "claim.answer",
                            "public_input_commitment_hex": hex_lower_prefixed(&blinded)
                        }
                    ]
                }),
                _ => serde_json::json!({ "template_id": parsed.base_id }),
            });
        }
        Ok(out)
    }

    fn steps_path(&self) -> PathBuf {
        self.root_dir
            .join("steps")
            .join(format!("{}.jsonl", rollup_file_stem(&self.rollup_context_digest)))
    }

    fn checkpoints_path(&self) -> PathBuf {
        self.root_dir.join("checkpoints").join(format!(
            "{}.jsonl",
            rollup_file_stem(&self.rollup_context_digest)
        ))
    }

    /// Next step index this manager expects (monotonic counter).
    #[must_use]
    pub fn next_step_index(&self) -> u64 {
        self.next_step_index
    }

    /// Rolling accumulator after the last successful append (`genesis` before any step).
    #[must_use]
    pub fn current_accumulator(&self) -> [u8; 32] {
        self.current_accumulator
    }

    /// Verify envelope against this stream, extend the accumulator, append one JSON line to
    /// `steps/<rollup>.jsonl`, and emit a checkpoint line when `(step_index + 1) % checkpoint_every == 0`.
    pub fn append_step(&mut self, step: &StepEnvelope) -> Result<(), StreamError> {
        let step = self.materialize_step_for_persistence(step)?;
        let w = &step.wrapper_v1;
        if w.context_domain != WRAP_CONTEXT_DOMAIN {
            return Err(StreamError::BadContextDomain {
                expected: WRAP_CONTEXT_DOMAIN.into(),
                got: w.context_domain.clone(),
            });
        }
        if w.schema_version != WRAP_SCHEMA_VERSION {
            return Err(StreamError::BadSchemaVersion {
                expected: WRAP_SCHEMA_VERSION.into(),
                got: w.schema_version.clone(),
            });
        }
        let digest_from_envelope = decode_hex32(&w.rollup_context_digest_hex)
            .map_err(|_| StreamError::RollupHexMismatch)?;
        if digest_from_envelope != self.rollup_context_digest {
            return Err(StreamError::RollupMismatch);
        }
        if w.step_index != self.next_step_index {
            return Err(StreamError::StepIndexOutOfSequence {
                expected: self.next_step_index,
                got: w.step_index,
            });
        }

        step.validate_template_rules()?;

        let sh = step_hash(&step)?;
        self.current_accumulator = accumulator_next(
            self.rollup_context_digest,
            w.step_index,
            self.current_accumulator,
            sh,
        );
        self.window_step_hashes.push(sh);

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.steps_path())?;
        writeln!(f, "{}", serde_json::to_string(&step)?)?;
        f.flush()?;

        let end = w.step_index;
        if (end + 1) % self.checkpoint_every == 0 {
            let expected = self.checkpoint_every as usize;
            if self.window_step_hashes.len() != expected {
                return Err(StreamError::WindowInvariant {
                    expected,
                    got: self.window_step_hashes.len(),
                });
            }
            let window_digest = window_step_hashes_digest(&self.window_step_hashes);
            let window_start = end + 1 - self.checkpoint_every;
            let ckpt = AccumulatorCheckpoint {
                schema_version: WRAP_SCHEMA_VERSION.into(),
                rollup_context_digest_hex: hex_lower_prefixed(&self.rollup_context_digest),
                context_domain: WRAP_CONTEXT_DOMAIN.into(),
                checkpoint_every: self.checkpoint_every,
                checkpoint_step_index: end,
                checkpoint_accumulator_hex: hex_lower_prefixed(&self.current_accumulator),
                window_start_step_index: window_start,
                window_end_step_index: end,
                window_step_hashes_blake3_hex: hex_lower_prefixed(&window_digest),
                created_unix_ms: now_unix_ms(),
            };
            let ckpt_line = serde_jcs::to_string(&ckpt)
                .map_err(|e| StreamError::CheckpointCanonical(e.to_string()))?;
            let mut cf = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.checkpoints_path())?;
            writeln!(cf, "{ckpt_line}")?;
            cf.flush()?;
            self.window_step_hashes.clear();
        }

        self.next_step_index = self.next_step_index.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArtifactHashes, EngineABinding, L2HandshakeProverPackageV1, L2_HANDSHAKE_PACKAGE_VERSION,
        L2_TRANSCRIPT_MAP_LAYOUT_VERSION, MsBinding, PolyOpsSummaryV1, ProverArtifactsV1,
        ProverEngineAPublicV1, R1csManifestSummaryV1, SeamBinding, SovereignLawV1, StepEnvelope,
        WitnessWireCountsV1, WrapperV1,
    };
    use tempfile::tempdir;

    fn fixture_digest_coeffs() -> Vec<u32> {
        let mut v = vec![0u32; 64];
        v[0] = 1;
        v[1] = 2;
        v[2] = 3;
        v[3] = 4;
        v
    }

    fn fixture_step(step_index: u64, rollup_hex: &str) -> StepEnvelope {
        let digest_coeff = fixture_digest_coeffs();
        StepEnvelope {
            prover_package: L2HandshakeProverPackageV1 {
                package_version: L2_HANDSHAKE_PACKAGE_VERSION.into(),
                description: "fixture".into(),
                sim_kaspa_parent_block_id_hex: "01020304".into(),
                merkle_leaf_left_hex: "11".into(),
                merkle_leaf_right_hex: "22".into(),
                rollup_state_root_hex: "33".into(),
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
                    transcript_map_layout_version: L2_TRANSCRIPT_MAP_LAYOUT_VERSION,
                    merkle_depth: 7,
                    refresh_copy_count: 0,
                    auto_refresh_merkle_xor: false,
                },
                refresh_metadata: vec![],
                warnings: vec![],
            },
            wrapper_v1: WrapperV1 {
                rollup_context_digest_hex: rollup_hex.into(),
                context_domain: WRAP_CONTEXT_DOMAIN.into(),
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
                schema_version: WRAP_SCHEMA_VERSION.into(),
            },
        }
    }

    #[test]
    fn append_hundred_emits_one_checkpoint() {
        let dir = tempdir().unwrap();
        let ctx = [0x7Eu8; 32];
        let rollup_hex = hex_lower_prefixed(&ctx);
        let mut mgr = SovereignStreamManager::create(dir.path(), ctx).unwrap();
        for i in 0u64..100 {
            let step = fixture_step(i, &rollup_hex);
            mgr.append_step(&step).unwrap();
        }
        let steps_raw = fs::read_to_string(mgr.steps_path()).unwrap();
        assert_eq!(steps_raw.lines().count(), 100);
        let ck_raw = fs::read_to_string(mgr.checkpoints_path()).unwrap();
        assert_eq!(ck_raw.lines().count(), 1);
        let v: AccumulatorCheckpoint = serde_json::from_str(ck_raw.lines().next().unwrap()).unwrap();
        assert_eq!(v.checkpoint_step_index, 99);
        assert_eq!(v.window_start_step_index, 0);
        assert_eq!(v.window_end_step_index, 99);
        assert_eq!(v.checkpoint_every, 100);
        // Window hash matches independent recompute from step hashes on disk.
        let mut acc = accumulator_genesis(ctx);
        let mut hashes = Vec::new();
        for line in steps_raw.lines() {
            let step: StepEnvelope = serde_json::from_str(line).unwrap();
            let sh = step_hash(&step).unwrap();
            hashes.push(sh);
            acc = accumulator_next(ctx, step.wrapper_v1.step_index, acc, sh);
        }
        assert_eq!(hex_lower_prefixed(&acc), v.checkpoint_accumulator_hex);
        assert_eq!(
            hex_lower_prefixed(&window_step_hashes_digest(&hashes)),
            v.window_step_hashes_blake3_hex
        );
    }

    #[test]
    fn rejects_wrong_step_index() {
        let dir = tempdir().unwrap();
        let ctx = [1u8; 32];
        let rh = hex_lower_prefixed(&ctx);
        let mut mgr = SovereignStreamManager::create(dir.path(), ctx).unwrap();
        let step = fixture_step(1, &rh);
        assert!(matches!(
            mgr.append_step(&step),
            Err(StreamError::StepIndexOutOfSequence { .. })
        ));
    }

    #[test]
    fn rejects_wrong_rollup() {
        let dir = tempdir().unwrap();
        let ctx = [2u8; 32];
        let mut mgr = SovereignStreamManager::create(dir.path(), ctx).unwrap();
        let step = fixture_step(0, &hex_lower_prefixed(&[0xabu8; 32]));
        assert!(matches!(
            mgr.append_step(&step),
            Err(StreamError::RollupMismatch)
        ));
    }

    #[test]
    fn rejects_bad_context_domain() {
        let dir = tempdir().unwrap();
        let ctx = [3u8; 32];
        let rh = hex_lower_prefixed(&ctx);
        let mut mgr = SovereignStreamManager::create(dir.path(), ctx).unwrap();
        let mut step = fixture_step(0, &rh);
        step.wrapper_v1.context_domain = "wrong".into();
        assert!(matches!(
            mgr.append_step(&step),
            Err(StreamError::BadContextDomain { .. })
        ));
    }

    #[test]
    fn materializes_parametric_law_and_persists_salt_locally() {
        let dir = tempdir().unwrap();
        let ctx = [4u8; 32];
        let rh = hex_lower_prefixed(&ctx);
        let mut mgr = SovereignStreamManager::create(dir.path(), ctx).unwrap();
        let mut step = fixture_step(0, &rh);
        step.wrapper_v1.sovereign_law = Some(SovereignLawV1 {
            template_id: "simple_math_zk_v1:42".into(),
            template_script: None,
            blinded_parameter_hash_hex: None,
        });
        mgr.append_step(&step).unwrap();
        let steps_raw = fs::read_to_string(mgr.steps_path()).unwrap();
        let persisted: StepEnvelope = serde_json::from_str(steps_raw.lines().next().unwrap()).unwrap();
        let law = persisted.wrapper_v1.sovereign_law.unwrap();
        assert_eq!(law.template_id, "simple_math_zk_v1");
        assert!(law.blinded_parameter_hash_hex.is_some());
        assert!(law.template_script.is_some());
        let secrets = fs::read_to_string(dir.path().join("secrets.json")).unwrap();
        assert!(secrets.contains("\"sovereign_law_salts\""));
        assert!(secrets.contains("\"0\""));
    }
}
