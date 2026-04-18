//! Append-only JSONL stream + rolling accumulator checkpoints (hybrid wrapper spec).

use std::fs;
use std::path::{Path, PathBuf};

use crate::checkpoint::{self, CheckpointWriteError};
use crate::law_materialization::{self, LawMaterializationError};
use crate::store::{self, StoreError};
#[allow(unused_imports)] // used by tests
use crate::{
    accumulator_genesis, accumulator_next, hex_lower_prefixed, step_hash, StepEnvelope,
    StepValidationError, WrapperError,
};

// Re-export types and constants that were previously defined here, now in submodules.
pub use crate::checkpoint::{
    AccumulatorCheckpoint, window_step_hashes_digest,
    DOMAIN_WINDOW_V1, WRAP_CONTEXT_DOMAIN, WRAP_SCHEMA_VERSION,
};

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
    #[error("binding_context mismatch (stream is bound to one context)")]
    BindingContextMismatch,
    #[error("expected step index {expected} got {got}")]
    StepIndexOutOfSequence { expected: u64, got: u64 },
    #[error("context_domain must be {expected:?}, got {got:?}")]
    BadContextDomain { expected: String, got: String },
    #[error("schema_version must be {expected:?}, got {got:?}")]
    BadSchemaVersion { expected: String, got: String },
    #[error("binding_context_hex does not decode or does not match stream digest")]
    BindingContextHexMismatch,
    #[error("checkpoint_every must be >= 1, got {0}")]
    InvalidCheckpointEvery(u64),
    #[error("internal: window buffer size {got} expected {expected} at checkpoint")]
    WindowInvariant { expected: usize, got: usize },
    #[error("sovereign law materialization failed: {0}")]
    SovereignLaw(String),
}

impl From<StoreError> for StreamError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::BadContextDomain { expected, got } => Self::BadContextDomain { expected, got },
            StoreError::BadSchemaVersion { expected, got } => Self::BadSchemaVersion { expected, got },
            StoreError::BindingContextHexMismatch => Self::BindingContextHexMismatch,
            StoreError::BindingContextMismatch => Self::BindingContextMismatch,
            StoreError::StepIndexOutOfSequence { expected, got } => Self::StepIndexOutOfSequence { expected, got },
            StoreError::Io(e) => Self::Io(e),
            StoreError::Json(e) => Self::Json(e),
        }
    }
}

impl From<LawMaterializationError> for StreamError {
    fn from(e: LawMaterializationError) -> Self {
        match e {
            LawMaterializationError::SovereignLaw(s) => Self::SovereignLaw(s),
            LawMaterializationError::Io(e) => Self::Io(e),
            LawMaterializationError::Json(e) => Self::Json(e),
        }
    }
}

impl From<CheckpointWriteError> for StreamError {
    fn from(e: CheckpointWriteError) -> Self {
        match e {
            CheckpointWriteError::Canonical(s) => Self::CheckpointCanonical(s),
            CheckpointWriteError::Io(e) => Self::Io(e),
        }
    }
}

/// Append-only [`StepEnvelope`] store with automatic [`AccumulatorCheckpoint`] emission.
#[derive(Debug)]
pub struct SovereignStreamManager {
    root_dir: PathBuf,
    binding_context: [u8; 32],
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
        binding_context: [u8; 32],
    ) -> Result<Self, StreamError> {
        Self::create_with_checkpoint_every(root_dir, binding_context, 100)
    }

    pub fn create_with_checkpoint_every(
        root_dir: impl AsRef<Path>,
        binding_context: [u8; 32],
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
            binding_context,
            checkpoint_every,
            next_step_index: 0,
            current_accumulator: accumulator_genesis(binding_context),
            window_step_hashes: Vec::with_capacity(checkpoint_every as usize),
            secrets_path: root_dir.join("secrets.json"),
        })
    }

    fn steps_path(&self) -> PathBuf {
        self.root_dir
            .join("steps")
            .join(format!("{}.jsonl", store::rollup_file_stem(&self.binding_context)))
    }

    fn checkpoints_path(&self) -> PathBuf {
        self.root_dir.join("checkpoints").join(format!(
            "{}.jsonl",
            store::rollup_file_stem(&self.binding_context)
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
        // 1. Law materialization (no-op if no sovereign_law / no param suffix).
        let step = law_materialization::materialize_step(
            step,
            self.binding_context,
            &self.secrets_path,
        )?;

        // 2. Binding validation (context_domain, schema_version, binding_context, step_index).
        store::validate_step_binding(&step, self.binding_context, self.next_step_index)?;

        // 3. Template rules validation.
        step.validate_template_rules()?;

        // 4. Accumulator update.
        let sh = step_hash(&step)?;
        self.current_accumulator = accumulator_next(
            self.binding_context,
            step.wrapper_v1.step_index,
            self.current_accumulator,
            sh,
        );
        self.window_step_hashes.push(sh);

        // 5. Persist step to store.
        store::append_step_line(&step, &self.steps_path())?;

        // 6. Emit checkpoint at window boundaries.
        let end = step.wrapper_v1.step_index;
        if (end + 1) % self.checkpoint_every == 0 {
            let expected = self.checkpoint_every as usize;
            if self.window_step_hashes.len() != expected {
                return Err(StreamError::WindowInvariant {
                    expected,
                    got: self.window_step_hashes.len(),
                });
            }
            let ckpt = checkpoint::create_checkpoint(
                end,
                self.checkpoint_every,
                self.binding_context,
                self.current_accumulator,
                &self.window_step_hashes,
            );
            checkpoint::write_checkpoint_line(&ckpt, &self.checkpoints_path())?;
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
        ArtifactHashes, EngineABinding, SovereignHandshakeProverPackageV1, SOVEREIGN_HANDSHAKE_PACKAGE_VERSION,
        SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION, PROTOCOL_VERSION, MsBinding, PolyOpsSummaryV1, ProverArtifactsV1,
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
            prover_package: SovereignHandshakeProverPackageV1 {
                package_version: SOVEREIGN_HANDSHAKE_PACKAGE_VERSION.into(),
                protocol_version: PROTOCOL_VERSION,
                description: "fixture".into(),
                sim_anchor_hash_hex: "01020304".into(),
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
                    transcript_map_layout_version: SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION,
                    merkle_depth: 7,
                    refresh_copy_count: 0,
                    auto_refresh_merkle_xor: false,
                },
                refresh_metadata: vec![],
                warnings: vec![],
            },
            wrapper_v1: WrapperV1 {
                binding_context_hex: rollup_hex.into(),
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
            Err(StreamError::BindingContextMismatch)
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
