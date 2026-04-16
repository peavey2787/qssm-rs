//! Full wrapper stream: **101** real `qssm-ms` + `qssm-le` proofs, [`qssm_wrapper::SovereignStreamManager`] through the first checkpoint (step **99**), then one more step.
#![cfg(all(feature = "ms-engine-b", feature = "lattice-bridge"))]

use blake3::Hasher;
use qssm_gadget::binding::SovereignWitness;
use qssm_gadget::merkle::MERKLE_DEPTH_MS;
use qssm_gadget::poly_ops::{EngineABindingInput, EngineABindingOp};
use qssm_le::{
    prove_arithmetic, verify_lattice, PublicInstance, VerifyingKey, Witness, N,
};
use qssm_ms::{commit, prove, verify};
use qssm_utils::hashing::blake3_hash;
use qssm_wrapper::{
    accumulator_genesis, accumulator_next, hex_lower_prefixed, step_hash, window_step_hashes_digest,
    ArtifactHashes, EngineABinding, L2HandshakeProverPackageV1, L2_HANDSHAKE_PACKAGE_VERSION,
    L2_TRANSCRIPT_MAP_LAYOUT_VERSION, MsBinding, PolyOpsSummaryV1, ProverArtifactsV1,
    ProverEngineAPublicV1, R1csManifestSummaryV1, SeamBinding, SovereignStreamManager, StepEnvelope,
    WitnessWireCountsV1, WrapperV1, WRAP_CONTEXT_DOMAIN, WRAP_SCHEMA_VERSION,
};
use tempfile::tempdir;

fn relation_digest(value: u64, target: u64, ms_challenge: [u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(48);
    v.extend_from_slice(&value.to_le_bytes());
    v.extend_from_slice(&target.to_le_bytes());
    v.extend_from_slice(&ms_challenge);
    blake3_hash(&v)
}

fn blake3_file_hex(body: &str) -> String {
    let mut h = Hasher::new();
    h.update(body.as_bytes());
    let digest: [u8; 32] = *h.finalize().as_bytes();
    hex_lower_prefixed(&digest)
}

fn build_step(
    step_index: u64,
    rollup: [u8; 32],
    vk: &VerifyingKey,
) -> StepEnvelope {
    let ledger: [u8; 32] = blake3_hash(format!("ledger-{step_index}").as_bytes());
    let seed: [u8; 32] = blake3_hash(format!("seed-{step_index}").as_bytes());
    let (root, salts) = commit(10, seed, ledger).expect("ms commit");
    let value = 100u64 + step_index;
    let target = 50u64;
    let context = format!("mirror-shift-step-{step_index}").into_bytes();
    let ms_proof = prove(value, target, &salts, ledger, &context, &rollup).expect("ms prove");
    assert!(verify(
        root,
        &ms_proof,
        ledger,
        value,
        target,
        &context,
        &rollup
    ));

    let state_root: [u8; 32] = blake3_hash(format!("state-{step_index}").as_bytes());
    let challenge: [u8; 32] = blake3_hash(format!("ch-{step_index}").as_bytes());
    let entropy: [u8; 32] = blake3_hash(format!("ent-{step_index}").as_bytes());
    let sw = SovereignWitness::bind(
        state_root,
        rollup,
        7,
        3,
        1,
        challenge,
        entropy,
        false,
    );
    assert!(sw.validate());

    let public = PublicInstance::digest_coeffs(sw.digest_coeff_vector);
    let mut r = [0i32; N];
    r[0] = 1;
    r[1] = -1;
    let witness = Witness { r };
    let (le_commitment, le_proof) =
        prove_arithmetic(vk, &public, &witness, &rollup).expect("le prove");
    assert!(verify_lattice(vk, &public, &le_commitment, &le_proof, &rollup).unwrap());

    let mut engine_in = EngineABindingInput {
        state_root: sw.root,
        ms_root: root.0,
        relation_digest: relation_digest(value, target, ms_proof.challenge),
        ms_fs_v2_challenge: ms_proof.challenge,
        rollup_context_digest: rollup,
        device_entropy_link: ledger,
        claimed_seam_commitment: [0u8; 32],
    };
    engine_in.claimed_seam_commitment = EngineABindingOp::commitment_digest(&engine_in);
    let seam_commit = engine_in.claimed_seam_commitment;
    let seam_open = EngineABindingOp::open_digest(&engine_in, seam_commit);
    let seam_bind = EngineABindingOp::binding_digest(&engine_in, seam_open);

    let sovereign_json = sw.to_prover_json();
    let merkle_json = "{}";
    let manifest_txt = format!("# step {step_index}\n");
    let sovereign_hex = blake3_file_hex(&sovereign_json);
    let merkle_hex = blake3_file_hex(merkle_json);
    let manifest_hex = blake3_file_hex(&manifest_txt);

    let kaspa = blake3_hash(&step_index.to_le_bytes());
    let leaf_l = blake3_hash(format!("L-{step_index}").as_bytes());
    let leaf_r = blake3_hash(format!("R-{step_index}").as_bytes());
    let rollup_hex = hex_lower_prefixed(&rollup);
    let prover_package = L2HandshakeProverPackageV1 {
        package_version: L2_HANDSHAKE_PACKAGE_VERSION.into(),
        description: "sovereign-stream integration (MS + LE)".into(),
        sim_kaspa_parent_block_id_hex: hex::encode(kaspa),
        merkle_leaf_left_hex: hex::encode(leaf_l),
        merkle_leaf_right_hex: hex::encode(leaf_r),
        rollup_state_root_hex: hex::encode(sw.root),
        nist_beacon_included: false,
        engine_a_public: ProverEngineAPublicV1 {
            message_limb_u30: sw.message_limb,
            digest_coeff_vector_u4: sw.digest_coeff_vector.to_vec(),
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
            manifest_file: "r1cs_merkle_parent.manifest.txt".into(),
            line_format: "xor|full_adder|equal with tab-separated var indices".into(),
        },
        poly_ops: PolyOpsSummaryV1 {
            transcript_map_layout_version: L2_TRANSCRIPT_MAP_LAYOUT_VERSION,
            merkle_depth: MERKLE_DEPTH_MS as u32,
            refresh_copy_count: 0,
            auto_refresh_merkle_xor: false,
        },
        refresh_metadata: vec![],
        warnings: vec![],
    };

    StepEnvelope {
        prover_package,
        wrapper_v1: WrapperV1 {
            rollup_context_digest_hex: rollup_hex,
            context_domain: WRAP_CONTEXT_DOMAIN.into(),
            step_index,
            ms_binding: MsBinding {
                ms_root_hex: hex_lower_prefixed(&root.0),
                ms_fs_v2_challenge_hex: hex_lower_prefixed(&ms_proof.challenge),
            },
            seam_binding: SeamBinding {
                seam_commitment_digest_hex: hex_lower_prefixed(&seam_commit),
                seam_open_digest_hex: hex_lower_prefixed(&seam_open),
                seam_binding_digest_hex: hex_lower_prefixed(&seam_bind),
            },
            engine_a_binding: EngineABinding {
                engine_a_public_message_limb_u30: sw.message_limb,
                engine_a_public_digest_coeff_vector_u4: sw.digest_coeff_vector.to_vec(),
            },
            artifact_hashes: ArtifactHashes {
                sovereign_witness_json_blake3_hex: sovereign_hex,
                merkle_parent_witness_json_blake3_hex: merkle_hex,
                r1cs_manifest_blake3_hex: manifest_hex,
            },
            schema_version: WRAP_SCHEMA_VERSION.into(),
        },
    }
}

#[test]
fn sovereign_stream_checkpoint_cycle_ms_le_101_steps() {
    let rollup: [u8; 32] = blake3_hash(b"SOVEREIGN-STREAM-ROLLUP-v1");
    let vk = VerifyingKey::from_seed(rollup);

    let stream_root = tempdir().expect("tempdir");
    let mut mgr = SovereignStreamManager::create(stream_root.path(), rollup).expect("stream");

    for i in 0u64..101 {
        let step = build_step(i, rollup, &vk);
        mgr.append_step(&step).expect("append");
    }

    let steps_path = stream_root.path().join("steps").join(format!("{}.jsonl", hex::encode(rollup)));
    let ck_path = stream_root
        .path()
        .join("checkpoints")
        .join(format!("{}.jsonl", hex::encode(rollup)));
    let steps_raw = std::fs::read_to_string(&steps_path).expect("read steps");
    assert_eq!(steps_raw.lines().count(), 101);
    let ck_raw = std::fs::read_to_string(&ck_path).expect("read checkpoints");
    assert_eq!(ck_raw.lines().count(), 1);

    let ck: qssm_wrapper::AccumulatorCheckpoint =
        serde_json::from_str(ck_raw.lines().next().unwrap()).expect("parse checkpoint");
    assert_eq!(ck.checkpoint_step_index, 99);
    assert_eq!(ck.window_start_step_index, 0);
    assert_eq!(ck.window_end_step_index, 99);
    assert_eq!(ck.checkpoint_every, 100);

    let mut acc = accumulator_genesis(rollup);
    let mut window_hashes = Vec::new();
    for line in steps_raw.lines().take(100) {
        let step: StepEnvelope = serde_json::from_str(line).expect("step json");
        let sh = step_hash(&step).expect("step hash");
        window_hashes.push(sh);
        acc = accumulator_next(rollup, step.wrapper_v1.step_index, acc, sh);
    }
    assert_eq!(ck.checkpoint_accumulator_hex, hex_lower_prefixed(&acc));
    assert_eq!(
        ck.window_step_hashes_blake3_hex,
        hex_lower_prefixed(&window_step_hashes_digest(&window_hashes))
    );

    // Step 100 extends the chain without a second checkpoint yet.
    let line100: StepEnvelope = serde_json::from_str(steps_raw.lines().nth(100).unwrap()).unwrap();
    let h100 = step_hash(&line100).unwrap();
    let acc100 = accumulator_next(rollup, 100, acc, h100);
    assert_eq!(mgr.current_accumulator(), acc100);
    assert_eq!(mgr.next_step_index(), 101);
}
