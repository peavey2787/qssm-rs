//! Tauri commands for sovereign identity + mesh snapshot controls.

use serde_json::{json, Value};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tauri::Manager;

use bip39::Mnemonic;
// SmtRoot: local newtype replacing qssm_traits::SmtRoot (crate removed)
struct SmtRoot(pub [u8; 32]);
use qssm_gadget::TruthWitness;
use qssm_gadget::EntropyAnchor;
use qssm_entropy::HarvestConfig;
use qssm_le::BETA;
use qssm_le::{encode_rq_coeffs_le, prove_arithmetic, PublicInstance, VerifyingKey, Witness};
use qssm_utils::hashing::blake3_hash;
use rand::{RngCore, SeedableRng};
use serde::Deserialize;
use qssm_templates::{QssmTemplate, QSSM_TEMPLATE_VERSION};

/// Application-level harvest gate (moved from `qssm-entropy`; this is UI/policy, not harvesting).
static HARDWARE_HARVEST_ENABLED: AtomicBool = AtomicBool::new(true);

/// Enable or pause hardware harvesting (pulse / proofs skip harvest when off).
#[tauri::command]
pub fn toggle_hardware_harvest(enabled: bool) -> bool {
    HARDWARE_HARVEST_ENABLED.store(enabled, Ordering::SeqCst);
    enabled
}

/// Retry `mssq-net` sidecar after a failed start (port conflict, etc.).
#[tauri::command]
pub fn retry_network_sidecar(app: tauri::AppHandle) -> Result<(), String> {
    let mmdbs = crate::sidecar::mmdb_candidates(&app);
    crate::sidecar::retry_sidecar(&app, mmdbs)
}

/// Generate a BIP39 24-word mnemonic from 256-bit hardware entropy.
#[tauri::command]
pub fn generate_mnemonic_24() -> Result<Value, String> {
    if !HARDWARE_HARVEST_ENABLED.load(Ordering::SeqCst) {
        return Err("hardware harvest is paused (UI / policy toggle)".into());
    }
    let hb = qssm_entropy::harvest(&HarvestConfig::default()).map_err(|e| e.to_string())?;
    let entropy_32 = hb.to_seed();
    let mnemonic =
        Mnemonic::from_entropy(&entropy_32).map_err(|e| format!("bip39 from entropy: {e}"))?;
    Ok(json!({
        "mnemonic_24": mnemonic.to_string(),
        "entropy_hex": hex::encode(entropy_32),
        "timestamp_ns": hb.timestamp(),
    }))
}

#[tauri::command]
pub fn validate_mnemonic_24(mnemonic_24: String) -> Result<Value, String> {
    let peer_id = crate::identity::validate_mnemonic_and_derive_peer_id(&mnemonic_24)?;
    Ok(json!({
        "ok": true,
        "public_peer_id": peer_id,
    }))
}

#[tauri::command]
pub fn list_identities(app: tauri::AppHandle) -> Result<Value, String> {
    let list = crate::identity::list_identities(&app)?;
    serde_json::to_value(list).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn create_identity_from_mnemonic(
    app: tauri::AppHandle,
    id_name: String,
    mnemonic_24: String,
    password: String,
) -> Result<Value, String> {
    let id = crate::identity::create_identity(&app, id_name, mnemonic_24, password)?;
    serde_json::to_value(id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn decrypt_identity(app: tauri::AppHandle, id: String, pwd: String) -> Result<Value, String> {
    let mut decrypted = crate::identity::decrypt_identity(&app, &id, &pwd)?;
    let out = json!({
        "id": decrypted.id,
        "id_name": decrypted.id_name,
        "public_peer_id": decrypted.public_peer_id,
        "mnemonic_24": decrypted.mnemonic_24.clone(),
    });
    use zeroize::Zeroize as _;
    decrypted.mnemonic_24.zeroize();
    Ok(out)
}

#[tauri::command]
pub fn activate_identity(app: tauri::AppHandle, id: String, pwd: String) -> Result<Value, String> {
    let mut decrypted = crate::identity::decrypt_identity(&app, &id, &pwd)?;
    crate::sidecar::set_active_identity(decrypted.id.clone());
    let out = json!({
        "active_identity": decrypted.id.clone(),
        "public_peer_id": decrypted.public_peer_id,
    });
    use zeroize::Zeroize as _;
    decrypted.mnemonic_24.zeroize();
    Ok(out)
}

#[tauri::command]
pub fn delete_identity(app: tauri::AppHandle, id: String, pwd: String) -> Result<(), String> {
    crate::identity::delete_identity(&app, &id, &pwd)
}

#[tauri::command]
pub fn list_hired_storage(app: tauri::AppHandle) -> Result<Value, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("app_data_dir: {e}"))?;
    let path = dir.join("hired_storage.json");
    if !path.exists() {
        return Ok(json!([]));
    }
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn hire_storage_provider(
    app: tauri::AppHandle,
    provider_peer_id: String,
    lease_label: String,
) -> Result<Value, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("app_data_dir: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("hired_storage.json");
    let mut cur: Vec<Value> = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    cur.push(json!({
        "provider_peer_id": provider_peer_id,
        "lease_label": lease_label,
        "rent_due": "pending_epoch_1024",
        "status": "active",
    }));
    fs::write(
        &path,
        serde_json::to_string_pretty(&cur).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(json!({"ok": true, "count": cur.len()}))
}

#[tauri::command]
pub fn repair_state(peer_id: String) -> Result<Value, String> {
    crate::sidecar::request_merkle_repair_for_peer(peer_id)?;
    Ok(json!({"ok": true}))
}

/// Switch MSSQ `network_id` (0 = mainnet, 1 = testnet-1). Stops the current sidecar node and starts a new one.
///
/// Invoke from JS with camelCase: `invoke("set_network_profile", { networkId: 0 | 1 })`.
#[tauri::command]
pub fn set_network_profile(network_id: u32) -> Result<(), String> {
    if network_id > 1 {
        return Err("unsupported network_id: use 0 (mainnet) or 1 (testnet-1)".into());
    }
    crate::sidecar::request_network_switch(network_id)
}

#[tauri::command]
pub fn get_network_profile() -> u32 {
    crate::sidecar::current_network_id()
}

const L1_HUD: &str = "Connected to Kaspa Node";
const VK_SEED: [u8; 32] = *b"QSSM_DESKTOP_VK_SEED_V1_________";

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum HandoffAnchorJson {
    #[serde(rename = "kaspa")]
    Kaspa { parent_block_id_hex: String },
    #[serde(rename = "static_root")]
    StaticRoot { root_hex: String },
    #[serde(rename = "timestamp")]
    Timestamp { unix_secs: u64 },
}

impl HandoffAnchorJson {
    fn to_entropy_anchor(&self) -> Result<EntropyAnchor, String> {
        match self {
            Self::Kaspa {
                parent_block_id_hex,
            } => Ok(EntropyAnchor::AnchorHash(hex_to_32(
                parent_block_id_hex,
            )?)),
            Self::StaticRoot { root_hex } => Ok(EntropyAnchor::StaticRoot(hex_to_32(root_hex)?)),
            Self::Timestamp { unix_secs } => Ok(EntropyAnchor::TimestampUnixSecs {
                unix_secs: *unix_secs,
            }),
        }
    }

    fn kind_label(&self) -> &'static str {
        match self {
            Self::Kaspa { .. } => "kaspa",
            Self::StaticRoot { .. } => "static_root",
            Self::Timestamp { .. } => "timestamp",
        }
    }
}

#[derive(Debug, Deserialize)]
struct HandoffFile {
    #[serde(default)]
    anchor: Option<HandoffAnchorJson>,
    #[serde(default)]
    anchor_hash_hex: Option<String>,
    state_root_hex: String,
    binding_context_hex: String,
    n: u8,
    k: u8,
    bit_at_k: u8,
    challenge_hex: String,
    #[serde(default)]
    local_entropy_hex: Option<String>,
}

impl HandoffFile {
    fn resolve_entropy_anchor(&self) -> Result<(EntropyAnchor, &'static str), String> {
        if let Some(a) = &self.anchor {
            let label = a.kind_label();
            return Ok((a.to_entropy_anchor()?, label));
        }
        let hex = self.anchor_hash_hex.as_ref().ok_or_else(|| {
            "missing entropy anchor: set anchor or anchor_hash_hex".to_string()
        })?;
        Ok((
            EntropyAnchor::AnchorHash(hex_to_32(hex)?),
            "anchor",
        ))
    }
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let t = s.trim().trim_start_matches("0x");
    let v = hex::decode(t).map_err(|e| format!("hex decode: {e}"))?;
    if v.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", v.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn random_witness(rng: &mut impl RngCore) -> Witness {
    loop {
        let mut r = [0i32; qssm_le::N];
        for x in &mut r {
            *x = (rng.next_u32() % (2 * BETA + 1)) as i32 - BETA as i32;
        }
        let w = Witness::new(r);
        if w.validate().is_ok() {
            return w;
        }
    }
}

fn prove_lattice_demo(
    digest_coeff_vector: [u32; qssm_le::PUBLIC_DIGEST_COEFFS],
    rollup_ctx: &[u8; 32],
    rng_seed: [u8; 32],
) -> Result<serde_json::Value, String> {
    let vk = VerifyingKey::from_seed(VK_SEED);
    let public = PublicInstance::digest_coeffs(digest_coeff_vector).map_err(|e| e.to_string())?;

    let mut rng = rand::rngs::StdRng::from_seed(rng_seed);
    for attempt in 0..24u8 {
        let witness = random_witness(&mut rng);
        // Derive per-attempt masking seed so each retry is deterministic
        let mask_seed = qssm_utils::hashing::hash_domain(
            "QSSM-SDK-LE-MASK-v1",
            &[&rng_seed, rollup_ctx, &[attempt]],
        );
        if let Ok((commitment, proof)) = prove_arithmetic(&vk, &public, &witness, rollup_ctx, mask_seed) {
            return Ok(json!({
                "commitment_coeffs_hex": hex::encode(encode_rq_coeffs_le(&commitment.0)),
                "t_coeffs_hex": hex::encode(encode_rq_coeffs_le(&proof.t)),
                "z_coeffs_hex": hex::encode(encode_rq_coeffs_le(&proof.z)),
                "challenge_hex": hex::encode(proof.challenge_seed),
            }));
        }
    }
    Err("lattice prover: rejected too many times (retry)".into())
}

fn run_pipeline(h: HandoffFile) -> Result<serde_json::Value, String> {
    let (entropy_anchor, anchor_kind) = h.resolve_entropy_anchor()?;
    let state_root = hex_to_32(&h.state_root_hex)?;
    let rollup_ctx = hex_to_32(&h.binding_context_hex)?;
    let challenge = hex_to_32(&h.challenge_hex)?;
    let smt = SmtRoot(state_root);

    let local = match &h.local_entropy_hex {
        Some(s) => hex_to_32(s)?,
        None => blake3_hash(b"QSSM_DESKTOP_DEFAULT_LOCAL_ENTROPY"),
    };

    let t0 = Instant::now();
    // Derive external entropy from anchor + local entropy (no network I/O).
    let anchor_bytes = match &entropy_anchor {
        EntropyAnchor::AnchorHash(h) => *h,
        EntropyAnchor::StaticRoot(r) => *r,
        EntropyAnchor::TimestampUnixSecs { unix_secs } => blake3_hash(&unix_secs.to_le_bytes()),
    };
    let external_entropy = blake3_hash(&[anchor_bytes.as_slice(), local.as_slice()].concat());
    let external_entropy_included = false;
    let limb_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let truth_witness = TruthWitness::bind(
        state_root,
        rollup_ctx,
        h.n,
        h.k,
        h.bit_at_k,
        challenge,
        external_entropy,
        external_entropy_included,
    );
    truth_witness.validate().map_err(|e| format!("TruthWitness: {e}"))?;

    let sw: Value = serde_json::from_str(&truth_witness.to_prover_json()
        .map_err(|e| format!("truth witness JSON serialization failed: {e}"))?)
        .map_err(|e| format!("truth witness JSON serialization failed: {e}"))?;
    let le_rng_seed = qssm_utils::hashing::hash_domain(
        "QSSM-SDK-LE-MASK-v1",
        &[&external_entropy, &rollup_ctx],
    );
    let lattice = prove_lattice_demo(truth_witness.digest_coeff_vector, &rollup_ctx, le_rng_seed)?;
    let qrng = if external_entropy_included { "external" } else { "fallback" };
    let l1_sync = match anchor_kind {
        "kaspa" => L1_HUD,
        "static_root" => "Generic mode - static root anchor (no L1)",
        "timestamp" => "Generic mode - timestamp anchor (no L1)",
        _ => "Generic verification",
    };

    Ok(json!({
        "l1_sync": l1_sync,
        "entropy_anchor_kind": anchor_kind,
        "qrng_status": qrng,
        "nist_included": external_entropy_included,
        "prover_latency_ms": limb_ms,
        "state_root_commitment": hex::encode(smt.0),
        "sovereign_witness": sw,
        "lattice_proof": lattice,
    }))
}

#[tauri::command]
pub fn generate_proof_from_file(path: String) -> Result<String, String> {
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    let h: HandoffFile =
        serde_json::from_str(&raw).map_err(|e| format!("parse handoff JSON: {e}"))?;
    let v = run_pipeline(h)?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn generate_proof_from_handoff_json(json: String) -> Result<String, String> {
    let h: HandoffFile =
        serde_json::from_str(&json).map_err(|e| format!("parse handoff JSON: {e}"))?;
    let v = run_pipeline(h)?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn lattice_demo_vk_seed_hex() -> String {
    hex::encode(VK_SEED)
}

#[tauri::command]
pub fn proof_of_age_template_json() -> Result<String, String> {
    let t = QssmTemplate::proof_of_age("proof-of-age-21")
        .with_lattice_vk_seed_hex(hex::encode(VK_SEED))
        .with_notes(
            "Pair with QSSM Helper output: check sovereign_witness.public.digest_coeff_vector_u4 and lattice_proof against qssm-le verifying key from lattice_vk_seed_hex.",
        );
    serde_json::to_string_pretty(&t).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn verify_claim_with_template(
    template_json: String,
    claim_json: String,
) -> Result<String, String> {
    let template: QssmTemplate =
        serde_json::from_str(&template_json).map_err(|e| format!("parse template: {e}"))?;
    if template.qssm_template_version() != QSSM_TEMPLATE_VERSION {
        return Err(format!(
            "unsupported qssm_template_version (got {}, expected {})",
            template.qssm_template_version(), QSSM_TEMPLATE_VERSION
        ));
    }
    let claim: Value =
        serde_json::from_str(&claim_json).map_err(|e| format!("parse claim JSON: {e}"))?;
    match template.verify_public_claim(&claim) {
        Ok(()) => serde_json::to_string(&json!({"ok": true, "detail": "all predicates passed"}))
            .map_err(|e| e.to_string()),
        Err(e) => serde_json::to_string(&json!({"ok": false, "detail": e.to_string()}))
            .map_err(|e| e.to_string()),
    }
}

#[tauri::command]
pub fn export_qssm_template(path: String, template_json: String) -> Result<(), String> {
    let template = QssmTemplate::from_json_slice(template_json.as_bytes()).map_err(|e| {
        format!("invalid .qssm template (must match QssmTemplate + PredicateBlock schema): {e}")
    })?;
    if template.qssm_template_version() != QSSM_TEMPLATE_VERSION {
        return Err(format!(
            "unsupported qssm_template_version (got {}, expected {})",
            template.qssm_template_version(), QSSM_TEMPLATE_VERSION
        ));
    }
    let pretty = serde_json::to_string_pretty(&template).map_err(|e| e.to_string())?;
    std::fs::write(&path, pretty.as_bytes()).map_err(|e| format!("write {path}: {e}"))
}
