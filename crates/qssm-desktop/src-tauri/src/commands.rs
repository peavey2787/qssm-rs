//! Tauri commands: handoff JSON → Phase 8 entropy → [`SovereignWitness`] + QSSM‑LE proof; `.qssm` templates.

use std::time::Instant;

use qssm_common::SmtRoot;
use qssm_gadget::binding::SovereignWitness;
use qssm_gadget::entropy::EntropyAnchor;
use qssm_gadget::entropy::EntropyProvider;
use qssm_gadget::prover_json::sovereign_witness_value;
use qssm_gadget::{QssmTemplate, QSSM_TEMPLATE_VERSION};
use qssm_le::BETA;
use qssm_le::{encode_rq_coeffs_le, prove_arithmetic, PublicInstance, VerifyingKey, Witness};
use qssm_utils::hashing::blake3_hash;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

const L1_HUD: &str = "Connected to Kaspa Node";
const VK_SEED: [u8; 32] = *b"QSSM_DESKTOP_VK_SEED_V1_________";

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum HandoffAnchorJson {
    #[serde(rename = "kaspa")]
    Kaspa {
        parent_block_id_hex: String,
    },
    #[serde(rename = "static_root")]
    StaticRoot {
        root_hex: String,
    },
    #[serde(rename = "timestamp")]
    Timestamp {
        unix_secs: u64,
    },
}

impl HandoffAnchorJson {
    fn to_entropy_anchor(&self) -> Result<EntropyAnchor, String> {
        match self {
            Self::Kaspa {
                parent_block_id_hex,
            } => Ok(EntropyAnchor::KaspaParentBlockHash(hex_to_32(
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
    /// Preferred: explicit entropy anchor (Kaspa, static root, or timestamp).
    #[serde(default)]
    anchor: Option<HandoffAnchorJson>,
    /// Legacy Kaspa limb; used when **`anchor`** is omitted.
    #[serde(default)]
    kaspa_parent_block_id_hex: Option<String>,
    state_root_hex: String,
    rollup_context_digest_hex: String,
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
        let hex = self
            .kaspa_parent_block_id_hex
            .as_ref()
            .ok_or_else(|| "missing entropy anchor: set anchor or kaspa_parent_block_id_hex".to_string())?;
        Ok((
            EntropyAnchor::KaspaParentBlockHash(hex_to_32(hex)?),
            "kaspa",
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
        let w = Witness { r };
        if w.validate().is_ok() {
            return w;
        }
    }
}

fn prove_lattice_demo(
    message_limb: u64,
    rollup_ctx: &[u8; 32],
) -> Result<serde_json::Value, String> {
    let vk = VerifyingKey::from_seed(VK_SEED);
    let public = PublicInstance {
        message: message_limb,
    };
    public.validate().map_err(|e| e.to_string())?;

    let mut rng = rand::thread_rng();
    for _ in 0..24 {
        let witness = random_witness(&mut rng);
        if let Ok((commitment, proof)) = prove_arithmetic(&vk, &public, &witness, rollup_ctx) {
            return Ok(json!({
                "commitment_coeffs_hex": hex::encode(encode_rq_coeffs_le(&commitment.0)),
                "t_coeffs_hex": hex::encode(encode_rq_coeffs_le(&proof.t)),
                "z_coeffs_hex": hex::encode(encode_rq_coeffs_le(&proof.z)),
                "challenge_hex": hex::encode(proof.challenge),
            }));
        }
    }
    Err("lattice prover: rejected too many times (retry)".into())
}

fn run_pipeline(h: HandoffFile) -> Result<serde_json::Value, String> {
    let (entropy_anchor, anchor_kind) = h.resolve_entropy_anchor()?;
    let state_root = hex_to_32(&h.state_root_hex)?;
    let rollup_ctx = hex_to_32(&h.rollup_context_digest_hex)?;
    let challenge = hex_to_32(&h.challenge_hex)?;
    let smt = SmtRoot(state_root);

    let local = match &h.local_entropy_hex {
        Some(s) => hex_to_32(s)?,
        None => blake3_hash(b"QSSM_DESKTOP_DEFAULT_LOCAL_ENTROPY"),
    };

    let t0 = Instant::now();
    let prov = EntropyProvider::default();
    let (sovereign_entropy, nist_included) =
        prov.generate_sovereign_entropy_from_anchor(&entropy_anchor, local);
    let limb_span = t0.elapsed();
    let limb_ms = limb_span.as_secs_f64() * 1000.0;

    let sovereign = SovereignWitness::bind(
        state_root,
        rollup_ctx,
        h.n,
        h.k,
        h.bit_at_k,
        challenge,
        sovereign_entropy,
        nist_included,
    );
    if !sovereign.validate() {
        return Err("SovereignWitness::validate failed".into());
    }

    let sw = sovereign_witness_value(&sovereign);
    let lattice = prove_lattice_demo(sovereign.message_limb, &rollup_ctx)?;

    let qrng = if nist_included { "nist" } else { "fallback" };

    let l1_sync = match anchor_kind {
        "kaspa" => L1_HUD,
        "static_root" => "Generic mode — static root anchor (no L1)",
        "timestamp" => "Generic mode — timestamp anchor (no L1)",
        _ => "Generic verification",
    };

    Ok(json!({
        "l1_sync": l1_sync,
        "entropy_anchor_kind": anchor_kind,
        "qrng_status": qrng,
        "nist_included": nist_included,
        "prover_latency_ms": limb_ms,
        "state_root_commitment": hex::encode(smt.0),
        "sovereign_witness": sw,
        "lattice_proof": lattice,
    }))
}

/// Read handoff JSON from disk, run NIST opportunistic entropy, build [`SovereignWitness`], prove with QSSM‑LE.
#[tauri::command]
pub fn generate_proof_from_file(path: String) -> Result<String, String> {
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    let h: HandoffFile =
        serde_json::from_str(&raw).map_err(|e| format!("parse handoff JSON: {e}"))?;
    let v = run_pipeline(h)?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

/// Same as [`generate_proof_from_file`] but JSON body from the webview (file input / fetch).
#[tauri::command]
pub fn generate_proof_from_handoff_json(json: String) -> Result<String, String> {
    let h: HandoffFile =
        serde_json::from_str(&json).map_err(|e| format!("parse handoff JSON: {e}"))?;
    let v = run_pipeline(h)?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

/// Hex‑encode the desktop demo **`VerifyingKey`** seed (for **`.qssm`** `lattice_vk_seed_hex`).
#[tauri::command]
pub fn lattice_demo_vk_seed_hex() -> String {
    hex::encode(VK_SEED)
}

/// Build the canonical **Proof of age (21+)** template JSON (includes desktop demo VK seed).
#[tauri::command]
pub fn proof_of_age_template_json() -> Result<String, String> {
    let mut t = QssmTemplate::proof_of_age("proof-of-age-21");
    t.lattice_vk_seed_hex = Some(hex::encode(VK_SEED));
    t.notes = Some(
        "Pair with QSSM Helper output: check sovereign_witness.public.message_limb_u30 and lattice_proof against qssm-le verifying key from lattice_vk_seed_hex.".into(),
    );
    serde_json::to_string_pretty(&t).map_err(|e| e.to_string())
}

/// Validate **`claim_json`** public fields against a **`.qssm`** template document (JSON string).
///
/// Tauri IPC: invoke with camelCase keys **`templateJson`** and **`claimJson`**.
#[tauri::command]
pub fn verify_claim_with_template(template_json: String, claim_json: String) -> Result<String, String> {
    let template: QssmTemplate =
        serde_json::from_str(&template_json).map_err(|e| format!("parse template: {e}"))?;
    if template.qssm_template_version != QSSM_TEMPLATE_VERSION {
        return Err(format!(
            "unsupported qssm_template_version (got {}, expected {})",
            template.qssm_template_version,
            QSSM_TEMPLATE_VERSION
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

/// Write UTF‑8 **`.qssm`** JSON to **`path`** (any extension; caller should use **`.qssm`**).
///
/// Parses the document as [`QssmTemplate`] so every **`predicates`** entry matches [`qssm_gadget::PredicateBlock`].
///
/// Tauri IPC: invoke with **`path`** and camelCase **`templateJson`** (maps to **`template_json`**).
#[tauri::command]
pub fn export_qssm_template(path: String, template_json: String) -> Result<(), String> {
    let template = QssmTemplate::from_json_slice(template_json.as_bytes()).map_err(|e| {
        format!("invalid .qssm template (must match QssmTemplate + PredicateBlock schema): {e}")
    })?;
    if template.qssm_template_version != QSSM_TEMPLATE_VERSION {
        return Err(format!(
            "unsupported qssm_template_version (got {}, expected {})",
            template.qssm_template_version,
            QSSM_TEMPLATE_VERSION
        ));
    }
    let pretty = serde_json::to_string_pretty(&template).map_err(|e| e.to_string())?;
    std::fs::write(&path, pretty.as_bytes()).map_err(|e| format!("write {path}: {e}"))
}
