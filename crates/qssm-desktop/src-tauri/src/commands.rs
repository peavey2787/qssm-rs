//! Tauri commands for sovereign identity + mesh snapshot controls.

use serde_json::{json, Value};
use std::fs;
use tauri::Manager;

use qssm_he::HarvestConfig;
use bip39::Mnemonic;

/// Enable or pause `qssm-he` hardware harvesting (pulse / proofs skip harvest when off).
#[tauri::command]
pub fn toggle_hardware_harvest(enabled: bool) -> bool {
    qssm_he::set_hardware_harvest_enabled(enabled);
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
    let hb = qssm_he::harvest(&HarvestConfig::default()).map_err(|e| e.to_string())?;
    let entropy_32 = hb.to_seed();
    let mnemonic =
        Mnemonic::from_entropy(&entropy_32).map_err(|e| format!("bip39 from entropy: {e}"))?;
    Ok(json!({
        "mnemonic_24": mnemonic.to_string(),
        "entropy_hex": hex::encode(entropy_32),
        "timestamp_ns": hb.timestamp,
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
    fs::write(&path, serde_json::to_string_pretty(&cur).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(json!({"ok": true, "count": cur.len()}))
}

#[tauri::command]
pub fn repair_state(peer_id: String) -> Result<Value, String> {
    crate::sidecar::request_merkle_repair_for_peer(peer_id)?;
    Ok(json!({"ok": true}))
}
