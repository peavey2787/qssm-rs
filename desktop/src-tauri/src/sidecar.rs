//! Background mesh sidecar â€” STUBBED.
//!
//! The `p2p-net` crate has been removed from the workspace.  This module
//! preserves the public API surface so the rest of the desktop app compiles,
//! but all networking functionality is disabled until the desktop refactor.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde_json::{json, Value};
use tauri::{AppHandle, Manager};

static NETWORK_ONLINE: AtomicBool = AtomicBool::new(false);
static CURRENT_NETWORK_ID: AtomicU32 = AtomicU32::new(1);

const NETWORK_PROFILE_FILE: &str = "network_profile.json";

#[must_use]
pub fn network_online() -> bool {
    NETWORK_ONLINE.load(Ordering::SeqCst)
}

#[must_use]
pub fn current_network_id() -> u32 {
    CURRENT_NETWORK_ID.load(Ordering::SeqCst)
}

#[must_use]
pub fn network_label_for_id(network_id: u32) -> String {
    if network_id == 0 {
        "MAINNET".to_string()
    } else {
        format!("TESTNET-{network_id}")
    }
}

pub fn set_active_identity(_identity_id: String) {}

pub fn load_network_id(app: &AppHandle) -> Option<u32> {
    let path = app.path().app_data_dir().ok()?.join(NETWORK_PROFILE_FILE);
    let raw = fs::read_to_string(path).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    v.get("network_id")
        .and_then(|x| x.as_u64())
        .map(|n| n as u32)
}

pub fn request_network_switch(_network_id: u32) -> Result<(), String> {
    Err("mesh sidecar disabled (p2p-net removed)".into())
}

pub fn spawn_command_center(_app: &AppHandle, _bundle_mmdbs: Vec<PathBuf>) {
    // Stubbed â€” no p2p_net available
}

pub fn retry_sidecar(_app: &AppHandle, _bundle_mmdbs: Vec<PathBuf>) -> Result<(), String> {
    Err("mesh sidecar disabled (p2p-net removed)".into())
}

pub fn request_merkle_repair_for_peer(_peer_id: String) -> Result<(), String> {
    Err("mesh sidecar disabled (p2p-net removed)".into())
}

pub fn mmdb_candidates(app: &AppHandle) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = app
        .path()
        .resolve("dbip-city-lite.mmdb", tauri::path::BaseDirectory::Resource)
    {
        out.push(p);
    }
    if let Ok(p) = app
        .path()
        .resolve("GeoLite2-City.mmdb", tauri::path::BaseDirectory::Resource)
    {
        out.push(p);
    }
    if let Ok(res_dir) = app.path().resource_dir() {
        out.push(res_dir.join("dbip-city-lite.mmdb"));
        out.push(res_dir.join("resources").join("dbip-city-lite.mmdb"));
        out.push(res_dir.join("GeoLite2-City.mmdb"));
        out.push(res_dir.join("resources").join("GeoLite2-City.mmdb"));
    }
    out
}

pub fn ensure_local_backup(app: &AppHandle) {
    if let Ok(dir) = app.path().app_data_dir() {
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("my_merit_proof.json");
        if file.exists() {
            return;
        }
        let nid = load_network_id(app).unwrap_or(1);
        let label = network_label_for_id(nid);
        let bootstrap = json!({
            "kind": "local_merkle_branch_backup",
            "network": label,
            "smt_root_hex": hex::encode([0u8; 32]),
            "branch_hash_hex": hex::encode([0u8; 32]),
            "note": "First-run local backup to avoid lockout before hiring provider."
        });
        if let Ok(s) = serde_json::to_string_pretty(&bootstrap) {
            let _ = fs::write(file, s);
        }
    }
}
