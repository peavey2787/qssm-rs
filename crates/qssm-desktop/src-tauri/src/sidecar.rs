//! Background `mssq-net` node + snapshot → Tauri `emit` bridge.

use std::path::PathBuf;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use crate::geo::{resolve_geo, GeoFix};

static NETWORK_ONLINE: AtomicBool = AtomicBool::new(false);
static SIDECAR_SPAWNED: AtomicBool = AtomicBool::new(false);
static ACTIVE_IDENTITY: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);
static NODE_HANDLE: std::sync::RwLock<Option<mssq_net::NodeHandle>> = std::sync::RwLock::new(None);

#[must_use]
pub fn network_online() -> bool {
    NETWORK_ONLINE.load(Ordering::SeqCst)
}

pub fn set_active_identity(identity_id: String) {
    if let Ok(mut guard) = ACTIVE_IDENTITY.write() {
        *guard = Some(identity_id);
    }
}

fn active_identity() -> Option<String> {
    ACTIVE_IDENTITY.read().ok().and_then(|g| g.clone())
}

/// Spawn the mesh sidecar once. If startup fails, emits `network-status` with `online: false`.
pub fn spawn_command_center(app: &AppHandle, bundle_mmdbs: Vec<PathBuf>) {
    if SIDECAR_SPAWNED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let handle = app.clone();
    let geo = resolve_geo(bundle_mmdbs);

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("mssq-net-sidecar")
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                NETWORK_ONLINE.store(false, Ordering::SeqCst);
                SIDECAR_SPAWNED.store(false, Ordering::SeqCst);
                let _ = handle.emit(
                    "network-status",
                    json!({ "online": false, "error": format!("tokio runtime: {e}") }),
                );
                return;
            }
        };

        rt.block_on(async move {
            let cfg = mssq_net::NodeConfig {
                network_id: 1,
                ..mssq_net::NodeConfig::default()
            };
            match mssq_net::start_node(cfg).await {
                Ok(node) => {
                    if let Ok(mut guard) = NODE_HANDLE.write() {
                        *guard = Some(node.clone());
                    }
                    NETWORK_ONLINE.store(true, Ordering::SeqCst);
                    let _ = handle.emit(
                        "network-status",
                        json!({ "online": true, "detail": "mssq-net started" }),
                    );

                    let mut ticker = tokio::time::interval(Duration::from_millis(450));
                    let mut last_repair_request = std::time::Instant::now()
                        .checked_sub(Duration::from_secs(30))
                        .unwrap_or_else(std::time::Instant::now);
                    loop {
                        ticker.tick().await;
                        let snap = node.snapshot.lock().await.clone();
                        let mut payload = command_center_payload(&snap, &geo);
                        let proof_verified = local_backup_matches_root(&handle, &snap.smt_root_hex);
                        if let Value::Object(ref mut map) = payload {
                            map.insert("proof_verified".to_string(), json!(proof_verified));
                        }
                        if !proof_verified && last_repair_request.elapsed() >= Duration::from_secs(10) {
                            let _ = node.request_merkle_branch(snap.peer_id.clone());
                            last_repair_request = std::time::Instant::now();
                        }
                        maybe_persist_repair(&handle, &snap);
                        let _ = handle.emit("command-center", payload);
                    }
                }
                Err(e) => {
                    if let Ok(mut guard) = NODE_HANDLE.write() {
                        *guard = None;
                    }
                    NETWORK_ONLINE.store(false, Ordering::SeqCst);
                    SIDECAR_SPAWNED.store(false, Ordering::SeqCst);
                    let _ = handle.emit(
                        "network-status",
                        json!({ "online": false, "error": e.to_string() }),
                    );
                }
            }
        });
    });
}

/// Manual retry after a failed start (does not stop an already-running sidecar).
pub fn retry_sidecar(app: &AppHandle, bundle_mmdbs: Vec<PathBuf>) -> Result<(), String> {
    if NETWORK_ONLINE.load(Ordering::SeqCst) {
        return Err("network already online".into());
    }
    SIDECAR_SPAWNED.store(false, Ordering::SeqCst);
    spawn_command_center(app, bundle_mmdbs);
    Ok(())
}

pub fn request_merkle_repair_for_peer(peer_id: String) -> Result<(), String> {
    let guard = NODE_HANDLE
        .read()
        .map_err(|_| "node handle lock failed".to_string())?;
    let Some(node) = guard.as_ref() else {
        return Err("node not running".to_string());
    };
    node.request_merkle_branch(peer_id)
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

fn command_center_payload(snap: &mssq_net::NodeSnapshot, geo: &GeoFix) -> Value {
    let mut base = mssq_net::snapshot_to_json(snap);
    if let Value::Object(ref mut map) = base {
        map.insert(
            "geo".to_string(),
            serde_json::to_value(geo).unwrap_or(Value::Null),
        );
        map.insert(
            "hardware_harvest_enabled".to_string(),
            json!(qssm_he::hardware_harvest_enabled()),
        );
        map.insert("network_online".to_string(), json!(network_online()));
        map.insert("active_identity".to_string(), json!(active_identity()));
        // Normalized “fever” 0..1 for UI.
        let fever_tmin =
            ((snap.current_t_min_milli.saturating_sub(1000)).max(0) as f64 / 3000.0_f64).clamp(0.0, 1.0);
        let fever_density = if snap.global_density_avg_milli < 800 { 0.45 } else { 0.0 };
        let fever = fever_tmin.max(fever_density);
        map.insert("fever_0_1".to_string(), json!(fever));
    }
    base
}

fn local_backup_matches_root(app: &AppHandle, root_hex: &str) -> bool {
    let Ok(dir) = app.path().app_data_dir() else {
        return false;
    };
    let p = dir.join("my_merit_proof.json");
    let Ok(raw) = fs::read_to_string(p) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<Value>(&raw) else {
        return false;
    };
    v.get("smt_root_hex")
        .and_then(Value::as_str)
        .map(|s| s == root_hex)
        .unwrap_or(false)
}

fn maybe_persist_repair(app: &AppHandle, snap: &mssq_net::NodeSnapshot) {
    let (Some(peer_id), Some(root_hex), Some(proof_hex)) = (
        snap.repair_peer_id.as_ref(),
        snap.repair_root_hex.as_ref(),
        snap.repair_proof_hex.as_ref(),
    ) else {
        return;
    };
    if let Ok(dir) = app.path().app_data_dir() {
        let _ = persist_repair_to_dir(&dir, peer_id, root_hex, proof_hex);
    }
}

fn persist_repair_to_dir(
    dir: &std::path::Path,
    peer_id: &str,
    root_hex: &str,
    proof_hex: &str,
) -> Result<(), String> {
    let root_vec = hex::decode(root_hex).map_err(|e| e.to_string())?;
    if root_vec.len() != 32 {
        return Err("invalid root length".into());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_vec);
    let proof_bytes = hex::decode(proof_hex).map_err(|e| e.to_string())?;
    let proof = qssm_utils::SparseMerkleProof::decode(&proof_bytes).ok_or("invalid proof codec")?;
    if !qssm_utils::StateMirrorTree::verify_proof(root, &proof) {
        return Err("proof does not match root".into());
    }
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let file = dir.join("my_merit_proof.json");
    let payload = json!({
        "kind": "local_merkle_branch_backup",
        "network": "TESTNET-1",
        "peer_id": peer_id,
        "smt_root_hex": root_hex,
        "proof_hex": proof_hex,
    });
    let s = serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?;
    fs::write(file, s).map_err(|e| e.to_string())
}

pub fn ensure_local_backup(app: &AppHandle) {
    if let Ok(dir) = app.path().app_data_dir() {
        let _ = fs::create_dir_all(&dir);
        let file = dir.join("my_merit_proof.json");
        if file.exists() {
            return;
        }
        let bootstrap = json!({
            "kind": "local_merkle_branch_backup",
            "network": "TESTNET-1",
            "smt_root_hex": hex::encode([0u8; 32]),
            "branch_hash_hex": hex::encode([0u8; 32]),
            "note": "First-run local backup to avoid lockout before hiring provider."
        });
        if let Ok(s) = serde_json::to_string_pretty(&bootstrap) {
            let _ = fs::write(file, s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::persist_repair_to_dir;
    use qssm_utils::StateMirrorTree;

    #[test]
    fn liar_branch_with_mismatched_root_does_not_overwrite_backup() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("qssm-sidecar-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let backup = dir.join("my_merit_proof.json");
        std::fs::write(&backup, "{\"sentinel\":true}").expect("seed file");

        let mut smt = StateMirrorTree::new();
        let key = [1u8; 32];
        smt.insert(key, [9u8; 32]);
        let proof = smt.prove(&key).encode();
        let liar_root = hex::encode([7u8; 32]); // intentionally mismatched
        let proof_hex = hex::encode(proof);

        let err = persist_repair_to_dir(&dir, "peer-liar", &liar_root, &proof_hex).expect_err("must fail");
        assert!(err.contains("proof"));
        let after = std::fs::read_to_string(&backup).expect("read backup");
        assert_eq!(after, "{\"sentinel\":true}");
    }
}
