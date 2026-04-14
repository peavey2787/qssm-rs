//! Background `mssq-net` node + snapshot → Tauri `emit` bridge.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use crate::geo::{resolve_geo, GeoFix};

static NETWORK_ONLINE: AtomicBool = AtomicBool::new(false);
static SIDECAR_SPAWNED: AtomicBool = AtomicBool::new(false);
static ACTIVE_IDENTITY: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

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
            let cfg = mssq_net::NodeConfig::default();
            match mssq_net::start_node(cfg).await {
                Ok(node) => {
                    NETWORK_ONLINE.store(true, Ordering::SeqCst);
                    let _ = handle.emit(
                        "network-status",
                        json!({ "online": true, "detail": "mssq-net started" }),
                    );

                    let mut ticker = tokio::time::interval(Duration::from_millis(450));
                    loop {
                        ticker.tick().await;
                        let snap = node.snapshot.lock().await.clone();
                        let payload = command_center_payload(&snap, &geo);
                        let _ = handle.emit("command-center", payload);
                    }
                }
                Err(e) => {
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
