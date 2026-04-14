use std::fs;
use std::path::PathBuf;

use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

const CACHE_FILE: &str = ".mssq-net-peer-cache.json";
const MAX_CACHE: usize = 32;

#[derive(Debug, Serialize, Deserialize, Default)]
struct PeerCacheFile {
    addrs: Vec<String>,
}

fn cache_path() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(CACHE_FILE)
}

pub fn load_last_addrs(limit: usize) -> Vec<Multiaddr> {
    let path = cache_path();
    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let parsed: PeerCacheFile = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    parsed
        .addrs
        .into_iter()
        .filter_map(|s| s.parse::<Multiaddr>().ok())
        .take(limit)
        .collect()
}

pub fn record_seen_addr(addr: &Multiaddr) {
    let mut now = load_last_addrs(MAX_CACHE)
        .into_iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>();
    let addr_s = addr.to_string();
    now.retain(|a| a != &addr_s);
    now.insert(0, addr_s);
    now.truncate(MAX_CACHE);
    let payload = PeerCacheFile { addrs: now };
    if let Ok(text) = serde_json::to_string_pretty(&payload) {
        let _ = fs::write(cache_path(), text);
    }
}
