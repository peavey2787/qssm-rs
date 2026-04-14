//! Privacy-first geo: public IP via HTTPS, lat/lon from a **local** MaxMind GeoLite2 `.mmdb` when present.
//! Coordinates are jittered (~0.5°) before leaving the Rust side.

use std::path::PathBuf;

use maxminddb::geoip2;
use rand::Rng;
use serde::Serialize;

/// Jitter amplitude in degrees (city/region granularity, not front-door precise).
const FUZZ_DEG: f64 = 0.5;

#[derive(Debug, Clone, Serialize)]
pub struct GeoFix {
    pub public_ip: Option<String>,
    /// Fuzzed WGS84; omit when DB / lookup unavailable.
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub source: &'static str,
}

/// Resolve public IPv4/IPv6 (HTTPS). Does not send coordinates to third parties.
pub fn fetch_public_ip() -> Result<String, String> {
    let v: serde_json::Value = ureq::get("https://api.ipify.org?format=json")
        .call()
        .map_err(|e| format!("ipify: {e}"))?
        .into_json()
        .map_err(|e| format!("ipify json: {e}"))?;
    v.get("ip")
        .and_then(|x| x.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "ipify: missing ip field".to_string())
}

fn geolite_candidates(bundle_mmdbs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("QSSM_GEOIP_MMDB") {
        out.push(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("QSSM_GEOLITE_MMDB") {
        out.push(PathBuf::from(p));
    }
    for p in bundle_mmdbs {
        out.push(p);
    }
    out.push(PathBuf::from("dbip-city-lite.mmdb"));
    out.push(PathBuf::from("GeoLite2-City.mmdb"));
    out
}

/// Best-effort lookup. If no `.mmdb` is found, returns `GeoFix` with IP only.
///
/// `bundle_mmdbs`: candidate paths from Tauri resource dir and local overrides.
pub fn resolve_geo(bundle_mmdbs: Vec<PathBuf>) -> GeoFix {
    let ip = fetch_public_ip().ok();
    let Some(ref ip_s) = ip else {
        return GeoFix {
            public_ip: None,
            latitude: None,
            longitude: None,
            source: "ipify_failed",
        };
    };

    let ip_addr: std::net::IpAddr = match ip_s.parse() {
        Ok(a) => a,
        Err(_) => {
            return GeoFix {
                public_ip: ip,
                latitude: None,
                longitude: None,
                source: "ip_parse_failed",
            };
        }
    };

    for path in geolite_candidates(bundle_mmdbs) {
        if !path.is_file() {
            continue;
        }
        let reader = match maxminddb::Reader::open_readfile(&path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Ok(city) = reader.lookup::<geoip2::City>(ip_addr) {
            let lat = city.location.as_ref().and_then(|l| l.latitude);
            let lon = city.location.as_ref().and_then(|l| l.longitude);
            if let (Some(lat), Some(lon)) = (lat, lon) {
                let mut rng = rand::thread_rng();
                let dlat = rng.gen_range(-FUZZ_DEG..FUZZ_DEG);
                let dlon = rng.gen_range(-FUZZ_DEG..FUZZ_DEG);
                return GeoFix {
                    public_ip: ip,
                    latitude: Some((lat + dlat).clamp(-90.0, 90.0)),
                    longitude: Some((lon + dlon).clamp(-180.0, 180.0)),
                    source: "local_mmdb",
                };
            }
        }
    }

    GeoFix {
        public_ip: ip,
        latitude: None,
        longitude: None,
        source: "mmdb_missing_or_no_coords",
    }
}
