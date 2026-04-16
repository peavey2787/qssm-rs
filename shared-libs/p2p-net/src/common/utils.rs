//! Small shared helpers (timestamps, etc.) used by `node` and other modules.

/// Current wall-clock time in nanoseconds since UNIX epoch (best-effort).
#[must_use]
pub fn unix_timestamp_ns() -> u64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_nanos() as u64)
        .unwrap_or_default()
}
