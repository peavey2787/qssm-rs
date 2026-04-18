//! Wall-clock timestamp for [`crate::Heartbeat`] (nanoseconds since Unix epoch where supported).
//!
//! This is an internal helper, not part of the frozen public surface. Callers access the
//! timestamp through [`crate::Heartbeat::timestamp()`].

/// Nanoseconds since Unix epoch, or milliseconds × 10⁶ when sub-second precision is unavailable.
///
/// Returns `0` if the system clock reports a time before the Unix epoch (practically unreachable
/// on any supported platform).
#[must_use]
pub(crate) fn unix_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let ns = d.as_nanos();
            if ns <= u128::from(u64::MAX) {
                ns as u64
            } else {
                d.as_millis().saturating_mul(1_000_000) as u64
            }
        }
        Err(_) => 0,
    }
}
