//! Wall-clock timestamp for [`crate::Heartbeat`] (nanoseconds since Unix epoch where supported).

/// Nanoseconds since Unix epoch, or milliseconds × 10⁶ when sub-second precision is unavailable.
#[must_use]
pub fn unix_timestamp_ns() -> u64 {
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
