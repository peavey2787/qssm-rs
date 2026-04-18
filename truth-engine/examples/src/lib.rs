//! Shared helpers for zk-stack examples.

/// Format a 32-byte hash as `<first8>...<last8>`.
pub fn hex_short(bytes: &[u8]) -> String {
    let h = hex::encode(bytes);
    if h.len() >= 16 {
        format!("{}...{}", &h[..8], &h[h.len() - 8..])
    } else {
        h
    }
}
