//! Append-only archive of merkle branch proofs (disk), separate from the swarm loop.

use mssq_batcher::RollupState;

pub(crate) fn archive_branch(state: &RollupState, key: &[u8; 32], encoded_proof: &[u8]) {
    let line = serde_json::json!({
        "key_hex": hex::encode(key),
        "root_hex": hex::encode(state.root()),
        "proof_hex": hex::encode(encoded_proof),
        "pulse_height": state.pulse_height,
    });
    if let Ok(mut p) = std::env::current_dir() {
        p.push("history_archive_merkle.jsonl");
        if let Ok(s) = serde_json::to_string(&line) {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
            {
                let _ = writeln!(f, "{s}");
            }
        }
    }
}
