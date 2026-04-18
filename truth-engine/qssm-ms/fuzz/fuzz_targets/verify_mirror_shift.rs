#![no_main]

use libfuzzer_sys::fuzz_target;
use qssm_ms::{verify, GhostMirrorProof, Root};

/// Minimum bytes: 32 (root) + 1 (n) + 1 (k) + 1 (bit_at_k) + 32 (salt)
///              + 7*32 (path) + 32 (challenge) + 8 (value) + 8 (target)
///              + 32 (binding_ent) + 4 (purpose_len) + 0 (purpose)
///              + 32 (binding_ctx) = 397
const MIN_SIZE: usize = 32 + 1 + 1 + 1 + 32 + 7 * 32 + 32 + 8 + 8 + 32 + 4 + 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN_SIZE {
        return;
    }
    let mut o = 0usize;

    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&data[o..o + 32]);
    o += 32;
    let root = Root::new(root_bytes);

    let n = data[o];
    o += 1;
    let k = data[o];
    o += 1;
    let bit_at_k = data[o];
    o += 1;

    let mut salt = [0u8; 32];
    salt.copy_from_slice(&data[o..o + 32]);
    o += 32;

    let mut path = Vec::with_capacity(7);
    for _ in 0..7 {
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&data[o..o + 32]);
        o += 32;
        path.push(sibling);
    }

    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&data[o..o + 32]);
    o += 32;

    let proof = match GhostMirrorProof::new(n, k, bit_at_k, salt, path, challenge) {
        Ok(p) => p,
        Err(_) => return,
    };

    let value = u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    o += 8;
    let target = u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    o += 8;

    let mut binding_ent = [0u8; 32];
    binding_ent.copy_from_slice(&data[o..o + 32]);
    o += 32;

    let purpose_len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    let purpose_len = purpose_len.min(64).min(data.len().saturating_sub(o + 32));
    if o + purpose_len + 32 > data.len() {
        return;
    }
    let purpose = &data[o..o + purpose_len];
    o += purpose_len;

    let mut binding_ctx = [0u8; 32];
    binding_ctx.copy_from_slice(&data[o..o + 32]);

    // The verifier must never panic regardless of input.
    let _ = verify(root, &proof, binding_ent, value, target, purpose, &binding_ctx);
});
