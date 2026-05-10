#![no_main]

use libfuzzer_sys::fuzz_target;
use qssm_ms::{
    commit_value_v2, prove_predicate_only_v2, verify_predicate_only_v2, PredicateOnlyStatementV2,
};

/// Minimum: 32 seed + 32 binding_entropy + 32 binding_ctx + 8 value + 8 target + 32 prover
const MIN: usize = 32 + 32 + 32 + 8 + 8 + 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < MIN {
        return;
    }
    let mut o = 0usize;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[o..o + 32]);
    o += 32;
    let mut binding_entropy = [0u8; 32];
    binding_entropy.copy_from_slice(&data[o..o + 32]);
    o += 32;
    let mut binding_ctx = [0u8; 32];
    binding_ctx.copy_from_slice(&data[o..o + 32]);
    o += 32;
    let value = u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    o += 8;
    let target = u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    o += 8;
    let mut prover_seed = [0u8; 32];
    prover_seed.copy_from_slice(&data[o..o + 32]);

    let (commitment, witness) = match commit_value_v2(value, seed, binding_entropy) {
        Ok(x) => x,
        Err(_) => return,
    };
    let ctx_len = (data.len().saturating_sub(o)).min(64);
    let context = data[o..o + ctx_len].to_vec();
    let statement = PredicateOnlyStatementV2::new(
        commitment,
        target,
        binding_entropy,
        binding_ctx,
        context,
    );
    if let Ok(proof) = prove_predicate_only_v2(&statement, &witness, prover_seed) {
        let _ = verify_predicate_only_v2(&statement, &proof);
    }
});
