# qssm-core

`qssm-core` is the Rust and WASM-facing entry point for the QSSM truth engine.

It exposes five functions:

- `compile` builds an opaque blueprint byte array from a built-in template ID or raw template JSON.
- `commit` binds arbitrary secret bytes to a 32-byte salt.
- `prove` creates a proof byte array that a JSON claim satisfies the compiled blueprint.
- `verify` checks a proof byte array against a blueprint.
- `open` recomputes the commitment for debugging or envelope matching.

The main model is simple: compile once, then pass opaque byte arrays between commit, prove, and verify.

## Full lifecycle example

```rust
use qssm_core::{commit, compile, open, prove, verify};

fn main() -> Result<(), String> {
    // 1. Compile a built-in template into an opaque blueprint byte array.
    let blueprint: Vec<u8> = compile("age-gate-21")?;

    // 2. Prepare the claim bytes and a caller-chosen 32-byte salt.
    let claim_bytes = br#"{"claim":{"age_years":25}}"#;
    let salt = [7u8; 32];

    // 3. Optionally commit the same byte array you intend to prove.
    let commitment: Vec<u8> = commit(claim_bytes, &salt);

    // 4. Produce a proof that the claim satisfies the blueprint.
    let proof: Vec<u8> = prove(claim_bytes, &salt, &blueprint)?;

    // 5. Verify the proof against the blueprint.
    assert!(verify(&proof, &blueprint));

    // 6. Optional debugging step: recompute the commitment locally.
    let reopened_commitment: Vec<u8> = open(claim_bytes, &salt);
    assert_eq!(commitment, reopened_commitment);

    Ok(())
}
```

## Notes

- `compile` returns an opaque blueprint byte array. Treat it as transport data, not a stable public format.
- `prove` expects the secret bytes to be valid JSON claim data.
- `verify` returns `false` on invalid, tampered, or mismatched proof data.
- `open` is optional and mainly useful for debugging or commitment matching.

## WASM output

This crate also builds as `cdylib` and is used as the source for the generated WASM package under `pkg/`.
