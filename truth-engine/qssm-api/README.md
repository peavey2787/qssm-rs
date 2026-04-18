# qssm-api

Stable public SDK for QSSM proof verification, proof transport, and shared
carrier types.

`qssm-api` is the external-facing crate for applications that need to accept,
store, transport, and verify QSSM proofs. It exposes the stable verification
surface, the versioned wire format, and the shared proof/context/error types.

For proving, use `qssm-local-prover`. For a convenience offline verifier that
resolves built-in templates by ID, use `qssm-local-verifier`.

## What You Get

- `verify()` for cross-engine proof verification
- `ProofContext` for deriving the verifying key from a 32-byte seed
- `Proof` as the in-memory proof artifact bundle
- `ProofBundle` as the versioned serde-compatible wire format
- `ZkError` and `WireFormatError` as the stable error surface
- `qssm_templates` re-export for template construction and resolution

## Security Model

- Verification is deterministic.
- The verifier does not trust prover-claimed LE public inputs.
- `verify()` recomputes the truth digest from the MS transcript and binding
  context, then verifies the LE proof against that recomputed public instance.
- `ProofBundle` uses strict parsing with `#[serde(deny_unknown_fields)]` and
  length/count validation for all serialized proof components.

## Public API

Primary exports from `src/lib.rs`:

- `verify(ctx, template, claim, proof, binding_ctx)`
- `ProofContext`
- `Proof`
- `ProofBundle`
- `ZkError`
- `WireFormatError`
- `PROTOCOL_VERSION`
- `qssm_templates`

The public structs and enums that may grow over time are marked
`#[non_exhaustive]` so downstream code should avoid exhaustive matching and
struct literals.

## Quick Start: Verify A Proof

```rust
use qssm_api::{verify, ProofContext};
use qssm_templates::QssmTemplate;
use serde_json::json;

let ctx = ProofContext::new([7u8; 32]);
let template = QssmTemplate::proof_of_age("age-21");
let claim = json!({ "claim": { "age_years": 25 } });
let binding_ctx = [9u8; 32];

// Obtain `proof` from qssm-local-prover or deserialize it from ProofBundle.
// let ok = verify(&ctx, &template, &claim, &proof, binding_ctx)?;
// assert!(ok);
```

## Quick Start: Wire Format Round-Trip

```rust
use qssm_api::ProofBundle;

fn round_trip(bundle: &ProofBundle) {
    let proof = bundle.to_proof().expect("valid bundle");
    let encoded = ProofBundle::from_proof(&proof);
    assert_eq!(encoded.protocol_version, bundle.protocol_version);
}
```

## Typical Integration Pattern

1. Create a `ProofContext` from the shared 32-byte seed.
2. Build or resolve a `QssmTemplate`.
3. Receive a `Proof` directly, or deserialize a `ProofBundle` from JSON.
4. Call `verify()` with the public claim and `binding_ctx`.
5. Treat `ZkError` and `WireFormatError` as typed, stable failure surfaces.

If you need local proving in the same application, keep that in
`qssm-local-prover` and treat `qssm-api` as the shared carrier and verifier
layer.

## Stability Contract

This crate is frozen at `v1.0.0` for institutional use.

- `Proof`, `ProofBundle`, `ZkError`, and `WireFormatError` are part of the
  stable surface.
- `ProofBundle` field names and validation semantics are locked for this wire
  generation.
- Rebinding behavior in `verify()` is locked: verifier recomputes the digest;
  it never trusts a prover-supplied LE public instance.
- Additive evolution may happen through new fields or variants where allowed by
  `#[non_exhaustive]`, but removals or behavioral contract changes require a
  new audit and major version bump.

## What This Crate Does Not Do

- It does not harvest entropy.
- It does not provide proving.
- It does not expose Layer 1/2/3 internals as public API.
- It does not relax verification by trusting prover-supplied digest material.

## Verification

```sh
cargo test -p qssm-api
```

Before changing public behavior, review:

- `FREEZE.md`
- `SECURITY_CHECKLIST.md`

If a change would alter the stable API surface, wire format, or verifier
rebinding semantics, stop and treat it as a new security review item.
