# QSSM Security Policy

## Responsible Disclosure

If you discover a security vulnerability in QSSM, **do not open a public issue.**

Please report vulnerabilities privately:

1. **GitHub Security Advisories:** Use the "Report a vulnerability" button on the repository's Security tab if available.
2. **Encryption:** If you need to share sensitive material, request a PGP key from the maintainer before sending.

We will acknowledge receipt within 72 hours and aim to provide a fix or mitigation plan within 30 days.

### What to include in a report

- Description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof-of-concept.
- Affected crate(s) and version(s).
- Any suggested mitigations.

## No Production Secrets in Repository

This repository **must never contain**:

- Private keys, seeds, or key material.
- Production entropy sources or harvested entropy blobs.
- API tokens, passwords, or credentials.
- Real user data, PII, or claim payloads.

All test seeds, entropy values, and binding contexts in the codebase are **deterministic test fixtures** derived from BLAKE3 hashes of public labels (e.g. `blake3_hash(b"QSSM-SDK-TEST-SEED")`). They carry no security value.

If you discover any production secret committed to this repository, report it immediately via the responsible disclosure process above.

## Cryptographic Assumptions

QSSM's security relies on the following hardness assumptions:

| Assumption | Component | Parameters |
|---|---|---|
| Module-LWE (MLWE) | QSSM-LE (Engine A) | $N = 256$, $q = 8{,}380{,}417$, $\beta = 8$, module rank $k = 1$ |
| BLAKE3 collision resistance | QSSM-MS (Engine B), gadget, key schedule | 256-bit output |
| Merkle tree binding | QSSM-MS commitment scheme | BLAKE3-based, 128-leaf binary tree |

All parameters target **128-bit post-quantum security** against known lattice attacks (BKZ 2.0, primal uSVP, dual attack).

## Deterministic Build Requirements

QSSM proofs are **deterministic**: identical inputs must produce identical outputs. This is a security invariant, not a convenience feature.

### Why determinism matters

- **Auditability:** third parties can reproduce a proof from the same inputs and verify it matches.
- **No hidden randomness:** the SDK never generates internal entropy — all secrets derive from caller-provided `entropy_seed + binding_ctx` via domain-separated BLAKE3.
- **Replay protection:** proofs are bound to a specific `binding_ctx` (anchor hash, session ID, etc.).

### Domain separation constants (locked)

| Constant | Purpose |
|---|---|
| `DOMAIN_SDK_MS_SEED` | MS commitment salt derivation |
| `DOMAIN_SDK_LE_WITNESS` | LE short-vector witness derivation |
| `DOMAIN_SDK_LE_MASK` | LE Lyubashevsky masking seed |
| `DOMAIN_EXTERNAL_ENTROPY` | External entropy derivation |
| `MS_CONTEXT_TAG` (`b"qssm-sdk-v1"`) | MS prove/verify context binding |

These are frozen and must not change without a major version bump across the entire stack.

## Reproducible Build Instructions

### Prerequisites

- Rust 1.78+ (install via [rustup](https://rustup.rs/))
- No C/C++ dependencies — pure Rust, `#![forbid(unsafe_code)]` in all truth-engine crates

### Build from source

```bash
git clone <repository-url>
cd qssm-rs
cargo build --workspace --release
```

### Verify tests

```bash
cargo test --workspace
```

### Verify determinism

The proof pipeline is deterministic. You can verify this by running the same prove call twice and comparing wire-format output:

```bash
cargo run -p zk-examples --bin simple_proof
cargo run -p zk-examples --bin simple_proof
# Both runs produce identical output for the same hardcoded inputs.
```

### Verify constant-time properties

For crates handling secret material (`qssm-le`, `qssm-ms`), constant-time behavior is enforced via the `subtle` crate. The verification script:

```bash
python scripts/verify_ct_asm.py
```

### Audit trail

Build audit snapshots are stored in `audit/`. Each snapshot records:

- Crate versions at build time
- Dependency tree
- Test results
- Compiler version and target

## Crate Security Invariants

Every truth-engine crate enforces:

| Invariant | Mechanism |
|---|---|
| No unsafe code | `#![forbid(unsafe_code)]` |
| Secret zeroization | `zeroize` crate, `ZeroizeOnDrop` derive |
| Constant-time secret ops | `subtle` crate for comparisons |
| Non-exhaustive public types | `#[non_exhaustive]` on enums and structs |
| Strict wire parsing | `#[serde(deny_unknown_fields)]` on `ProofBundle` |
| No internal randomness | All entropy from caller-provided seeds |

## Frozen Crate Policy

Crates at v1.0.0+ are **frozen for institutional use**. Each frozen crate has:

- `FREEZE.md` — locked API surface, invariants, and verification evidence.
- `SECURITY_CHECKLIST.md` — pre-release review gate with all boxes checked.

Breaking changes to a frozen crate require a major version bump, a new security review, and synchronized updates to all downstream crates.
