<p align="center">
  <img src="https://github.com/user-attachments/assets/9570f905-ed28-4d42-9095-df68a2504742" width="450">
</p>

[![License: BSL-1.1](https://img.shields.io/badge/license-BSL--1.1-blue.svg)](LICENSE)
[![Rust 1.78+](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](CONTRIBUTING.md)
[![CI](https://github.com/peavey2787/qssm-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/peavey2787/qssm-rs/actions/workflows/ci.yml)
[![CI: ct-assembly-gate](https://github.com/peavey2787/qssm-rs/actions/workflows/ct-assembly-gate.yml/badge.svg)](https://github.com/peavey2787/qssm-rs/actions/workflows/ct-assembly-gate.yml)

# QSSM: Quantum-Safe Sovereign Multiset

### A stateless lattice-powered truth engine

**QSSM** is a general-purpose, post-quantum, non-interactive, no-trusted-setup, stateless ZK stack centered on the Stateless Universal Truth Engine: a lattice-powered system for producing compact, portable proofs without requiring verifiers to replay history, trust a ledger, or rely on centralized relays.

The goal is not to ship an L2-in-a-box. The goal is to build a cryptographic power tool: a template-like truth machine with a prover-network-less integration surface, mobile-oriented performance targets, and no blockchain silo baked into the core product.

Stateless in this context means verifiers do not replay history, maintain state, or depend on a blockchain ledger.

See [SECURITY.md](SECURITY.md) for disclosure policy and security invariants, and [docs/01-architecture/architecture-overview.md](docs/01-architecture/architecture-overview.md) for the high-level system boundary.

Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)

**Note:**
Some exploratory L1/L2 application notes/specs remain under `docs/02-protocol-specs/l1-l2`, but they are not the product boundary for this repository and are not the main entry point for QSSM.

### Features

- Post‑quantum (lattice‑based)
- Deterministic proving (no randomness)
- Prover‑network‑less (no GPU farms, no prover clusters)
- Stateless verification (no ledger replay, no history)
- Mobile‑class performance targets ( < 10ms )
- Template‑driven truth predicates
- Fully local prover + verifier
- Six‑layer frozen architecture

### Non-goals

- Not a zkVM
- Not a universal circuit system
- Not a blockchain
- Not a prover network
- Not an L2-in-a-box
- Not a sequencer product


### Who is QSSM for?

- Developers integrating local proof/verify flows
- Researchers exploring post‑quantum proving systems
- Teams building trust‑minimized applications without blockchains
- Auditors reviewing deterministic, frozen cryptographic primitives


### Status

All core crates are frozen and stable. APIs are semver‑locked.

### Documentation map

- [Architecture overview](docs/01-architecture/architecture-overview.md)
- [QSSM-LE — Engine A](docs/02-protocol-specs/qssm-le-engine-a.md)
- [QSSM-MS — Engine B](docs/02-protocol-specs/qssm-ms-engine-b.md)
- [BLAKE3-lattice gadget spec](docs/02-protocol-specs/blake3-lattice-gadget-spec.md)
- [Truth Engine layer diagram](docs/01-architecture/diagrams/truth-engine-layers.md)
- [Prove/verify pipeline](docs/01-architecture/diagrams/prove-verify-pipeline.md)
- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## The six-layer truth engine


- **Layer 1 — `qssm-le` (Lattice-Engine A)**: the mathematical foundation.
- **Layer 2 — `qssm-ms` (Mirror-Shift Engine B)**: the integrity engine and truth binder.
- **Layer 3 — `qssm-gadget` (The Recursive Bridge)**: the connective tissue that allows Engine A to verify Engine B.
- **Layer 4 — `qssm-local-prover` + `qssm-entropy`**: consumes entropy and produces a complete proof artifact.
- **Layer 5 — `qssm-local-verifier`**: the logic that returns the final yes or no decision.
- **Layer 6 — `qssm-api`**: how the world talks to the machine.

## Crates and freeze status


- [`truth-engine/qssm-le`](truth-engine/qssm-le) — Layer 1 mathematical foundation — frozen `v1.0.0`.
- [`truth-engine/qssm-ms`](truth-engine/qssm-ms) — Layer 2 integrity engine — frozen `v1.0.0`.
- [`truth-engine/qssm-gadget`](truth-engine/qssm-gadget) — Layer 3 recursive bridge — frozen `v1.1.0`.
- [`truth-engine/qssm-local-prover`](truth-engine/qssm-local-prover) — Layer 4 local prover — frozen `v2.0.0`.
- [`truth-engine/qssm-entropy`](truth-engine/qssm-entropy) — Layer 4 entropy carrier and `to_seed()` path — frozen `v1.0.0`.
- [`truth-engine/qssm-local-verifier`](truth-engine/qssm-local-verifier) — Layer 5 local verifier — frozen `v2.0.0`.
- [`truth-engine/qssm-api`](truth-engine/qssm-api) — Layer 6 public integration surface — frozen `v2.0.0`.
- [`truth-engine/qssm-utils`](truth-engine/qssm-utils) — shared hashing, Merkle, and entropy helpers — frozen `v1.0.0`.
- [`truth-engine/examples`](truth-engine/examples) — example integrations and reference flows.
- [`desktop`](desktop) — GUI for template authoring, lab workflows, and desktop-side operator tooling.
- [`desktop/src-tauri`](desktop/src-tauri) — Rust backend for the desktop application.

See each frozen crate's `README.md`, `FREEZE.md`, and `SECURITY_CHECKLIST.md` for the stable contract and verification record.

## Getting started

### Read first

1. Start with the [architecture overview](docs/01-architecture/architecture-overview.md).
2. Read the protocol specs for [Engine A](docs/02-protocol-specs/qssm-le-engine-a.md), [Engine B](docs/02-protocol-specs/qssm-ms-engine-b.md), and the [BLAKE3-lattice gadget](docs/02-protocol-specs/blake3-lattice-gadget-spec.md).
3. Use the crate READMEs under `truth-engine/` for contributor-facing entry points.

### Where to start

- Start with [`truth-engine/qssm-api`](truth-engine/qssm-api) if you are integrating the Truth Engine into an application, service, SDK, or product.
- Start with [`desktop`](desktop) if you want the GUI workflow for template authoring, lab use, and desktop-side tooling.
- Treat [`truth-engine/qssm-local-prover`](truth-engine/qssm-local-prover) and [`truth-engine/qssm-local-verifier`](truth-engine/qssm-local-verifier) as internal engine layers unless you are auditing internals, fixing a bug, or reviewing a security issue.

### How to Install

```sh
git clone https://github.com/peavey2787/qssm-rs
cargo build --workspace
```

### Verify the workspace

```sh
cargo check --workspace
cargo test -p qssm-api
cargo test -p qssm-entropy
```

### Minimal Example

```rust
use qssm_api::{compile, commit, prove, verify, open};

fn main() {
    // 1. Compile a template into an opaque blueprint (byte array).
    let blueprint = compile("age-gate-21").expect("unknown template");

    // 2. Commit a secret for later reveal.
    let secret = b"my-secret";
    let salt = [1u8; 32];
    let commitment = commit(secret, &salt);

    // 3. Prove a claim against the blueprint.
    let claim = br#"{"claim":{"age_years":25}}"#;
    let proof = prove(claim, &salt, &blueprint).expect("prove failed");

    // 4. Verify the proof.
    assert!(verify(&proof, &blueprint));

    // 5. Reveal — reconstruct the commitment and compare.
    assert_eq!(open(secret, &salt), commitment);
}
```

## License and sovereignty

This project is licensed under the **Business Source License 1.1 (BSL-1.1)**. See [`LICENSE`](LICENSE) for the full text.

* **Non-commercial / research use:** 100% free under the license terms.
* **Commercial use:** requires a license (see `LICENSE`).
* **Change date:** April 13, 2029 (then **GPLv3** or later, per `LICENSE`).

*Math is law. Sovereignty is non-negotiable.*