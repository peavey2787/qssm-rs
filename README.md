<p align="center">
  <img src="https://github.com/user-attachments/assets/9570f905-ed28-4d42-9095-df68a2504742" width="450">
</p>

# QSSM: Quantum-Safe Sovereign Multiset

### A stateless lattice-powered truth engine

**QSSM** is a general-purpose, post-quantum, non-interactive, no-trusted-setup, stateless ZK stack centered on the Stateless Universal Truth Engine: a lattice-powered system for producing compact, portable proofs without requiring verifiers to replay history, trust a ledger, or rely on centralized relays.

The goal is not to ship an L2-in-a-box. The goal is to build a cryptographic power tool: a template-like truth machine with a prover-network-less integration surface, mobile-oriented performance targets, and no blockchain silo baked into the core product.

Some exploratory L1/L2 application notes/specs remain under `docs/02-protocol-specs/l1-l2`, but they are not the product boundary for this repository and are not the main entry point for QSSM.

### Documentation map

- [Architecture overview](docs/01-architecture/architecture-overview.md)
- [QSSM-LE — Engine A](docs/02-protocol-specs/qssm-le-engine-a.md)
- [QSSM-MS — Engine B](docs/02-protocol-specs/qssm-ms-engine-b.md)
- [BLAKE3-lattice gadget spec](docs/02-protocol-specs/blake3-lattice-gadget-spec.md)
- [Truth Engine layer diagram](docs/01-architecture/diagrams/truth-engine-layers.md)
- [Prove/verify pipeline](docs/01-architecture/diagrams/prove-verify-pipeline.md)

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
- [`truth-engine/qssm-local-prover`](truth-engine/qssm-local-prover) — Layer 4 local prover — frozen `v1.0.0`.
- [`truth-engine/qssm-entropy`](truth-engine/qssm-entropy) — Layer 4 entropy carrier and `to_seed()` path — frozen `v1.0.0`.
- [`truth-engine/qssm-local-verifier`](truth-engine/qssm-local-verifier) — Layer 5 local verifier — frozen `v1.0.0`.
- [`truth-engine/qssm-api`](truth-engine/qssm-api) — Layer 6 public integration surface — frozen `v1.0.0`.
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

### Verify the workspace

```sh
cargo check --workspace
cargo test -p qssm-api
cargo test -p qssm-entropy
```

### Where to start

- Start with [`truth-engine/qssm-api`](truth-engine/qssm-api) if you are integrating the Truth Engine into an application, service, SDK, or product.
- Start with [`desktop`](desktop) if you want the GUI workflow for template authoring, lab use, and desktop-side tooling.
- Treat [`truth-engine/qssm-local-prover`](truth-engine/qssm-local-prover) and [`truth-engine/qssm-local-verifier`](truth-engine/qssm-local-verifier) as internal engine layers unless you are auditing internals, fixing a bug, or reviewing a security issue.

## License and sovereignty

This project is licensed under the **Business Source License 1.1 (BSL-1.1)**. See [`LICENSE`](LICENSE) for the full text.

* **Non-commercial / research use:** 100% free under the license terms.
* **Commercial use:** requires a license (see `LICENSE`).
* **Change date:** April 13, 2029 (then **GPLv3** or later, per `LICENSE`).

*Math is law. Sovereignty is non-negotiable.*