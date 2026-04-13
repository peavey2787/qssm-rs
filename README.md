# QSSM: Quantum-Safe Sovereign Multiset

### Post-quantum sovereignty for BlockDAG sequencing

**QSSM** is a high-performance cryptographic protocol family designed to solve the "Egalitarian Sequencing" problem in high-throughput BlockDAG architectures (like Kaspa). It enables sub-millisecond state commitment and verification without relying on centralized relays or Layer 2 "band-aids."

### Documentation map

* [Architecture overview](docs/architecture-overview.md)
* [MSSQ — Egalitarian rollup](docs/mssq-rollup.md)
* [QSSM-LE — Engine A](docs/qssm-le-engine-a.md)
* [QSSM-MS — Engine B](docs/qssm-ms-engine-b.md)
* [BLAKE3–lattice gadget spec](docs/blake3-lattice-gadget-spec.md)
* [BLAKE3–lattice gadget — Rust plan](docs/blake3-lattice-gadget-rust-plan.md)
* [Kaspa L2 core deployment manifest](docs/l2-kaspa-core-deployment-manifest.md)

## ⚡ Core performance

* **Lattice-LE verification:** ~0.026 ms per proof.
* **Architecture:** Post-quantum lattice-based multiset hash (reducible to SIS).
* **Throughput:** Optimized for 10-BPS+ environments.

## 🛠 Project structure

* [`crates/qssm-le`](crates/qssm-le) — Core lattice linear engine (receipts for the ~0.026 ms claim).
* [`crates/qssm-desktop`](crates/qssm-desktop) — Tauri desktop helper (“Lab” UI).
* [`crates/mssq-batcher`](crates/mssq-batcher) — Mirror-Shift Sovereign Queue sequencer.
* [`crates/qssm-gadget`](crates/qssm-gadget) — Human-readable sugar blocks and predicate logic.

## ⚖️ License and sovereignty

This project is licensed under the **Business Source License 1.1 (BSL-1.1)**. See [`LICENSE`](LICENSE) for the full text.

* **Non-commercial / research use:** 100% free under the license terms.
* **Commercial use:** requires a license for entities with **more than $5,000,000 USD** annual revenue (see `LICENSE`).
* **Change date:** April 13, 2029 (then **GPLv3** or later, per `LICENSE`).

*Math is law. Sovereignty is non-negotiable.*