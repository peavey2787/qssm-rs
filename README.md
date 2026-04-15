<p align="center">
  <img src="https://github.com/user-attachments/assets/9570f905-ed28-4d42-9095-df68a2504742" width="450">
</p>

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

## ⚡ Core Performance

* **Lattice-LE Verification:** **< 1 ms per proof** (Reference: 0.079 ms on Ryzen 5800X).
* **Security Baseline:** **128-bit Post-Quantum** concrete hardness ($N=256, q=8,380,417$).
* **Architecture:** Post-quantum lattice-based multiset hash with **Recursive Merkle Integration**.
* **Throughput:** Sustained performance optimized for **10-BPS+ BlockDAG environments** (e.g., Kaspa).
* **Proof Payload:** ~2.1 KB (Optimized for p2p wire-protocols and high-frequency sequencing).

## 🛠 Project structure

* [`crates/qssm-le`](crates/qssm-le) — Core lattice linear engine (receipts for the ~0.026 ms claim).
* [`crates/qssm-desktop`](crates/qssm-desktop) — Tauri desktop helper (“Lab” UI).
* [`crates/mssq-batcher`](crates/mssq-batcher) — Mirror-Shift Sovereign Queue sequencer.
* [`crates/qssm-gadget`](crates/qssm-gadget) — Human-readable sugar blocks and predicate logic.

## ⚖️ License and sovereignty

This project is licensed under the **Business Source License 1.1 (BSL-1.1)**. See [`LICENSE`](LICENSE) for the full text.

* **Non-commercial / research use:** 100% free under the license terms.
* **Commercial use:** requires a license (see `LICENSE`).
* **Change date:** April 13, 2029 (then **GPLv3** or later, per `LICENSE`).

*Math is law. Sovereignty is non-negotiable.*

<p align="center">
  <img width="280" alt="miss-q" src="https://github.com/user-attachments/assets/40a9f10f-5968-426d-8eb0-c8666bfe9771" />
</p>