### Documentation map

* [README](../README.md) — Project home
* [Architecture overview](./architecture-overview.md)
* [MSSQ — Egalitarian rollup](./mssq-rollup.md)
* **This document** — Workspace crates: roles and dependencies

---

# QSSM workspace — crates overview

This repository is a Cargo **workspace**. Most functionality lives under `crates/`; the workspace root package **`qssm-ref`** ties crates together for demos, tests, and integration. Below, each crate is described by **purpose**, **what it contains**, and **who depends on it** (direct `path` dependencies from each crate’s `Cargo.toml`).

---

## `qssm-common`

**Purpose:** Shared types and traits so rollup code, engines, and adapters agree on wire shapes and L1-facing interfaces.

**What it provides**

- L2 types: `L2Transaction`, `Batch`, `SmtRoot`
- `StorageLease` and related rollup-side bookkeeping types
- `RollupState`: in-memory SMT (`StateMirrorTree` from `qssm-utils`), lease map, `pulse_height`, and `recent_roots` (rolling root history for pruning / fraud checks)
- L1 traits: `L1Anchor` (finality-aware Kaspa view), `L1BatchSink` (batch posting), combined as `SovereignAnchor`
- `MockKaspaAdapter` for tests and local demos
- `rollup_context_from_l1` and related helpers to build a canonical rollup context from an anchor

**For:** Every layer that sequences transactions or talks about “the rollup” without re-embedding domain definitions.

---

## `qssm-utils`

**Purpose:** Cryptographic and domain utilities shared by engines, batcher, gadgets, and networking—no business policy, mostly pure helpers.

**What it provides**

- Domain-separated BLAKE3 hashing and versioned domain tags
- `RollupContext` and `rollup_context_digest` (binding proofs to a finalized L1 view)
- Merkle helpers (`merkle_parent`, `PositionAwareTree`)
- **State Mirror Tree (`StateMirrorTree`)** and **`SparseMerkleProof`** (`encode` / `decode`) — the SMT used as the rollup balance / leaf store; proofs are what `mssq-batcher` expects on `L2Transaction::proof`
- MSSQ seed and leader-score helpers (`mssq_seed_k`, leader attestation message bytes, ML-DSA-derived leader IDs, duel leaderboard key)

**For:** `qssm-common`, `qssm-le`, `qssm-ms`, `mssq-batcher`, `qssm-gadget`, `mssq-net`, `qssm-desktop`, and anything that must hash or tree-commit consistently.

---

## `qssm-le` (QSSM-LE — Engine A)

**Purpose:** Post-quantum **lattice** proofs over a cyclotomic ring \(R_q\): MLWE-style commitments and Lyubashevsky-style Fiat–Shamir proofs, with the rollup context digest in the challenge (anti-replay across L1 views).

**What it provides**

- `prove_arithmetic`, `verify_lattice`, `commit_mlwe`, CRS/`VerifyingKey`, ring/NTT parameters (`N`, `Q`, `BETA`, …)

**For:** “Heavy” structured relations where the whitepaper’s Engine A API applies; verification targets fast NTT paths.

---

## `qssm-ms` (QSSM-MS — Engine B)

**Purpose:** **Mirror-Shift** succinct proofs: Ghost-Mirror leaves, ledger-anchored rotation, and compact inequality proofs (the “fast path” for comparisons like \(v_A > v_B\)).

**What it provides**

- `GhostMirrorProof`, tree construction, prove/verify APIs over Merkle openings (see crate docs for normative hashing notes)

**For:** Small proof bodies and comparison-style predicates without full lattice cost.

---

## `qssm-gadget`

**Purpose:** Integration layer between human-facing artifacts (JSON templates, handoffs) and the cryptographic cores: **BLAKE3 gadgetry**, **predicate evaluation**, **sovereign witness** binding, optional **lattice bridge** to `qssm-le` (`lattice-bridge` feature), and **Phase 8 entropy** (anchor leg + local floor + optional NIST beacon).

**What it provides**

- `entropy`: `EntropyAnchor`, `EntropyProvider`, `generate_sovereign_entropy` / `…_from_anchor` (used by flows that need salted, auditable randomness)
- `predicate`: template/predicate evaluation (`PredicateBlock`, `eval_predicate`, …)
- `binding`: `SovereignWitness`, sovereign digest limbs, proof metadata encoding
- BLAKE3 compress / Merkle / R1CS tooling for the gadget roadmap

**For:** JSON-driven proving pipelines and lab workflows; keeps wire formats out of the minimal engines. `qssm-desktop` enables `lattice-bridge` on this crate via `Cargo.toml` (gadget APIs available to the app build).

---

## `qssm-he` (QSSM-HE — hardware heart)

**Purpose:** **Raw hardware-anchored entropy**: OpenEntropy **raw** capture on Unix, optional IMU bytes via [`SensorEntropy`], BLAKE3 **sovereign seed**, heuristic **density** screening (rayon), and Argon2id **PMK** derivation for cold backups.

**What it provides**

- `harvest` / `harvest_with_sensor`, `poll_raw_accelerometer_i16`
- `Heartbeat`, `verify_density`, `to_seed`, `generate_pmk`
- Harvest gate: `set_hardware_harvest_enabled` / `hardware_harvest_enabled` (used by desktop to pause harvesting)
- **Unix:** `openentropy-core` raw capture. **Windows x86_64:** TSC delta harvester (`_rdtsc`, no OS RNG). **Other targets:** [`HeError::UnsupportedEntropyPlatform`].

**For:** `mssq-net` (pulse generation and validation), `qssm-desktop` (mnemonics and identity flows), and any UI-agnostic entropy consumer; complements Phase 8 flows in `qssm-gadget` where anchor/NIST mixing is required.

---

## `qssm-governor`

**Purpose:** Deterministic **metabolic governor**: windowed peer statistics, expanding/defending state, density floors, blacklisting, throttling, and related policy knobs (`GovernorConfig`, `Governor`, `verify_metabolic_gate`, `PeerAction`, …).

**What it provides**

- Pure-Rust policy logic (currently depends on `rust_decimal` only)
- Unit tests under `tests/metabolic_brain.rs`

**For:** **`mssq-net`** integrates this crate for heartbeat / mesh reputation gating. It is **not** the same as consensus DAA inside `mssq-batcher` (the batcher still handles leader lottery + attestations only, not full economic DAA).

---

## `mssq-net`

**Purpose:** Production-oriented **libp2p** swarm runtime for MSSQ: transport composition, mesh behaviours, pulse gossip with `qssm-he` density checks, and metabolic policy via `qssm-governor`.

**What it provides**

- Tokio swarm bootstrap and runtime loop (`NodeConfig`, `start_node`, `NodeHandle`, `NodeSnapshot`, `snapshot_to_json`)
- Transport stack: QUIC, TCP + Noise + Yamux, DNS, WebSocket, relay client (see `crates/mssq-net/src/transport.rs`); `TransportPlan` also records browser-oriented webrtc-direct / webtransport listen targets for operator visibility where configured
- `NetworkBehaviour` composition: Gossipsub, Kademlia, mDNS, AutoNAT, DCUtR, Relay client, Identify, Ping
- Heartbeat topic (`heartbeat_topic`, `HeartbeatEnvelope`), inbound density validation, reputation module
- Optional **`dashboard`** feature: `examples/mssq_node.rs` ratatui dashboard (`cargo run --example mssq_node --features dashboard`)

**Dependencies (workspace):** `qssm-he`, `qssm-governor`, `qssm-utils`, `qssm-common`, `mssq-batcher` (rollup types / batch application paths where the node touches state proofs).

**For:** Operators running a live MSSQ networking node; desktop spawns this stack as a background sidecar.

---

## `mssq-batcher`

**Purpose:** **MSSQ rollup clerk**: deterministic transaction ordering, **ML-DSA** leader lottery and attestation verification, and **proof-gated** application of batches to `RollupState` / SMT.

**What it provides**

- Lexicographic sequencing (`sort_lexicographical`)
- `mssq_seed_from_anchor`, `mssq_seed_from_anchor_and_dag_tips`, `elect_leader`, `LeaderAttestation`, attestation verify helpers
- `apply_batch`: duplicate `tx.id` check, injected `TxProofVerifier`, **`SparseMerkleProof` verification on `tx.proof`** against the current SMT root (membership or non-membership as appropriate), then `apply_tx_transition` (balance / leaf updates per payload layout, including storage-lease opcodes `0x10`–`0x12` where used)
- `prune_state` for `recent_roots` retention
- Causal DAG / pulse helpers: `CausalDag`, `EntropyPulse`, `lattice_anchor_seed_with_tips`
- Merit maturation: `merit_maturation`, `MeritState`, `MeritTier`

**For:** Nodes or services that apply MSSQ batches. Application-specific proof bytes (e.g. lattice bundles) belong in **`payload`** (or another field agreed with your verifier); **`proof`** is reserved for the canonical SMT opening (see `qssm-ref` millionaires integration).

---

## `qssm-kaspa`

**Purpose:** Production-shaped **Kaspa L1 adapter**: implements `L1Anchor` + `L1BatchSink` for a gRPC-backed anchor (default build uses a **stub** with placeholder fields until RPCs are wired).

**What it provides**

- `GrpcKaspaAnchor`, `GrpcBatchSink`
- Optional `kaspa-grpc` feature placeholder for `tonic` client wiring

**For:** Rolling up against a real Kaspa node without duplicating anchor traits in application code.

---

## `qssm-desktop`

**Purpose:** **Tauri** desktop app (“Sovereign Command Center”): encrypted **identities** (BIP39 mnemonics from `qssm-he`), **libp2p** `PeerId` derivation, optional **MaxMind** geo hints, and a background **`mssq-net`** sidecar that publishes mesh snapshots to the web UI.

**What it provides**

- Rust crate `qssm_desktop_lib` under `crates/qssm-desktop/src-tauri/`
- IPC commands in `commands.rs`: hardware harvest toggle, sidecar retry, mnemonic generation/validation, identity CRUD, storage hire/list, `repair_state`
- `sidecar.rs`: Tokio `mssq_net::start_node`, mesh snapshot → UI events, geo + governor telemetry fields, and guarded persistence of `my_merit_proof.json` (SMT root / repair proofs verified with `qssm_utils::SparseMerkleProof` before overwrite)
- Frontend: `crates/qssm-desktop/src/` (React)

**Dependencies (workspace, selected):** `mssq-net`, `qssm-he`, `qssm-gadget` (with `lattice-bridge`), `qssm-common`, `qssm-le`, `qssm-utils`, `libp2p` (identity types), plus Tauri, crypto, and GeoIP crates per `Cargo.toml`.

**For:** Operators who want a packaged UI over the same networking and entropy stack the libraries expose.

---

## `qssm-ref` (workspace root package)

**Purpose:** **Integration umbrella**: re-exports workspace crates, hosts **millionaires duel** demo logic (`src/millionaires_duel.rs`, `src/verify.rs`), and binaries such as `millionaires_duel` that exercise Engine A/B + MSSQ batcher pieces together.

**Integration note:** The batcher requires `L2Transaction::proof` to be an encoded **`SparseMerkleProof`** for `tx.id` under the current state root. The duel demo places the lattice/attestation **wire** after a fixed prefix in **`payload`** (`duel_settlement_payload` / `MILLIONAIRES_WIRE_PAYLOAD_OFFSET`) and uses `MillionairesDuelVerifier` to decode that suffix—so `tx.proof` stays free for the SMT path.

**For:** Tests, examples, and a single `cargo` package name to depend on when you want “all the pieces” for integration.

---

## Dependency sketch (informal)

```
qssm-utils   ←  qssm-common, qssm-le, qssm-ms, mssq-batcher, qssm-gadget, mssq-net, qssm-desktop, qssm-ref
qssm-common  ←  mssq-batcher, qssm-kaspa, mssq-net, qssm-desktop, qssm-ref
qssm-le      ←  qssm-gadget (optional lattice-bridge), qssm-desktop, qssm-ref
qssm-ms      ←  qssm-gadget (dev), qssm-ref (tests / demos)
qssm-gadget  ←  qssm-desktop
qssm-he      ←  mssq-net, qssm-desktop
qssm-governor←  mssq-net
mssq-batcher ←  qssm-ref, mssq-net
mssq-net     ←  qssm-desktop (sidecar)
qssm-kaspa   ←  qssm-ref
```

---

# Mapping to the Finalized Six-Module Stack (v1.2)

The table below maps **this repository’s crates** to the conceptual stack. Where the stack names a capability that is **spec / docs only** or **not yet coded**, that is called out explicitly.

| Stack module | Role in v1.2 | Maps to this repo | Notes |
|---------------|----------------|-------------------|-------|
| **QSSM-HE (Heart)** | Entropy that salts proofs (“physical breath”) | **`crates/qssm-he`** (raw harvest + PMK); **`qssm-gadget`** Phase 8 `entropy` for anchor + NIST-style flows; **`qssm-desktop`** and **`mssq-net`** call `qssm-he` directly | Two layers: gadget entropy for handoff/beacon wiring; `qssm-he` for hardware observatory + density + PMK. |
| **QSSM-LE — Engine A** | Lattice proofs for complex anchoring / identity | **`crates/qssm-le`** | Matches. |
| **QSSM-MS — Engine B** | ~291-byte Ghost-Mirror fast path for inequalities | **`crates/qssm-ms`** | Matches. |
| **Epistemic Governor (Module 4)** | DAA, reputation, metabolic rate (inflation / difficulty) | **`crates/qssm-governor`** (policy core) + **`mssq-net`** (integration) | Implements metabolic / peer-window policy used by the swarm. **`mssq-batcher`** still does **not** embed consensus DAA—it covers leader lottery, ML-DSA attestations, lex ordering, SMT + lease transitions, merit hooks, and causal-DAG-related seeds. |
| **UTXO / SMT circulation** | Proof-gated value movement without an interpreter | **`mssq-batcher`** (`apply_batch` + `RollupState`) with SMT from **`qssm-utils`** | `tx.proof` is the canonical sparse Merkle opening; payload layout and lease opcodes are defined in batcher code. |
| **libp2p-MSSQ (Nervous System)** | Fast propagation of proofs / rollup data | **`crates/mssq-net`** | libp2p-based swarm as described above. |

### Extensions beyond the original “would we need new crates?” list

- **Governor (Module 4):** Implemented as **`qssm-governor`**, consumed from **`mssq-net`**. Economic DAA *inside the batcher* remains a separate future if you want it colocated with sequencing.
- **libp2p-MSSQ:** Implemented as **`mssq-net`**.
- **QSSM-HE:** Use **`qssm-gadget::entropy`** when you need Phase 8 anchor + NIST beacon mixing; use **`qssm-he`** for raw hardware paths, pulses, and desktop mnemonics.

---

*Last updated to match workspace `Cargo.toml` members: `qssm-common`, `qssm-utils`, `qssm-gadget`, `qssm-le`, `qssm-ms`, `mssq-batcher`, `qssm-kaspa`, `qssm-he`, `qssm-governor`, `mssq-net`, `qssm-desktop/src-tauri`, and root `qssm-ref`.*
