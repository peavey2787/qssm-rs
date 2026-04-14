### Documentation map

* [README](../README.md) — Project home
* [Architecture overview](./architecture-overview.md)
* [MSSQ — Egalitarian rollup](./mssq-rollup.md)
* **This document** — Workspace crates: roles and dependencies

---

# QSSM workspace — crates overview

This repository is a Cargo **workspace**. Most functionality lives under `crates/`; the workspace root package **`qssm-ref`** ties crates together for demos, tests, and integration. Below, each crate is described by **purpose**, **what it contains**, and **who depends on it**.

---

## `qssm-common`

**Purpose:** Shared types and traits so rollup code, engines, and adapters agree on wire shapes and L1-facing interfaces.

**What it provides**

- L2 types: `L2Transaction`, `Batch`, `SmtRoot`
- Rollup state container: `RollupState` (used with the SMT in `qssm-utils`)
- L1 traits: `L1Anchor` (finality-aware Kaspa view), `L1BatchSink` (batch posting), combined as `SovereignAnchor`
- `MockKaspaAdapter` for tests and local demos
- `rollup_context_from_l1` and related helpers to build a canonical rollup context from an anchor

**For:** Every layer that sequences transactions or talks about “the rollup” without re-embedding domain definitions.

---

## `qssm-utils`

**Purpose:** Cryptographic and domain utilities shared by engines, batcher, and gadgets—no business policy, mostly pure helpers.

**What it provides**

- Domain-separated BLAKE3 hashing and versioned domain tags
- `RollupContext` and `rollup_context_digest` (binding proofs to a finalized L1 view)
- Merkle helpers (`merkle_parent`, `PositionAwareTree`)
- **State Mirror Tree (`StateMirrorTree`)** — the SMT used as the rollup balance / leaf store
- MSSQ seed and leader-score helpers (`mssq_seed_k`, leader attestation message bytes, ML-DSA-derived leader IDs)

**For:** `qssm-common`, `qssm-le`, `qssm-ms`, `mssq-batcher`, `qssm-gadget`, and anything that must hash or tree-commit consistently.

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

**Purpose:** Integration layer between human-facing artifacts (JSON templates, handoffs) and the cryptographic cores: **BLAKE3 gadgetry**, **predicate evaluation**, **sovereign witness** binding, optional **lattice bridge** to `qssm-le`, and **Phase 8 entropy** (anchor leg + local floor + optional NIST beacon).

**What it provides**

- `entropy`: `EntropyAnchor`, `EntropyProvider`, `generate_sovereign_entropy` / `…_from_anchor` (used by flows that need salted, auditable randomness)
- `predicate`: template/predicate evaluation (`PredicateBlock`, `eval_predicate`, …)
- `binding`: `SovereignWitness`, sovereign digest limbs, proof metadata encoding
- BLAKE3 compress / Merkle / R1CS tooling for the gadget roadmap

**For:** Desktop and JSON-driven proving pipelines; keeps wire formats and “lab” workflows out of the minimal engines.

---

## `mssq-batcher`

**Purpose:** **MSSQ rollup clerk**: deterministic transaction ordering, **ML-DSA** leader lottery and attestation verification, and **proof-gated** application of batches to `RollupState` / SMT.

**What it provides**

- Lexicographic sequencing (`sort_lexicographical`)
- `mssq_seed_from_anchor`, `elect_leader`, `LeaderAttestation`, attestation verify helpers
- `apply_batch`: duplicate-tx check, per-tx proof hook (`TxProofVerifier`), then balance / leaf updates per the v1 payload layout documented in code

**For:** Nodes or services that apply MSSQ batches; the actual transaction proof verification is injected via `TxProofVerifier` (implemented outside this crate in a full node / `qssm-ref` integration).

---

## `qssm-kaspa`

**Purpose:** Production-shaped **Kaspa L1 adapter**: implements `L1Anchor` + `L1BatchSink` for a gRPC-backed anchor (default build uses a **stub** with placeholder fields until RPCs are wired).

**What it provides**

- `GrpcKaspaAnchor`, `GrpcBatchSink`
- Optional `kaspa-grpc` feature placeholder for `tonic` client wiring

**For:** Rolling up against a real Kaspa node without duplicating anchor traits in application code.

---

## `qssm-desktop`

**Purpose:** **Tauri** desktop “lab” app: invokes Rust commands to turn **handoff JSON** into sovereign witness material, **QSSM-LE** proofs, template export, and related verification demos—bridging UI and `qssm-gadget` / `qssm-le`.

**What it provides**

- IPC commands (see `crates/qssm-desktop/src-tauri/src/commands.rs`): e.g. `generate_proof_from_handoff_json`, `verify_claim_with_template`, template helpers

**For:** Operators and developers who want a clickable path to the same crypto the engines expose in libraries.

---

## `qssm-ref` (workspace root package)

**Purpose:** **Integration umbrella**: re-exports workspace crates, hosts **millionaires duel** demo logic (`src/millionaires_duel.rs`, `src/verify.rs`), and binaries such as `millionaires_duel` that exercise Engine A/B + MSSQ batcher pieces together.

**For:** Tests, examples, and a single `cargo` package name to depend on when you want “all the pieces” for integration.

---

## Dependency sketch (informal)

```
qssm-utils  ←  qssm-common, qssm-le, qssm-ms, mssq-batcher, qssm-gadget
qssm-common ←  mssq-batcher, qssm-kaspa, qssm-desktop, qssm-ref
qssm-le     ←  qssm-gadget (optional bridge), qssm-desktop, qssm-ref
qssm-ms     ←  qssm-ref (tests / demos)
mssq-batcher←  qssm-ref
qssm-kaspa  ←  qssm-ref
qssm-gadget ←  qssm-desktop
```

---

# Mapping to the Finalized Six-Module Stack (v1.2)

The table below maps **this repository’s crates** to the conceptual stack. Where the stack names a capability that is **spec / docs only** or **not yet coded**, that is called out explicitly.

| Stack module | Role in v1.2 | Maps to this repo | Notes |
|---------------|----------------|-------------------|--------|
| **QSSM-HE (Heart)** | Entropy that salts proofs (“physical breath”) | **`qssm-gadget`** (`entropy` module) is the library implementation; **`qssm-desktop`** Tauri commands *invoke* those flows with handoff JSON / anchors | Entropy logic is **not** isolated as its own crate today; it lives in `qssm-gadget` by design. |
| **QSSM-LE — Engine A** | Lattice proofs for complex anchoring / identity | **`crates/qssm-le`** | Matches. |
| **QSSM-MS — Engine B** | ~291-byte Ghost-Mirror fast path for inequalities | **`crates/qssm-ms`** | Matches. |
| **Epistemic Governor (Module 4)** | DAA, reputation, metabolic rate (inflation / difficulty) | **Not implemented** in **`mssq-batcher`** | Current batcher covers **leader lottery**, **ML-DSA attestations**, **lex ordering**, and **SMT updates**—no DAA/reputation/difficulty policy module appears in code. |
| **UTXO / SMT circulation** | Proof-gated value movement without an interpreter | **`mssq-batcher`** (`apply_batch` + `RollupState`) with SMT from **`qssm-utils`** | Matches the “no interpreter” story; payload layout is fixed in code comments. |
| **libp2p-MSSQ (Nervous System)** | Fast propagation of proofs / rollup data | **No crate** | Described at the architecture / MSSQ doc level only; there is **no** `libp2p` (or other) networking crate in this workspace yet. |

### Would we need new crates?

- **Governor (Module 4):** When you implement DAA/reputation/metabolic policy, you will almost certainly want either a **dedicated crate** (e.g. `qssm-governor` or `mssq-governor`) or a clearly separated module with stable APIs—so rollup nodes can swap policy without forking the batcher’s sequencing core.
- **libp2p-MSSQ:** A **new crate** (e.g. `mssq-network` / `libp2p-mssq`) is the natural home once you add peer propagation, gossip topics, and proof relay—nothing in the current workspace fills that role.
- **QSSM-HE:** A **separate crate is optional**: today entropy is **`qssm-gadget::entropy`**. Splitting **`qssm-he`** out would only be justified if you want a minimal dependency surface (e.g. nodes that harvest entropy but do not pull the full gadget stack).

---

*Last updated with workspace members as of the `Cargo.toml` workspace list (`qssm-common`, `qssm-utils`, `qssm-gadget`, `qssm-le`, `qssm-ms`, `mssq-batcher`, `qssm-kaspa`, `qssm-desktop/src-tauri`, and root `qssm-ref`).*
