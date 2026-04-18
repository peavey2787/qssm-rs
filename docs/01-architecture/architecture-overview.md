### Documentation map

* [README](../../README.md) — Project home
* **Desktop helper (primary user entry):** [../../desktop/](../../desktop/) — Tauri app: handoff JSON → entropy collection → witness packaging → proof scaffolding
* [QSSM-LE — Engine A](../02-protocol-specs/qssm-le-engine-a.md)
* [QSSM-MS — Engine B](../02-protocol-specs/qssm-ms-engine-b.md)
* [BLAKE3-lattice gadget spec](../02-protocol-specs/blake3-lattice-gadget-spec.md)
* [BLAKE3-lattice gadget — Rust plan](../04-implementation-plans/blake3-lattice-gadget-rust-plan.md)
* [MSSQ — Egalitarian rollup](../02-protocol-specs/l1-l2/mssq.md)

---

# The QSSM Family — Architecture Overview
### The Stateless Universal Truth Engine & The Egalitarian Rollup

---

## 0. The Mission: The Stateless Universal Truth Engine

The primary goal of this repository is not the rollup by itself. The primary goal is the construction of a **Stateless Universal Truth Engine**: a post-quantum proving stack that lets a user prove a meaningful fact without requiring every verifier to replay the user’s history or carry the entire network state.

Historically, decentralized truth has been tied to heavy, stateful infrastructure. A chain stores the past, nodes replay the past, and “truth” becomes something you derive by carrying a large amount of historical baggage. QSSM is designed to break that dependency. The core stack aims to let a prover produce a succinct statement about arithmetic, magnitude, or membership, and let an observer verify that statement quickly from compact artifacts alone.

This repo therefore contains **two projects with a one-way dependency**:

1. **The Truth Engine (core project):** the recursive proving stack built from **QSSM-LE**, **QSSM-MS**, and the **BLAKE3-lattice gadget**. This is the main star of the show.
2. **The Egalitarian Rollup (downstream project):** **MSSQ**, a sovereign validity rollup that uses the Truth Engine to enforce MEV-zero ordering, proof-gated execution, and finalized BlockDAG anchoring.

The right mental model is simple: **QSSM is the product; MSSQ is one major application of it.**

---

## 1. Two Project Paths

### **Project One — Portable Truth**

The first project is the stateless proof system itself. It is a vertical cryptographic stack for producing portable truth: proofs that can move across applications, devices, and settlement environments without dragging a large state history behind them.

Its job is to answer questions like these:

- Did this arithmetic relation hold?
- Is one value greater than another?
- Is this value a member of a committed set?
- Can one proof system recursively bind the output of another?

### **Project Two — MSSQ as Implementation**

The second project is the rollup that consumes those proofs. MSSQ uses the QSSM stack to build a fairness-oriented execution environment on top of finalized L1 data. It is important, but it is not the root of the architecture. MSSQ depends on QSSM; QSSM does not depend on MSSQ.

---

## 2. The Recursive Proving Stack

The Truth Engine is a three-layer proving stack. This is the heart of the repository.

| Component | Role | Logic |
| --- | --- | --- |
| **QSSM-LE (Engine A)** | The Brain | Lyubashevsky-style lattice NIZK for general arithmetic and structured relations |
| **QSSM-MS (Engine B)** | The Scalpel | Hash-native Mirror-Shift predicates for comparisons and compact decision proofs |
| **BLAKE3-lattice gadget** | The Bridge | Recursive integration layer that binds Engine B style hash witnesses inside Engine A style lattice constraints |

Together, these three layers create the repo’s core promise: a prover can carry a compact proof artifact instead of a stateful execution history, and a verifier can check it without replaying an entire chain.

---

## 3. Engine A: QSSM-LE (The Lattice Engine)

QSSM-LE is the post-quantum arithmetic foundation of the stack. When the statement is general, multi-step, or structurally rich, LE is the engine that carries it.

It operates over a power-of-two cyclotomic ring \(R_q = \mathbb{Z}_q[X]/(X^{256} + 1)\) and uses a Lyubashevsky-style Fiat-Shamir protocol with module-lattice commitments. Proofs publish a masking commitment \(t\) and response \(z\), with rejection sampling enforcing witness hiding and a verifier norm bound \(\|z\|_\infty \le \gamma\).

### **Why it exists**

QSSM-LE is the stack’s general-purpose proving layer. It is where arithmetic statements, structured commitments, and recursive compositions can live without falling back to classical SNARK assumptions.

### **Why it matters**

- **Post-quantum security:** built on lattice assumptions rather than fragile elliptic-curve machinery
- **Witness hiding:** rejection sampling is part of the design, not an afterthought
- **Fast verification target:** optimized NTT paths are intended to keep verification in the sub-millisecond class on commodity hardware
- **Context binding:** transcripts include a `rollup_context_digest` when used in anchored environments, preventing replay across incompatible finalized views

### **What to use it for**

Use LE when the statement is richer than a simple comparison and needs arithmetic structure, recursive composition, or a lattice-native commitment layer.

---

## 4. Engine B: QSSM-MS (The Mirror-Shift Engine)

Not every truth problem deserves a full lattice proof. Many important facts are simple comparisons:

- Is \(v_A > v_B\)?
- Is a balance at least a threshold?
- Is an age or score above a cutoff?

QSSM-MS exists for this class of problem. It is the stack’s compact, hash-native proving layer: a symmetric logic eraser for comparison-style predicates where a heavy arithmetic system would be unnecessary overhead.

### **Core idea**

QSSM-MS treats values as positions on a modular circle and applies a ledger-bound rotation. The proof then demonstrates the intended relation through a compact hash witness and Merkle path structure instead of a large circuit or polynomial argument.

### **Why it matters**

- **Small proof body:** about 291 bytes, excluding the 32-byte Merkle root
- **Hash-native construction:** centered on BLAKE3 rather than algebraic proving circuits
- **Post-quantum posture:** resistant to the elliptic-curve failure mode that breaks classical SNARK ecosystems
- **Practical specialization:** ideal when the fact being proven is mostly ordering, threshold, or comparison logic

In the stack model, MS is not a competitor to LE. It is a specialized lower-cost engine that complements LE.

---

## 5. The Recursive Bridge: The BLAKE3-Lattice Gadget

The gadget is the connective tissue that turns two separate proving styles into one stack.

Its purpose is to let Engine A consume evidence produced in the style of Engine B. Informally, the recursive statement is:

> "I have a lattice proof that certifies the existence of a valid hash-native witness."

That bridge is what turns QSSM from a pair of useful engines into a stateless universal truth stack. The gadget binds compact hash-side facts into lattice-side constraints so the final artifact can carry both kinds of truth at once.

### **Why this is the secret sauce**

- It enables recursive composition across proof styles.
- It lets compact comparison proofs participate in a stronger arithmetic envelope.
- It supports a stateless packaging model where Merkle root, context digest, and user proof material can be collapsed into a single portable verification story.

This bridge is what makes the phrase **Universal Truth Engine** meaningful instead of marketing language.

---

## 6. MSSQ: The Egalitarian Rollup Built on QSSM

MSSQ is the second project in the repo and the first major implementation of the Truth Engine. It is a sovereign validity rollup that uses the QSSM stack to solve sequencing and settlement problems on top of a BlockDAG anchor.

Its purpose is not to redefine the architecture around the rollup. Its purpose is to demonstrate how the core proving stack can be applied to a concrete system where fairness and verifiable execution matter.

### **What MSSQ uses from the core stack**

- **QSSM-MS** for compact predicate proofs where comparison logic is enough
- **QSSM-LE** for arithmetic and structured proof composition
- **Shared `RollupContext` binding** so proofs, leader messages, and batch semantics attach to the same finalized L1 view

### **What MSSQ adds on top**

- **MEV-zero sequencing:** leaders do not choose arbitrary transaction order; they sort by hash-lexicographical order
- **Egalitarian leader selection:** a **Seed\(_k\)** lottery gives registered nodes a fair slot race
- **Finalized anchoring:** context is derived from finalized L1 limbs, not merely a volatile tip
- **Proof-gated execution:** state transitions are applied only when the required proof material verifies

In short, MSSQ is the first sovereign rollup implementation of the Truth Engine, not the definition of the Truth Engine itself.

---

## 7. User Entry: QSSM Desktop and Handoff Flow

For operators and integrators, the main human-facing entry point is the Tauri-based desktop helper in [../../desktop/](../../desktop/).

The desktop app exists to make the stack usable. It takes a handoff JSON, gathers entropy inputs, packages witness material, and helps scaffold the proof flow between the underlying engines. In that sense, it is the operator console for both projects: the core truth stack and the rollup workflow that consumes it.

### **What the desktop helper manages**

- handoff JSON ingestion
- entropy collection and fallback handling
- witness packaging
- proof scaffolding for LE-centric flows
- operator visibility into sync state, randomness source, and prover latency

**Run (from repo):** `cd desktop && npm install && npm run build && cargo tauri dev`

---

## Summary: Running Code Over Confused Framing

The QSSM family should be read in this order:

1. **First:** the stateless universal truth stack
2. **Second:** the rollup that uses it

If you need portable, post-quantum, stateless proofs for arithmetic, comparisons, or recursive composition, the primary architecture is **QSSM-LE + QSSM-MS + the BLAKE3-lattice gadget**.

If you need a concrete sovereign system that uses that stack for fair ordering and anchored execution, that system is **MSSQ**.

The repo therefore represents **Applied Epistemic Engineering through running code**: build the truth engine first, then build systems that consume it.

---

## References & Further Reading

- Ducas, L. et al. (2018). *CRYSTALS-Dilithium*.
- O'Connor, J. et al. (2021). *BLAKE3: One Function, Fast Everywhere*.
- Beeren, Y. et al. (2024). *BlockDAG Architectures and the Future of Proof-of-Work*.