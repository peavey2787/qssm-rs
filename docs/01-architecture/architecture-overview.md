### Documentation map

* [README](../../README.md) — Project home
* **Desktop helper (primary user entry):** [`crates/qssm-desktop/`](../../crates/qssm-desktop/) — Tauri app: handoff JSON → Phase 8 NIST/Kaspa entropy → sovereign witness JSON + QSSM‑LE proof scaffold.
* [MSSQ — Egalitarian rollup](../02-protocol-specs/mssq.md)
* [QSSM-LE — Engine A](../02-protocol-specs/qssm-le-engine-a.md)
* [QSSM-MS — Engine B](../02-protocol-specs/qssm-ms-engine-b.md)
* [BLAKE3–lattice gadget spec](../02-protocol-specs/blake3-lattice-gadget-spec.md)
* [BLAKE3–lattice gadget — Rust plan](../04-implementation-plans/blake3-lattice-gadget-rust-plan.md)
* [Kaspa L2 core deployment manifest](./l2-kaspa-deployment.md)

---

# The QSSM Family — Architecture Overview  
### A Sovereign, MEV‑Zero Framework for Post‑Quantum Logic on BlockDAG

---

## Introduction: The Algebraic Prison

For the last decade, decentralized finance (DeFi) has lived inside an “Algebraic Prison.” To prove that you have enough money for a trade or that you are over the age of 21 without revealing your identity, we have relied on massive, complex mathematical structures called Zero‑Knowledge Succinct Non‑Interactive Arguments of Knowledge (zk‑SNARKs).

While brilliant, SNARKs come with heavy baggage: they require complex “trusted setups,” they rely on fragile algebraic curves that quantum computers will eventually shatter, and they are so computationally “expensive” that they have forced us into a world of centralized sequencers. These sequencers act as the “kings” of the network, reordering your transactions to extract billions in value (Maximum Extractable Value, or MEV).

The QSSM Protocol Family — pronounced “Q‑sum” — is a formal protocol suite designed to delete these diseases. By moving away from universal algebraic circuits and toward Sovereign Native Logic, we have built a system that is post‑quantum secure, MEV‑zero by design, and efficient enough to run on a mobile phone.

---

## User entry point: QSSM Desktop Helper (`qssm-desktop`)

For **operators and integrators**, the default path into the stack is the **Tauri‑based helper** in [`crates/qssm-desktop/`](../../crates/qssm-desktop/): a small desktop shell that loads a **handoff JSON** (Kaspa parent id, state root, rollup context digest, FS challenge fields), runs **Phase 8** opportunistic entropy (**NIST beacon** with timeout + **Kaspa ‖ local** floor), builds a **`SovereignWitness`** (JSON), and runs a **QSSM‑LE** `prove_arithmetic` demo against a fixed demo verifying key. The UI shows **L1 sync** (mock until wired to `qssm-kaspa`), **QRNG / NIST vs fallback**, and **prover latency** for the sovereign limb step.

**Run (from repo):** `cd crates/qssm-desktop && npm install && npm run build && cargo tauri dev` (requires [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) and `cargo install tauri-cli` *or* `npx @tauri-apps/cli@2 dev` from that directory).

---

## 1. The Three‑Layer Stack

The QSSM architecture is not a single “blockchain.” It is a layered sovereign environment that sits on top of existing high‑performance BlockDAGs like Kaspa.

### **Layer 1 — The Anchor**
The Kaspa BlockDAG provides the “Source of Truth.” It provides the entropy (randomness) and the immutable storage needed to anchor our proofs. The rollup **binds challenges and leader messages to a `RollupContext` digest** derived from **finalized** L1 state (via an `L1Anchor` trait), not from volatile tip fields alone, so committed rollup state is not invalidated by ordinary tip reorgs.

### **Layer 2 — The Queue (MSSQ)**
Pronounced “Miss‑Q,” the Mirror‑Shift Sovereign Queue is the egalitarian layer that ensures transactions are ordered fairly, using math instead of bribes.

### **The Engines — QSSM‑A & QSSM‑B**
These are the proving systems. They allow users to prove facts about their data without revealing the data itself.

---

## 2. Engine A: QSSM‑LE (The Lattice Engine)

When you need to perform complex “heavy lifting”—such as a multi‑step financial contract or a general‑purpose smart contract—you use QSSM‑LE.

This engine is based on **module lattice** commitments over a cyclotomic ring \(R_q\), with a **Lyubashevsky‑style** Fiat–Shamir protocol: the proof publishes a masking commitment **\(t\)** and response **\(z\)** (no direct witness opening), with **rejection sampling** and a verifier check **\(\|z\|_\infty \le \gamma\)**. The Fiat–Shamir transcript includes a **rollup context digest** so proofs cannot be replayed across different finalized L1 views. The implementation **utilizes a direct Lyubashevsky‑style NIZK over \(R_q\)** (see `qssm-le`).

### **What it is**
A post‑quantum, witness‑hiding lattice proof layer for structured relations committed in \(R_q\) (NTT‑accelerated).

### **When to use it**
For arithmetic and relations that map cleanly to the supported commitment and proof API (see `qssm-le` and `qssm-le-engine-a.md`).

### **Performance**
Proof size is **ring‑element dominated** (two polynomials in \(R_q\) plus a 32‑byte challenge); verification targets fast NTT paths on modest hardware.

### **Note**
QSSM‑LE uses *lattice polynomials* as the algebraic carrier; parameter choices **\((\beta, \gamma, \eta, C_{\text{span}})\)** are security‑critical and documented beside the implementation.

---

## 3. Engine B: QSSM‑MS (The Mirror‑Shift Engine)

Most of what we do in crypto is simple: we compare numbers.

- Is \(v_A > v_B\)?
- Is my balance ≥ 100?
- Is my age ≥ 21?

For these tasks, using Engine A is like using a freight train to deliver a single letter.

QSSM‑MS is the “Sovereign Scalpel.” It uses a proprietary Mirror‑Shift logic that replaces all algebra with simple integer rotations and hash‑chains.

### **What it is**
A template‑specific NIZK argument: proof body **~291 bytes** (excluding the **32‑byte** Merkle root); see [Engine B](../02-protocol-specs/qssm-ms-engine-b.md) §4.

### **The Trick**
It uses a “Boolean Ghost‑Mirror.” Instead of doing math, Alice and Bob interpret their values as points on a circle. A random rotation from the Kaspa ledger “shifts” the circle. Alice then proves her position using a tiny Merkle path.

### **Performance**
~291 bytes (proof body; root separate).  
No polynomials.  
No circuits.  
Just pure, high‑speed hashing.

---

## 4. MSSQ: The Mirror‑Shift Sovereign Queue

If the engines are the brains, MSSQ (“Miss‑Q”) is the skeleton. It is a validity rollup architecture that solves the two biggest problems in modern L2s:

- **Censorship**
- **MEV**

### **Egalitarian Sequencing (MEV‑Zero)**

In MSSQ, there is no privileged sequencer. Instead:

1. A leader is elected for each slot via a **Seed\(_k\)** lottery over registered candidate IDs.  
2. The elected leader’s claim is **ML‑DSA–signed** over canonical bytes that include the same **rollup context digest** used by LE/MS.  
3. The leader **cannot** choose the order of transactions; they must sort by **hash‑lexicographical order**.

Your transaction order is determined by math, not bribes.  
MEV becomes mathematically impossible.

### **L1‑Anchored Randomness**

MSSQ uses **finalized** L1 limbs (and QRNG epochs where applicable) to build **Mirror‑Shift** and **lattice** challenges, so proof soundness is tied to the same **RollupContext** as the batcher. Production integration can use a **`qssm-kaspa`** adapter (gRPC scaffold) that maps node RPCs to `L1Anchor`.

---

## Summary: Why This Matters

The QSSM Family represents a move toward **Sovereign Logic**. We are no longer asking a central authority to validate our state; we are providing succinct, quantum‑safe proofs that the state is valid, and sequencing them in a way that treats every user as an equal.

### **If you need full logic:**  
Use **QSSM‑LE** (The Brain).

### **If you need to compare values:**  
Use **QSSM‑MS** (The Scalpel).

### **If you want fair ordering:**  
Use **MSSQ** (The Skeleton).

---

## References & Further Reading

- Beeren, Y. et al. (2024). *BlockDAG Architectures and the Future of Proof‑of‑Work*. Kaspa Research.  
- Hoffstein, J., Pipher, J., & Silverman, J. H. (2008). *An Introduction to Mathematical Cryptography*. Springer.  
- Nakamoto, S. (2008). *Bitcoin: A Peer‑to‑Peer Electronic Cash System*.