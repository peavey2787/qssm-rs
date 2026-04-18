### Documentation map

* [README](../README.md) — Project home
* [Architecture overview](./architecture-overview.md)
* [QSSM-LE — Engine A](./qssm-le-engine-a.md)
* [QSSM-MS — Engine B](./qssm-ms-engine-b.md)
* [BLAKE3–lattice gadget spec](./blake3-lattice-gadget-spec.md)
* [BLAKE3–lattice gadget — Rust plan](./blake3-lattice-gadget-rust-plan.md)
* [Kaspa L2 core deployment manifest](./l2-kaspa-core-deployment-manifest.md)

---

# MSSQ v1.0 — The Mirror‑Shift Sovereign Queue  
### MEV-Zero Autonomous Ordering & Verifiable Work-based Rollups

---

## Abstract

We introduce the Mirror‑Shift Sovereign Queue (MSSQ), a novel validity rollup architecture anchored on the Kaspa L1 BlockDAG. MSSQ utilizes the QSSM (Quantum‑Safe Sovereign Millionaire) proof family to execute a “Hash‑VM” predicate environment. Unlike traditional rollups that utilize a centralized sequencer with reordering discretion, MSSQ implements a **Seed\(_k\)** lottery for slot leaders, with each attestation **cryptographically bound** by an **ML‑DSA (FIPS 204)** signature over a canonical message that includes a **rollup context digest** (finalized L1 view, QRNG epoch, and related limbs). Transaction ordering is **deterministic hash‑lexicographical sequencing**. This configuration mathematically eliminates Maximum Extractable Value (MEV) while preserving censorship resistance through an L1‑embedded inbox and a recursive fallback liveness mechanism. State is carried in a **State Mirror Tree (SMT)**; batch application is **proof‑gated** via a verifier trait in the integration layer. We further detail a Sybil‑resistant reward model predicated on Proof‑of‑Useful‑Work (PoUW) to ensure long‑term network decentralization.

---

## 1. Core Philosophy and Architectural Intent

The Mirror‑Shift Sovereign Queue (MSSQ) represents a departure from the “Sequencer‑as‑King” model. The protocol is designed as a **Sovereign Validity Rollup**, where the L1 (Kaspa) acts as a passive Data Availability (DA) layer and an immutable entropy anchor. The primary objective of MSSQ is to reduce the role of the rollup operator to that of a deterministic “clerk” with **zero discretionary power** over transaction ordering, thereby achieving an **MEV‑zero** state.

---

## 2. Protocol Stack and Data Availability

MSSQ leverages the high‑throughput, low‑latency properties of the Kaspa BlockDAG to maintain state consistency.

### **DA Layer**
Kaspa L1 provides the immutable anchor \(s\) for randomness and a passive **L1‑embedded inbox** for L2 transactions.

### **Proving Engines**
Heterogeneous verification via:

- **QSSM‑LE** — General Arithmetic  
- **QSSM‑MS** — Succinct Predicates  

### **State Representation**
A **State Mirror Tree (SMT)** — a Merkle‑sum tree — tracks account balances and predicate states.

### **Settlement**
Rollup logic **settles on Kaspa‑finalized** L1 data (not the volatile DAG tip), so the **rollup context** and leader lottery resist tip reorgs. State transitions update an **SMT** root; per‑transaction proofs are verified before deltas apply (integration implements `TxProofVerifier`).

### **Demo — Millionaire’s Duel (`qssm-ref`)**
The workspace ships an end‑to‑end **Millionaire’s Duel** scenario: ML‑DSA leader attestations, a **Public‑Difference ZK Proof** from **QSSM‑LE** (Lyubashevsky‑style, `rollup_context_digest`‑bound), and an SMT **leaderboard leaf** keyed by `hash_domain("MSSQ-DUEL-LEADERBOARD-V1.0" ‖ "MSSQ_DUEL_LEADERBOARD_V1")`. **V1.0** makes the encoded difference scalar public (hiding witness and absolute balances on the LE wire, but revealing **distance** for winner logic); **V2.0** may hide the delta (witness‑hiding comparison). Run `cargo run -p qssm-ref --bin millionaires_duel` (use `--release` to exercise the sub‑10 ms `verify_lattice` bar in tests).

**Miss‑Q in Motion: The Reference Implementation**

The MSSQ logic is now live in the qssm‑rs workspace. By running the millionaires_duel binary, users can witness the Egalitarian Lottery and deterministic state update in real‑time.

Live benchmark posture (Asus TUF A16 class hardware): verify_lattice remains **sub-1ms**.

---

## 3. Leader Selection and Liveness Hardening

MSSQ utilizes a **Fair Clock** mechanism for slot allocation to ensure egalitarian network participation.

### **Leader Selection via \(Seed_k\) Lottery**

Eligible nodes participate in a slot‑based election. To maintain post‑quantum resilience, MSSQ avoids elliptic‑curve VRFs in favor of a **Seed\(_k\)** Lottery anchored to:

- the L1 BlockDAG  
- a Quantum Random Number Generator (QRNG) epoch  

For slot \(k\), the leader is the node \(ID_i\) minimizing the distance to:



\[
Seed_k = \text{BLAKE3}(\text{Parent\_Hash} \parallel \text{QRNG\_Epoch}).
\]



This ensures leader selection is unpredictable until the L1 block and QRNG tick finalize, making grinding attacks economically and computationally unviable.

### **Recursive Fallback Window**

To mitigate targeted DDoS on the elected leader, MSSQ implements a fallback:

- If slot \(k\) remains unbatched for \(T\) L1 blocks (\(T \approx 120\)),  
- the leader of slot \(k+1\) may **collapse** the pending transactions of slot \(k\) into a combined batch.

This ensures liveness even if a leader is offline or attacked.

---

## 4. Egalitarian Sequencing (MEV‑Zero)

In MSSQ, the “mempool” is the **L1‑anchored inbox**.

The leader’s role is strictly limited to:

- **Deduplication** — removing redundant transaction IDs  
- **Deterministic Sorting** — ordering transactions by **hash‑lexicographical order**

Because ordering is a deterministic function of transaction data, no leader can:

- insert  
- reorder  
- censor (without provable omission)  

MEV becomes **mathematically impossible**.

---

## 5. Dust‑Attack Defense and L1 Integration

To prevent resource exhaustion, MSSQ implements an **Economic Firewall** for the L1‑embedded inbox.

### **Mandatory Fee Burn**
Every transaction posted to the L1 inbox must include a verifiable burn of KAS (e.g., **0.0001 KAS**) to a null address.

### **Verification**
MSSQ nodes verify this burn before processing.  
This creates a **non‑trivial cost** for attackers attempting to flood the queue, while remaining negligible for legitimate users.

---

## 6. Sybil‑Resistant Reward Model (PoUW)

MSSQ rejects “Uptime‑as‑Stake” models, which are prone to Sybil clustering.  
Instead, it utilizes **Proof‑of‑Useful‑Work (PoUW)**.

### **Table 1: Work Credit Distribution**

```markdown
| Credit Type        | Verification Method                                         | Reward Weight |
|--------------------|-------------------------------------------------------------|---------------|
| Batch Verification | ML‑DSA leader attestation + context‑bound proofs            | High          |
| State Serving      | User‑signed Merkle inclusion receipts                       | Medium        |
| Relaying           | Inclusion of relayed tx in a finalized batch                | Low           |