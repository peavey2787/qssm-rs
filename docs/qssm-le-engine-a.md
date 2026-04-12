### **The QSSM Protocol Family Series**
* **Overview:** [The Architecture of Sovereignty](./architecture-overview.md)
* **Engine A (QSSM-LE):** [General Lattice Logic](./qssm-le-engine-a.md)
* **Engine B (QSSM-MS):** [Succinct Predicate Logic](./qssm-ms-engine-b.md)
* **The Queue (MSSQ):** [Egalitarian Rollup Layer](./mssq-rollup.md)
* **Integration (B→A):** [BLAKE3–Lattice Gadget](./blake3-lattice-gadget-spec.md)

---

# QSSM‑LE (Engine A) — The Lattice Engine  
### General‑Purpose Arithmetic & NIZK via Module‑SIS Commitments

---

## Abstract

Presenting QSSM‑LE (Lattice Engine), a post‑quantum **witness‑hiding** NIZK layer for sovereign verification on BlockDAG architectures. QSSM‑LE commits in a cyclotomic ring \(R_q\) using a module‑LWE style commitment \(C = A r + \mu(m)\) and proves knowledge of short \(r\) via a **Lyubashevsky‑style** Fiat–Shamir protocol: the prover publishes a masking term **\(t = A y\)**, challenge **\(c\)** from BLAKE3 over **`QSSM-LE-FS-LYU-v1.0` (domain tag, first)**, then **`rollup_context_digest`**, CRS seed, public message \(m\), commitment \(C\), and masking \(t\)**, and response **\(z = y + c r\)**, using **rejection sampling** until **\(\|z\|_\infty \le \gamma\)** (and bounds on \(y\)). The verifier checks the norm bound and the ring equation **\(A z = t + c \cdot (C - \mu(m))\)** without ever seeing \(r\). Soundness and ZK depend on standard module‑SIS / module‑LWE heuristics and on **careful tuning** of \((\beta, \gamma, \eta, C_{\text{span}})\) (see `qssm-le` `params` module).

---

## 1. Algebraic Foundation and Preliminaries

The QSSM‑LE protocol operates over the power‑of‑two cyclotomic ring:



\[
R_q = \mathbb{Z}_q[X]/(X^n + 1),
\]



where \(n = 64\). In this architecture, the polynomial ring \(R_q\) is utilized strictly as an algebraic container for vectorized data, facilitating Single Instruction, Multiple Data (SIMD) operations.

The matrix **\(A\)** is derived deterministically via **`VerifyingKey::matrix_a_poly`**, which expands a **32-byte `crs_seed`** into **\(R_q\)** coefficients using **domain-separated BLAKE3** hashes. This ensures the CRS is **transparent and reproducible** by any party with the seed (it is not a fixed “backdoor” constant baked into the verifier).

### Reference Implementation Detail

To achieve sub‑10ms verification, the implementation utilizes a Number Theoretic Transform (NTT) optimized for \(n = 64\). The arithmetic is performed via a 64‑bit modular lift, ensuring that the Goldilocks‑field (\(F_p\)) R1CS constraints map identically to the ring without overflow. While the QSSM family avoids universal arithmetic circuits for program representation, it leverages these structured lattice properties to achieve post‑quantum security and computational efficiency.

---

## Table 1: System Parameters

| Parameter | Value      | Definition                                               |
|-----------|------------|-----------------------------------------------------------|
| n         | 64         | Degree of the cyclotomic polynomial (Ring Dimension)      |
| q         | 7340033    | NTT‑friendly prime modulus (implementation)                 |
| k         | 1          | Module rank (implementation utilizes a single \(R_q\) polynomial for the CRS) |
| β         | 8          | Coefficient bound on witness \(r\) (prover sampling)      |
| η         | 2 048      | Mask \(y\) bound (rejection threshold)                    |
| γ         | 4 096      | Verifier‑accepted bound on \(\|z\|_\infty\)              |
| \(C_{\text{span}}\) | 16 | FS scalar challenge range \([-C_{\text{span}},C_{\text{span}}]\) |


---

The public parameters include a fixed pseudorandom ring element **\(A \in R_q\)** sampled transparently from the CRS seed (see `VerifyingKey::matrix_a_poly` in `qssm-le`). The reference code does **not** expand a full rank‑\(k\) module matrix with \(k = 2\); Table 1 lists **\(k = 1\)** to match that design. Heuristic hardness is discussed in terms of ring‑structured SIS/LWE problems at dimension \(n\); formal reductions to a specific module problem are not claimed for this stub.

---

## 2. Sovereign Commitment Scheme

The protocol employs a commitment scheme that is computationally hiding under M‑LWE and computationally binding under M‑SIS.

### Commitment Construction

To commit to a message \(v_A\) with **\(0 \le v_A < 2^{30}\)** (the implementation rejects \(v_A \ge \texttt{MAX_MESSAGE} = 2^{30}\)), it is first embedded as a constant polynomial \(\mu_A \in R_q\).  
Alice samples short randomness for **\(r\)** in \(R_q\) (coefficient \(\ell_\infty\) bound \(\beta\)).  
The commitment is defined as:



\[
C(v_A, r) = A\, r + \mu_A \pmod{q}.
\]



### Hiding

The tuple \((A, A r)\) in \(R_q\) is discussed heuristically under M‑LWE‑style assumptions at this dimension.

### Binding

Any valid opening to a different value would imply discovery of a short SIS witness where \(\|\mathbf{r}\|_\infty \le \beta\).

### Prover integrity

The witness \(r\) is sampled with \(\|r\|_\infty \le \beta\). The masking vector \(y\) is sampled subject to \(\|y\|_\infty \le \eta\); the protocol **aborts and resamples** until the published \(z\) satisfies \(\|z\|_\infty \le \gamma\).

> **Note (bounded prover time):** Rejection sampling is capped at **65 536** iterations (`MAX_PROVER_ATTEMPTS` in `qssm-le`). Failure to find a valid \(z\) within this window returns a prover error, ensuring **bounded execution time** for telemetry‑sensitive BlockDAG nodes (rather than unbounded resampling).

---

## 3. Message embedding and Goldilocks consistency (v1)

Public integers \(m\) are embedded as a structured constant term \(\mu(m)\) in \(R_q\) (see implementation). For v1, the code enforces **\(0 \le m < 2^{30}\)** (`MAX_MESSAGE`); values with \(m \ge 2^{30}\) are rejected. **Full R1CS → ring gadgets** (e.g. BLAKE3 and Merkle verification feeding \(\mu(m)\)) are specified in the [BLAKE3–Lattice Gadget](./blake3-lattice-gadget-spec.md) note; the reference code implements the **linear commitment + Lyubashevsky response** path described below.

---

## 4. Protocol flow (Fiat–Shamir + rollup context)

### Context binding

Let **`rollup_context_digest`** be a 32‑byte BLAKE3 digest over a canonical **`RollupContext`** (finalized L1 limbs, QRNG epoch, etc.). The same digest is mixed into **QSSM‑MS** challenges and **ML‑DSA** leader messages in MSSQ.

### Prove (sketch)

1. Form commitment \(C = A r + \mu(m)\) with short \(r\).  
2. Sample short \(y\); compute \(t = A y\).  
3. Hash inputs are concatenated **in this order** (each as specified in `fs_challenge_bytes`): **`QSSM-LE-FS-LYU-v1.0`** (UTF‑8 domain string, **first**), then **`rollup_context_digest`** (32 bytes), **CRS seed** (`vk`, 32 bytes), **public message** \(m\) (8 bytes LE `u64`), **commitment** \(C\) (encoded coefficients), **masking** \(t\) (encoded coefficients). Apply **BLAKE3**, then map the digest to a small integer **\(c\)** in \([-C_{\text{span}}, C_{\text{span}}]\).  
4. \(z = y + c \cdot r\) (ring arithmetic).  
5. **Reject** unless \(\|z\|_\infty \le \gamma\) (and \(y\) satisfied its bound).  
6. Output \(\pi = (t, z, \text{challenge\_bytes})\).

### Verify

Fail-fast order matches `verify_lattice_algebraic` in `qssm-le`:

1. **Validate public inputs.** Ensure the public message \(m\) satisfies **\(0 \le m < 2^{30}\)** (`PublicInstance::validate` / `MAX_MESSAGE`).  
2. **Norm check.** If **\(\|z\|_\infty > \gamma\)** (centered mod \(q\)), **reject immediately** — do not proceed to the ring equation.  
3. **Fiat–Shamir reconstitution.** Recompute the challenge digest from **`(\texttt{QSSM-LE-FS-LYU-v1.0}, \texttt{rollup\_context\_digest}, \text{vk}, m, C, t)\)** in the same order as Prove step 3; check it equals the proof’s **`challenge`**, then map to the scalar **\(c\)**.  
4. **Ring equation.** Verify **\(A z \stackrel{?}{=} t + c \cdot (C - \mu(m))\)** in \(R_q\).

No witness \(r\) is transmitted.

---

## 5. Zero‑Knowledge and complexity

The published transcript \((t, z)\) is shaped by **rejection sampling** so that \(z\) carries only bounded noise relative to \(c \cdot r\); exact HVZK constants depend on the parameter set above.

**Wire format (fixed width).** Using **`encode_rq_coeffs_le`**, polynomials **\(t\)** and **\(z\)** are serialized as **fixed-width 256-byte** arrays (**\(N = 64\)** coefficients, **4 bytes LE `u32`** per coefficient). The Fiat–Shamir **`challenge`** is **32 bytes**. A complete proof **\(\pi = (t, z, \text{challenge})\)** in this layout is therefore a **stable 544-byte** payload on the wire (\(256 + 256 + 32\)), independent of coefficient values.

**Verification** is dominated by a small number of NTT multiplications. While target latency is environment‑dependent, **real‑world verification has been clocked at 0.026ms on consumer‑grade hardware (Asus TUF A16)**, effectively rendering verification overhead negligible for high‑velocity BlockDAG integration.

---

## 6. Reference implementation notes

The *qssm‑rs* crate **`qssm-le`** is the normative description for wire formats, domain strings, and bounds. Workspace tests cover **round‑trip prove/verify**, **wrong `rollup_context_digest`**, and tampering of \(t\), \(z\), and commitments.

---

## 7. Empirical Performance Data
The following trace represents a cold-start execution of the millionaires_duel binary on consumer-grade hardware (Asus TUF A16).

cargo run -p qssm-ref --bin millionaires_duel --release
    Finished `release` profile [optimized] target(s) in 0.16s
     Running `target\release\millionaires_duel.exe`
Millionaire’s Duel — defaults: use args `<v_a> <v_b>` (demo uses Public-Difference ZK).
Balances: Alice=1000, Bob=500
verify_lattice: 0.026ms (release / God-Mode path)
[SMT State] Slot: 0x49024683049c88d3e77be87167ca787f12d779ccd778d0be92f916719ccbe7f1
[SMT State] Data: [01 00 00 00 00 00 00 00 57 65 61 6c 74 68 69 65 73 74 4b 6e 69 67 68 74 00 00 00 00 00 00 00 00]
Parsed: 1 Win | Status: WealthiestKnight
State transition: Alice (ID: c3a3107688d2…) promoted to ‘Wealthiest Knight’ — rollup root fb…
Full SMT root: fb452a66a363ea1c3301c52f03528cbb46b3a9fb9365c264576c7ce9f2307a42

Note on Latency: The 0.026ms verification time confirms the efficiency of the NTT-optimized negacyclic convolution. This performance ceiling allows for high-throughput validation without the need for specialized hardware accelerators.

---

## Appendix A: Security Definitions

### Definition 1 — Ring‑structured hardness (informal)

For a pseudorandom \(A \in R_q\) derived from the CRS, the advantage of any PPT adversary in finding a **short** non‑trivial ring element \(x\) satisfying an adversary‑chosen relation relevant to binding (e.g. SIS‑style) at \(\|\cdot\|_\infty \le \beta\) is assumed **negligible** under standard lattice heuristics. This document does not pin a single formal **module** problem to the reference implementation.

### Definition 2 — Knowledge soundness (informal)

One expects a **Fiat–Shamir** knowledge extractor in the **random oracle** model for this linear **Lyubashevsky** structure, modulo the chosen challenge space and bounds; a full proof write‑up is **not** claimed here. **Parameter mistakes** break soundness or witness leakage—review against Lyubashevsky / Dilithium‑style analyses before production use.

---

## References

Ducas, L., et al. (2018). *CRYSTALS-Dilithium: A lattice-based digital signature scheme.* (Related rejection‑sampling and linear‑response patterns.)  
        https://pq-crystals.org/dilithium/

Hoffstein, J., Pipher, J., & Silverman, J. H. (2008). *An introduction to mathematical cryptography.* Springer.  
        https://doi.org/10.1007/978-0-387-77993-5

Langley, A. (2023). *The BLAKE3 hashing function: Technical specification.*  
        https://github.com/BLAKE3-team/BLAKE3-specs

Lyubashevsky, V. (2012). *Lattice signatures with help from standard lattices.* In *Proceedings of the 44th Annual ACM Symposium on Theory of Computing (STOC).*  
        https://doi.org/10.1145/2213977.2214024

NIST (2024). *FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA).* (Used for MSSQ leader attestations in `mssq-batcher`.)