### Documentation map

* [README](../README.md) — Project home
* [Architecture overview](./architecture-overview.md)
* [MSSQ — Egalitarian rollup](./mssq-rollup.md)
* [QSSM-MS — Engine B](./qssm-ms-engine-b.md)
* [BLAKE3–lattice gadget spec](./blake3-lattice-gadget-spec.md)
* [BLAKE3–lattice gadget — Rust plan](./blake3-lattice-gadget-rust-plan.md)
* [Kaspa L2 core deployment manifest](./l2-kaspa-core-deployment-manifest.md)

---

# QSSM‑LE (Engine A) — The Lattice Engine  
### General‑Purpose Arithmetic & NIZK via Module‑SIS Commitments

---

## Abstract

Presenting QSSM‑LE (Lattice Engine), a post‑quantum **witness‑hiding** NIZK layer for sovereign verification on BlockDAG architectures. QSSM‑LE commits in a cyclotomic ring \(R_q\) using a module‑LWE style commitment \(C = A r + \mu(\text{public\_binding})\) and proves knowledge of short \(r\) via a **Lyubashevsky‑style** Fiat–Shamir protocol: the prover publishes a masking term **\(t = A y\)**, derives a transcript seed from BLAKE3 over **`QSSM-LE-FS-LYU-v1.0`** plus cross-protocol context, expands a short polynomial challenge **\(c(x)\)**, and responds with **\(z = y + c(x)r\)**, using **rejection sampling** until **\(\|z\|_\infty \le \gamma\)** (and bounds on \(y\)). The verifier checks the norm bound and the ring equation **\(A z = t + c(x) \cdot (C - \mu)\)** without ever seeing \(r\). Soundness and ZK depend on standard module‑SIS / module‑LWE heuristics and on **careful tuning** of \((\beta, \gamma, \eta, C_{\text{poly}})\) (see `qssm-le` `params` module).

---

## 1. Algebraic Foundation and Preliminaries

The QSSM‑LE protocol operates over the power‑of‑two cyclotomic ring:



\[
R_q = \mathbb{Z}_q[X]/(X^n + 1),
\]



where \(n = 256\). In this architecture, the polynomial ring \(R_q\) is utilized strictly as an algebraic container for vectorized data, facilitating Single Instruction, Multiple Data (SIMD) operations.

The matrix **\(A\)** is derived deterministically via **`VerifyingKey::matrix_a_poly`**, which expands a **32-byte `crs_seed`** into **\(R_q\)** coefficients using **domain-separated BLAKE3** hashes. This ensures the CRS is **transparent and reproducible** by any party with the seed (it is not a fixed “backdoor” constant baked into the verifier).

### Reference Implementation Detail

The implementation utilizes a Number Theoretic Transform (NTT) optimized for \(n = 256\). The arithmetic is performed via a 64‑bit modular lift, ensuring that the Goldilocks‑field (\(F_p\)) R1CS constraints map identically to the ring without overflow. While the QSSM family avoids universal arithmetic circuits for program representation, it leverages these structured lattice properties to achieve post‑quantum security and computational efficiency.

---

## Table 1: System Parameters

| Parameter | Value      | Definition                                               |
|-----------|------------|-----------------------------------------------------------|
| n         | 256        | Degree of the cyclotomic polynomial (Ring Dimension)      |
| q         | 8380417    | NTT‑friendly prime modulus (implementation)                 |
| k         | 1          | Module rank (implementation utilizes a single \(R_q\) polynomial for the CRS) |
| β         | 8          | Coefficient bound on witness \(r\) (prover sampling)      |
| η         | 2 048      | Mask \(y\) bound (rejection threshold)                    |
| γ         | 4 096      | Verifier‑accepted bound on \(\|z\|_\infty\)              |
| \(C_{\text{poly\_size}}\) | 64 | FS polynomial challenge coefficient count |
| \(C_{\text{poly\_span}}\) | 16 | FS per-coefficient range \([-C_{\text{poly\_span}},C_{\text{poly\_span}}]\) |


---

The public parameters include a fixed pseudorandom ring element **\(A \in R_q\)** sampled transparently from the CRS seed (see `VerifyingKey::matrix_a_poly` in `qssm-le`). The reference code does **not** expand a full rank‑\(k\) module matrix with \(k = 2\); Table 1 lists **\(k = 1\)** to match that design. Heuristic hardness is discussed in terms of ring‑structured SIS/LWE problems at dimension \(n\); formal reductions to a specific module problem are not claimed for this stub.

---

## 2. Sovereign Commitment Scheme

The protocol employs a commitment scheme that is computationally hiding under M‑LWE and computationally binding under M‑SIS.

### Commitment Construction

To commit, the implementation embeds either a legacy scalar limb or a digest coefficient-vector into \(\mu \in R_q\) (`PublicBinding`).  
Alice samples short randomness for **\(r\)** in \(R_q\) (coefficient \(\ell_\infty\) bound \(\beta\)).  
The commitment is defined as:



\[
C(\text{public\_binding}, r) = A\, r + \mu \pmod{q}.
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

Public input is embedded as \(\mu(\text{public\_binding})\) in \(R_q\): secure mode uses digest coefficient-vector lanes; legacy mode keeps the 30-bit limb for compatibility only. **Full R1CS → ring gadgets** (e.g. BLAKE3 and Merkle verification feeding \(\mu\)) are specified in the [BLAKE3–Lattice Gadget](./blake3-lattice-gadget-spec.md) note.

---

## 4. Protocol flow (Fiat–Shamir + rollup context)

### Context binding

Let **`rollup_context_digest`** be a 32‑byte BLAKE3 digest over a canonical **`RollupContext`** (finalized L1 limbs, QRNG epoch, etc.). The same digest is mixed into **QSSM‑MS** challenges and **ML‑DSA** leader messages in MSSQ.

### Prove (sketch)

1. Form commitment \(C = A r + \mu(m)\) with short \(r\).  
2. Sample short \(y\); compute \(t = A y\).  
3. Hash inputs are concatenated **in this order** (each as specified in `fs_challenge_bytes`): domain, cross-protocol binding labels, **`rollup_context_digest`**, **CRS seed**, serialized public binding bytes, **commitment** \(C\), and **masking** \(t\). Apply **BLAKE3** to obtain a seed.  
4. Expand seed into short polynomial challenge \(c(x)\) with \(C_{\text{poly\_size}}\) coefficients in \([-C_{\text{poly\_span}}, C_{\text{poly\_span}}]\).  
5. \(z = y + c(x) \cdot r\) (ring arithmetic).  
5. **Reject** unless \(\|z\|_\infty \le \gamma\) (and \(y\) satisfied its bound).  
6. Output \(\pi = (t, z, \text{challenge\_seed})\).

### Verify

Fail-fast order matches `verify_lattice_algebraic` in `qssm-le`:

1. **Validate public inputs.** Ensure selected public binding mode satisfies bounds (`PublicInstance::validate`).  
2. **Norm check.** If **\(\|z\|_\infty > \gamma\)** (centered mod \(q\)), **reject immediately** — do not proceed to the ring equation.  
3. **Fiat–Shamir reconstitution.** Recompute challenge seed from the same transcript inputs; check it equals proof **`challenge_seed`**; expand the same polynomial challenge \(c(x)\).  
4. **Ring equation.** Verify **\(A z \stackrel{?}{=} t + c(x) \cdot (C - \mu)\)** in \(R_q\).

No witness \(r\) is transmitted.

---

## 5. Zero‑Knowledge and complexity

The published transcript \((t, z)\) is shaped by **rejection sampling** so that \(z\) carries only bounded noise relative to \(c \cdot r\); exact HVZK constants depend on the parameter set above.

**Wire format (fixed width).** Using **`encode_rq_coeffs_le`**, polynomials **\(t\)** and **\(z\)** are serialized as **fixed-width 1024-byte** arrays (**\(N = 256\)** coefficients, **4 bytes LE `u32`** per coefficient). The Fiat–Shamir **`challenge`** is **32 bytes**. A complete proof **\(\pi = (t, z, \text{challenge})\)** in this layout is therefore a **stable 2080-byte** payload on the wire (\(1024 + 1024 + 32\)), independent of coefficient values.

**Verification** is dominated by a small number of NTT multiplications. While target latency is environment‑dependent, real‑world measurements on consumer‑grade hardware remain **sub-1ms verification** (`< 1ms`), effectively rendering verification overhead negligible for high‑velocity BlockDAG integration.

---

## 6. Reference implementation notes

The *qssm‑rs* crate **`qssm-le`** is the normative description for wire formats, domain strings, and bounds. Workspace tests cover **round‑trip prove/verify**, **wrong `rollup_context_digest`**, and tampering of \(t\), \(z\), and commitments.

---

## 7. Empirical Performance Data
The following trace represents a cold-start execution of the millionaires_duel binary on consumer-grade hardware (Asus TUF A16).

cargo run -p qssm-ref --bin millionaires_duel --release
    Finished `release` profile [optimized] target(s) in 0.16s
     Running `target\release\millionaires_duel.exe`
QSSM Protocol Family: Millionaires' Duel
Privacy-Preserving Magnitude Comparison via Lattice-Based Predicates
------------------------------------------------------------------------

Demo: Public-Difference ZK, ML-DSA attestations, SMT leaderboard.
You will enter each player’s balance at the prompts below.

Enter Alice’s balance (non-negative integer): 1000
Enter Bob’s balance (non-negative integer): 500

Using balances: Alice=1000, Bob=500
Magnitude: Alice > Bob (public duel scalar above shift)
verify_lattice: < 1ms (release / God-Mode path)
[SMT State] Slot: 0x49024683049c88d3e77be87167ca787f12d779ccd778d0be92f916719ccbe7f1
[SMT State] Data: [01 00 00 00 00 00 00 00 57 65 61 6c 74 68 69 65 73 74 4b 6e 69 67 68 74 00 00 00 00 00 00 00 00]
Parsed: 1 Win | Status: WealthiestKnight
State transition: slot leader Alice (ID: c3a3107688d2…) committed duel outcome winner=Alice — rollup root fb…
Full SMT root: fb452a66a363ea1c3301c52f03528cbb46b3a9fb9365c264576c7ce9f2307a42

Note on Latency: Sub-1ms verification confirms the efficiency of the NTT-optimized negacyclic convolution. This performance ceiling allows for high-throughput validation without the need for specialized hardware accelerators.

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