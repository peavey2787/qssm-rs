### Documentation map

* [README](../README.md) — Project home
* [Architecture overview](./architecture-overview.md)
* [MSSQ — Egalitarian rollup](./mssq-rollup.md)
* [QSSM-LE — Engine A](./qssm-le-engine-a.md)
* [QSSM-MS — Engine B](./qssm-ms-engine-b.md)
* [BLAKE3–lattice gadget — Rust plan](./blake3-lattice-gadget-rust-plan.md)
* [Kaspa L2 core deployment manifest](./l2-kaspa-core-deployment-manifest.md)

---

# Recursive Integration — BLAKE3–Lattice Gadget Specification  
### Verifying Engine B (QSSM‑MS) Hash Witnesses Inside Engine A (QSSM‑LE) Constraints

---

## Abstract

This note specifies how **BLAKE3**-based artifacts from **Engine B** (position‑aware Merkle parents, MS domain‑separated leaves, and **`fs_v2`** challenges) can be **checked inside** the arithmetic layer that feeds **Engine A**’s **\(R_q\)** commitment and **Lyubashevsky‑style** Fiat–Shamir transcript. The goal of the **Recursive Integration Roadmap** is a single sovereign statement: an **LE** proof whose public message (or auxiliary digest) encodes **“Engine B’s Merkle path + FS binding holds under `rollup_context_digest`.”**  

The **reference ring** remains **`qssm-le`**:  
\[
R_q = \mathbb{Z}_q[X]/(X^{64}+1),\quad q = 7\,340\,033.
\]  
This document is **normative for gadget design**; it does **not** replace the **`qssm-le`** / **`qssm-ms`** crates as the behavior spec for standalone verification.

---

## 1. Design Scope

| Layer | Role in integration |
|--------|---------------------|
| **Constraint / R1CS (Goldilocks \(F_p\))** | Bit logic, 32‑bit word arithmetic mod \(2^{32}\), BLAKE3 round functions, Merkle chaining. Coefficients are small; **`q`** is large enough for **boolean** and **limb** algebra with **no wrap** inside a single limb if limbs are chosen \(\ll q\). |
| **Lift to \(R_q\)** | The existing LE pipeline maps structured field witnesses to **\(\mu(m)\)** and short vectors **\(r,y,z\)** (see [Engine A](./qssm-le-engine-a.md)). The **gadget** produces the integer(s) that become **`m`** or a hashed digest limb sequence **consistent** with **`MAX_MESSAGE`** and embedding rules. |

**Integration invariant:** Engine B’s **7‑step** Merkle path (128 leaves → depth **7**) matches **`PositionAwareTree`** + **`merkle_parent`** in **`qssm-utils`** (`DOMAIN_MERKLE_PARENT = "QSSM-MERKLE-PARENT-v1.0"`).

---

## 2. Representing 32‑Bit Integers in \(R_q\)

We distinguish **three** representations; the integrator picks one per pipeline stage.

### 2.1 Bit vector (canonical for XOR / rotations)

A **32‑bit** unsigned word **\(W\)** is encoded by bits **\(b_0,\dots,b_{31}\)** with  
\[
W = \sum_{i=0}^{31} b_i\,2^i,\qquad b_i \in \{0,1\}.
\]  
**Binary constraints** (quadratic, degree **2**):  
\[
b_i(1 - b_i) = 0 \quad\text{in } \mathbb{Z}_q.
\]  
Because **\(q = 7\,340\,033 > 32\)**, the sum **\(W\)** fits in a **single** field element for **constraint‑system** purposes; no coefficient of the **lifted** polynomial need store **\(W\)** as a single giant integer—**\(W\)** is a **scalar wire** in the **R1CS** layer.

### 2.2 Coefficient‑wise SIMD in one polynomial

For **vectorized** hashing, allocate **\(32\)** indices **\(i \in \{0,\dots,31\}\)** in one **\(R_q\)** polynomial **\(f\)** with  
\[
f_i = b_i
\]  
(and remaining coefficients **\(0\)** or used for other lanes). This matches the **SIMD container** intuition in [Engine A §1](./qssm-le-engine-a.md): one polynomial carries **many** independent small coefficients. **Range checks** \(\{0,1\}\) apply **per coefficient** as above.

### 2.3 Multi‑limb (only if needed)

If a wire must hold a value **\(\ge q\)**, split into **\(\ell\)** limbs **\(L_j < 2^{b}\)** with **\(2^{b\ell} \ge\) range** and constrain carries. For **BLAKE3** on **32‑bit** words, **limbs are unnecessary** if all intermediate **\(u32\)** operations are modeled **mod \(2^{32}\)** with explicit **overflow** bits (standard **R1CS** pattern).

---

## 3. Bitwise Logic via Arithmetic (Degree‑2 Core)

For **\(x,y \in \{0,1\}\)** regarded as **\(\mathbb{Z}_q\)** elements satisfying **\(x^2=x\)**, **\(y^2=y\)**:

\[
x \oplus y = x + y - 2xy.
\]

This is **one multiplication** (**\(xy\)**) and **linear** combination—**degree 2** overall in the **R1CS** sense when **\(x,y\)** are witnesses.

**Conjunction** (AND): **\(x \land y = xy\)** (degree 2).

**Negation**: **\(\lnot x = 1 - x\)** (linear), provided **\(x\)** is boolean‑constrained.

### 3.1 32‑bit XOR

Decompose **\(a,b\)** into bits **\(a_i,b_i\)**, introduce witness **\(o_i\)** and constrain  
\[
o_i = a_i + b_i - 2 a_i b_i,\quad a_i(1-a_i)=0,\ b_i(1-b_i)=0,\ o_i(1-o_i)=0.
\]  
**32** independent **degree‑2** blocks—**no** cross‑depth multiplication between blocks unless composing with add/carry.

### 3.2 Unsigned rotation on 32‑bit words

**Two** equivalent strategies:

1. **Bit wiring (preferred, degree 1):** **ROTR32(\(a,r\))** permutes indices: **\(o_{(i+r)\bmod 32} = a_i\)**. **No** new multiplications—only **equality** constraints between witness indices (or a **copy** gadget). This **avoids** degree growth entirely for the rotation step.

2. **Arithmetic:** **\((a \ll r) \oplus (a \gg (32-r))\)** using shifts built from **sums of masked bits**—higher constraint count but same **degree‑2** ceiling if XOR uses §3.

The roadmap **recommends (1)** inside the BLAKE3 **G**‑function scheduling: fix **rotation constants** from the BLAKE3 spec and **rewire** bits.

### 3.3 Addition mod \(2^{32}\)

Standard **ripple carry**: bits **\(a_i,b_i,c_i^{\text{in}},s_i,c_i^{\text{out}}\)** with **full‑adder** constraints (each **degree 2**). **Chained depth** is **\(O(32)\)** in **constraint layers**, not **multiplicative degree** in a single polynomial.

---

## 4. BLAKE3 Inside the Constraint System

**Interface to the rest of QSSM:** **`hash_domain(domain, chunks)`** is **`BLAKE3( UTF8(domain) ‖ chunk_0 ‖ … )`** truncated to **32** bytes (**`qssm_utils::hashing`**). **Merkle parent** is **`hash_domain(DOMAIN_MERKLE_PARENT, &[concat(left\Vert right)])`** — **64**‑byte chunk after **domain** prefix.

### 4.1 Decomposition strategy

- **Outer:** Implement **BLAKE3**’s **chunk** / **CV** chaining for the **32‑byte** digest output required at each Merkle node.
- **Inner:** **Quarter‑round** on **\(u32\)** words using **§3** (XOR, add mod \(2^{32}\), ROTR via **bit wiring**).

### 4.2 Preventing degree explosion

| Risk | Mitigation |
|------|------------|
| **Deep composition** \(f(g(h(\cdot)))\) with **multiplicative** gates | **Do not** nest **nonlinear** maps in one giant expression. After each **XOR** / **AND** / **carry** chunk, introduce a **fresh** witness vector that is **asserted equal** to the output of the previous gadget (**one R1CS row per equality batch**). |
| **High degree in one constraint** | Keep each row **degree ≤ 2** (standard R1CS). **\(x \oplus y\)** uses **one** multiply; **\(x \land y\)** uses **one** multiply. |
| **Lyubashevsky verification cost** | Native **LE** verification stays **\(O(n)\)** NTTs; **gadget cost** hits **proving time** and **statement size**, not the **\(A z = t + c(\cdots)\)** check. Target **constant‑width** BLAKE3 **per node** so **7** Merkle levels stay **\(7 \times\)** fixed work. |
| **Lookup / table‑based BLAKE3 (future)** | If **degree‑2** copy constraints dominate, consider **lookup arguments** (outside this stub) for **S‑box‑free** word ops—**trade circuit size for verifier‑friendly** structure. |

**Bottom line:** **Degree explosion** is avoided by **(i)** **degree‑2** boolean algebra, **(ii)** **bit‑permutation** rotations, **(iii)** **fresh witnesses** per BLAKE3 **round** / **Merkle** **level**, so the **R1CS** remains **sparse** and **low‑degree**; the **0.026 ms** **LE** verifier time quoted in [Engine A](./qssm-le-engine-a.md) applies to the **lattice** step once **`m`** is fixed, **not** to proving the **hash** gadget (prover‑side cost is separate).

---

## 5. Merkle Path “Wrapping” for Engine B → Engine A

**Goal:** Given **public** Merkle **root** **\(R^\*\)** (32 B) and **Engine B** proof body fields (see [Engine B §4](./qssm-ms-engine-b.md)), the **constraint system** proves that the **opened leaf** **\(L\)** and **siblings** **\(S_0,\dots,S_6\)** satisfy **\( \text{root}(L; S_0,\dots,S_6) = R^\*\)** using the **same** **`merkle_parent`** as **`qssm-ms`**.

### 5.1 Witness layout (suggested)

| Witness block | Contents |
|---------------|----------|
| **Leaf digest** | **32** bytes → **8** × **\(u32\)** or **256** bits with boolean range checks |
| **Siblings** **\(S_\ell\)** | **7** × **32** bytes, same decomposition |
| **Running hashes** **\(H_0,\dots,H_7\)** | **\(H_0 = L\)**, **\(H_{\ell+1} = \texttt{merkle\_parent}(X_\ell, Y_\ell)\)** where **\((X_\ell,Y_\ell)\)** is **\((H_\ell, S_\ell)\)** or **\((S_\ell, H_\ell)\)** per **leaf index** parity |
| **Index bits** | **7** bits (or full **7**‑bit index) fixing **left/right** order at each level |

Each **`merkle_parent`** invocation expands to **one** **`hash_domain(DOMAIN_MERKLE_PARENT, ·)`** → **one** **BLAKE3** **gadget** outputting **32** bytes.

### 5.2 Binding to LE’s public input

- **Option A (digest embedding):** Compute **\(d = \texttt{BLAKE3}(\text{“MS‑VERIFIED”} \Vert R^\* \Vert \cdots)\)** and embed **\(d \bmod 2^{30}\)** (or a limb) as **`m`** subject to **`MAX_MESSAGE`** (see **`qssm-le`** `params`).
- **Option B (multi‑proof):** Multiple **LE** messages or an extended **rollup** statement carry **32‑byte** **root** explicitly in a **batch** verifier (future **`qssm-ref`** trait).

The **Fiat–Shamir** transcript for **MS** already mixes **`rollup_context_digest`**; the **integrated** statement must **re‑expose** the same digest in the **LE** FS input order when **cross‑binding** engines.

### 5.3 Soundness sketch

If **BLAKE3** is **collision‑resistant** and **R1CS** sound, a prover cannot forge **\(R^\*\)** **unless** they break **MS** binding or **LE** soundness. **Domain separation** (**`DOMAIN_MERKLE_PARENT`**, **`DOMAIN_MS`**, **`QSSM-LE-FS-LYU-v1.0`**) prevents **cross‑protocol** **malleability**.

---

## 6. Open Engineering Tasks

1. **Fixed** BLAKE3 **sub-circuit** library in **Goldilocks** (or chosen **\(F_p\)**) with **test vectors** vs **`blake3`** crate.  
2. **End-to-end** **witness** generator: **MS** proof → **R1CS** assignment → **\(\mu(m)\)** lift.  
3. **Bench** **prover** time vs standalone **MS** **verify**; tune **batching** or **recursion** depth.  
4. **Audit** **message** **range** and **embedding** so **no** **wrap** in **\(\mu(m)\)** **collides** with **hash** **outputs**.

---

## References (internal)

- [Engine A — QSSM‑LE](./qssm-le-engine-a.md)  
- [Engine B — QSSM‑MS](./qssm-ms-engine-b.md)  
- **`qssm-utils`**: `merkle_parent`, `hash_domain`, `DOMAIN_MERKLE_PARENT`  
- **`qssm-le`**: `params` (`N`, `Q`, `MAX_MESSAGE`)

---

## Bibliographic references

O’Connor, J., Aumasson, J. P., Neves, S., & Wilcox‑O’Hearn, Z. (2021). *BLAKE3: One function, fast everywhere.*  
https://github.com/BLAKE3-team/BLAKE3-specs

---
