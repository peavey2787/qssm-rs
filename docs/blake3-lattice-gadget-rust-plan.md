### **The QSSM Protocol Family Series**
* **Overview:** [The Architecture of Sovereignty](./architecture-overview.md)
* **Integration (B→A):** [BLAKE3–Lattice Gadget](./blake3-lattice-gadget-spec.md)

---

# BLAKE3–Lattice Gadget — Rust implementation plan

This document is the **normative implementation plan** for [`blake3-lattice-gadget-spec.md`](./blake3-lattice-gadget-spec.md). **Math is law:** there is no “primitives first, decomposition later” shortcut—**bit decomposition and degree‑2 algebra are mandatory from the first line of `bits.rs`.**

---

## Mandatory requirements (normative)

### 1. Algebraic primitives (`bits.rs`) — degree‑2 R1CS compatibility

All bit/word logic exposed from **`bits.rs`** must be expressible as **degree‑2** constraints over \(\{0,1\}\) (or small integers) in a future R1CS embedding.

| Rule | Requirement |
|------|-------------|
| **XOR** | **Must** use **\(x \oplus y = x + y - 2xy\)** on bit witnesses ([`constraint_xor`]). The **normative** witness path **must not** use `^` / `bitxor` for exported witnesses—tests may assert against `^` only for equality checks. |
| **AND / OR** | **AND** = **\(xy\)**; **OR** on bits = **\(a + b - ab\)**. |
| **Addition** | **Must not** use `wrapping_add` (or any single native “add”) as the **definition** of `u32` addition in the witness API. **Must** use a **ripple‑carry adder** from **[`FullAdder`]** at every bit, with **[`RippleCarryWitness`]** holding **all** stages. |
| **Full adder** | **[`FullAdder`]** **must** expose **`sum`**, **`carry_out`**, **`a`**, **`b`**, **`cin`** as explicit wires. Carries **must** chain bit‑to‑bit—no collapsed carry. |
| **Phase‑1 / Phase‑2 sync (schedule)** | **Phase 1** implementation **includes** witness structs (**[`XorWitness`]**, **[`RippleCarryWitness`]**, `validate()`) **from day one**. There is **no** separate “Phase 1 = raw ops only, Phase 2 = structs later.” Decomposition and **\(x+y-2xy\)** are **not optional follow‑ons**—they **are** Phase 1. |

---

### 2. Endianness safety (Little‑Endian bit decomposition)

**Strict rule:** **`bits[i]`** is the bit with weight **\(2^i\)** (**LSB at `i == 0`**). This matches **little‑endian** **`u32`** ↔ bytes and **must** stay **bit‑for‑bit** consistent with the **BLAKE3** reference’s 32‑bit word operations.

- **`to_le_bits` / `from_le_bits`** are the **only** canonical word↔bit serialization unless a docstring defines an exception.
- **Phase 1** **starts** with LE decomposition: every higher‑level gadget (**XOR witness**, ripple add, and later BLAKE3 wiring) **must** obtain words **only** through these bits (or explicit permutations thereof)—**no** parallel “integer‑only” code path that skips bits for production witnesses.
- Unit tests **must** include **LE byte** cross‑checks (e.g. `0xAABBCCDD` vs `to_le_bytes()` per bit index).

---

### 3. Commitment-binding security — **Sovereign Digest** (not raw root, not simple mod)

**Rule:** Engine A’s public message **`m`** **must not** be:

- the raw Merkle **root**, or  
- **`root mod 2^{30}`**, or  
- any **simple modular reduction** of the root alone.

**Sovereign Digest (normative intent):** **`m`** is derived only after hashing the **full** cross‑engine binding input—see **§5** for the operational limb step.

---

### 4. Phase 0 — Merkle internal consistency (`merkle.rs`) — **mandatory bit‑path match**

Before **`recompute_root`** (or any hash chaining), **`merkle.rs` must**:

1. Treat **`leaf_index`** as defining a **bit path** in the binary tree: at each level **ℓ** (0…**depth−1**), whether the running node is the **left** or **right** child is **fixed** by **LE** decomposition of the index—use **`to_le_bits(leaf_index as u32)[ℓ]`** (for depth 7 and **`leaf_index < 128`**) to obtain the **mandatory** “acc on right” parity for that level, **or** an equivalent formulation **derived from the same LE bits** (no ad‑hoc `(idx&1)` without tying it to **`leaf_index`**’s bit path).
2. **Verify** that this **bit‑derived** parity sequence **matches** the **physical sibling orientation** at each level: i.e. the same left/right placement of **`acc`** vs **`sibling`** as **`verify_path_to_root`** in **`qssm-ms`** (when **`acc`** is on the right, **`leaf_index`**’s bit at that level **must** be **1**, and symmetrically for left / **0**).
3. On mismatch, return **`GadgetError::IndexMismatch`** and **abort**—**do not** hash upward.

Optional cross‑checks (e.g. Engine B **`k`**, **`bit_at_k`** with **`leaf_index == 2k + bit_at_k`**) are **recommended** and may produce **`IndexMismatch`** / **`MsOpeningMismatch`**.

---

### 5. Sovereign Digest — **hash root + context (+ metadata), then limb extraction**

This section replaces any notion of “take **`root % 2^{30}`**” or other **unhashed** truncation. **Limb extraction applies only to the digest of the full binding input.**

**Normative pipeline:**

1. **Compute**  
   **`SovereignDigest = H(domain_tag ‖ Root ‖ RollupContext ‖ ProofMetadata)`**  
   using the project’s **`hash_domain`** (or equivalent domain‑separated BLAKE3):  
   - **`Root`**: 32 B Merkle root (committed Engine B state).  
   - **`RollupContext`**: **`rollup_context_digest`** (32 B).  
   - **`ProofMetadata`**: fixed schema of Engine B fields required for non‑malleability (e.g. **`n`**, **`k`**, **`challenge`**, FS‑bound fields)—exact chunk order **fixed in code** and golden tests.

2. **Only then** extract **`m`**: take the **first 30 bits** of **`SovereignDigest`** under a **documented LE bit order** (e.g. low 30 bits of the first four bytes assembled consistently with **`to_le_bits`**) so **`0 ≤ m < 2^{30}`** for **`qssm-le`** **`PublicInstance`**.

3. **Security posture:** Pre‑hashing **binds** **`m`** to **root + rollup + metadata**, so **30‑bit** outputs are **not** raw root snippets—collision and malleability risk is reduced versus embedding or naïvely reducing the root.

**Forbidden in normative APIs:** **`m = root mod 2^{30}`**, **`m = truncate(root)`** without the **Sovereign Digest** step above.

---

## Sovereign integration path (end state)

1. **`qssm-gadget`** verifies Engine B where applicable (`qssm_ms::verify` / Merkle).
2. **Phase 0** enforces **leaf_index** ↔ **LE bit path** ↔ **sibling orientation** before any **`merkle_parent`** chain.
3. **Phase 1** (**`bits.rs`**) uses **degree‑2** XOR and **ripple** witnesses **from day one**—**always** with LE decomposition.
4. **`SovereignDigest`** (§3, §5) is computed; **30‑bit** **`m`** follows **only** from that digest.
5. Engine A lattice proof closes the statement.

```mermaid
flowchart LR
  MS[Engine B proof plus root]
  P0[Phase 0 bit path vs orientation]
  Bits[Phase 1 bits.rs witnesses]
  SD[Sovereign Digest then limb]
  LE[Engine A lattice proof]
  MS --> P0 --> Bits --> SD --> LE
```

---

## Phases (rewritten — no lazy staging)

| Phase | Focus | Exit criteria |
|-------|---------|----------------|
| **0** | **`merkle.rs`**: **mandatory** LE bit‑path vs **sibling orientation** per level; **`IndexMismatch`** if not; then **`recompute_root`**. | MS tests; tamper / wrong index negatives. |
| **1** | **`bits.rs`**: **`to_le_bits`**, **`constraint_xor` (\(x+y-2xy\))**, **`FullAdder`**, **`ripple_carry_adder`**, **`XorWitness`**, **`RippleCarryWitness`**, **`validate()`**—**one** phase, **day one**. | No `wrapping_add` on add witness API; LE byte tests. |
| **2** | **`blake3_native.rs`**: Merkle‑parent‑width / quarter‑round using **only** Phase 1 bit primitives. | Vectors vs **`blake3`** / **`hash_domain`**. |
| **3** | **`binding.rs`**: **§5** **Sovereign Digest**; **30‑bit** limb; **never** raw root or mod‑only **`m`**. | Golden vectors; **`PublicInstance::validate`**. |
| **4** | **R1CS IR / backend stub**; optional benches. | Feature‑gated. |

---

## Key files (rewritten)

| File | Responsibility |
|------|----------------|
| [`crates/qssm-gadget/Cargo.toml`](crates/qssm-gadget/Cargo.toml) | Crate manifest; `qssm-utils`, `thiserror`; `blake3` dev for vectors. |
| [`crates/qssm-gadget/src/lib.rs`](crates/qssm-gadget/src/lib.rs) | `bits`, `merkle`, `binding`, `error`; optional `blake3_native`. |
| [`crates/qssm-gadget/src/bits.rs`](crates/qssm-gadget/src/bits.rs) | Degree‑2 XOR, **`FullAdder`**, ripple + **`XorWitness` / `RippleCarryWitness`** from **day one**; LE only. |
| [`crates/qssm-gadget/src/merkle.rs`](crates/qssm-gadget/src/merkle.rs) | **Phase 0** LE path ↔ orientation; **`recompute_root`**. |
| [`crates/qssm-gadget/src/binding.rs`](crates/qssm-gadget/src/binding.rs) | **§5** **Sovereign Digest** → **30‑bit** **`m`**. |
| [`crates/qssm-gadget/src/blake3_native.rs`](crates/qssm-gadget/src/blake3_native.rs) | BLAKE3 using **`bits`** primitives only. |
| [`crates/qssm-gadget/src/error.rs`](crates/qssm-gadget/src/error.rs) | **`GadgetError`** variants. |
| [`crates/qssm-gadget/tests/`](crates/qssm-gadget/tests/) | MS + digest golden tests. |

---

## Workspace / crate layout (summary)

| Item | Notes |
|------|--------|
| Workspace | Add **`crates/qssm-gadget`** to root **`Cargo.toml`** `members`. |
| **`qssm-ref`** | Optional **`qssm-gadget`** when integration binaries need it. |

---

## Documentation sync

- Align [`blake3-lattice-gadget-spec.md`](./blake3-lattice-gadget-spec.md) §5.2 with **§5** here (Sovereign Digest before limb).
- This file is the **implementation** law; the spec is **design** normative.

---

## Implementation todos (aligned — no split “structs later”)

1. Scaffold **`qssm-gadget`** + workspace + **`error`**.  
2. **`merkle.rs`**: Phase 0 **LE bit path** vs **orientation**; **`recompute_root`**.  
3. **`bits.rs`**: **Phase 1 unified** — primitives **and** **`XorWitness` / `RippleCarryWitness` / `validate`** **together**.  
4. **`blake3_native.rs`** (Phase 2 table).  
5. **`binding.rs`**: **§5** Sovereign Digest + 30‑bit limb (Phase 3 table).  
6. R1CS stub (Phase 4) + benches + spec cross‑links.

---

## Updated text for Sections 2, 3, and 5 (verbatim blocks)

### Section 2 — Endianness safety (Little‑Endian bit decomposition)

**Strict rule:** **`bits[i]`** is the bit with weight **\(2^i\)** (**LSB at `i == 0`**). This matches **little‑endian** **`u32`** ↔ bytes and **must** stay **bit‑for‑bit** consistent with the **BLAKE3** reference’s 32‑bit word operations.

- **`to_le_bits` / `from_le_bits`** are the **only** canonical word↔bit serialization unless a docstring defines an exception.
- **Phase 1** **starts** with LE decomposition: every higher‑level gadget (**XOR witness**, ripple add, and later BLAKE3 wiring) **must** obtain words **only** through these bits (or explicit permutations thereof)—**no** parallel “integer‑only” code path that skips bits for production witnesses.
- Unit tests **must** include **LE byte** cross‑checks (e.g. `0xAABBCCDD` vs `to_le_bytes()` per bit index).

### Section 3 — Commitment-binding security — Sovereign Digest (not raw root, not simple mod)

**Rule:** Engine A’s public message **`m`** **must not** be the raw Merkle **root**, **`root mod 2^{30}`**, or any **simple modular reduction** of the root alone.

**Sovereign Digest (normative intent):** **`m`** is derived only after hashing the **full** cross‑engine binding input—see **§5** for the operational limb step.

### Section 5 — Sovereign Digest — hash root + context (+ metadata), then limb extraction

**Normative pipeline:**

1. **Compute** **`SovereignDigest = H(domain_tag ‖ Root ‖ RollupContext ‖ ProofMetadata)`** using domain‑separated hashing; chunk order **fixed** in code and tests.  
2. **Only then** extract **`m`**: **first 30 bits** of **`SovereignDigest`** under a **documented LE bit order** so **`0 ≤ m < 2^{30}`** for **`PublicInstance`**.  
3. **Forbidden:** **`m`** from raw root truncation or **mod‑only** reduction **without** this hash.

---