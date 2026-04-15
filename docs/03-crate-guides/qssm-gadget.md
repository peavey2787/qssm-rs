### Documentation map

* [README](../../README.md) — Project home
* [Crates overview](../01-architecture/crates-overview.md)
* [QSSM-HE crate guide](./heart-he.md) (hardware entropy path)
* **This document** — `qssm-gadget`: Phase 8 floor/beacon and related gadgets

---

# `qssm-gadget` — entropy mixing and Phase 8 beaconing

Crate: `crates/qssm-gadget`. Module layout in `src/lib.rs`.

## Role

BLAKE3-heavy **gadgets** for templates, predicates, sovereign digest binding, optional **lattice bridge** (`lattice-bridge` feature → `qssm-le`), Merkle/R1CS helpers — and **`entropy`**: Phase 8 **opportunistic** mixing of a **32-byte anchor leg**, **32 bytes of local** material, and an optional **NIST Randomness Beacon** pulse.

> **Scope:** This crate does **not** implement raw hardware harvest; that lives in **`qssm-he`** (see [heart-he.md](./heart-he.md)).

## Phase 8 entropy module (`src/primitives/entropy.rs` via `src/lib.rs` re-export `qssm_gadget::entropy`)

### Anchor leg

**`EntropyAnchor`** (enum):

- `KaspaParentBlockHash([u8; 32])` / `StaticRoot([u8; 32])` — leg is the 32 bytes as-is.
- `TimestampUnixSecs { unix_secs }` — leg = `blake3_hash` of tagged 8-byte LE encoding (domain prefix `QSSM-ENTROPY-ANCHOR-TIMESTAMP-v1` + bytes).

**`entropy_leg()`** returns the 32-byte leg for mixing.

### Floor (no HTTP)

**`entropy_floor(anchor_leg, local_bytes)`** = **`blake3_hash`** of **64** bytes: `anchor_leg ‖ local_bytes`.

### NIST beacon

- **URL constant:** `NIST_BEACON_LAST_PULSE_URL` = `https://beacon.nist.gov/beacon/2.0/pulse/last`
- **Default HTTP timeout:** `DEFAULT_NIST_TIMEOUT` = **500 ms** (`ureq`)
- **`fetch_nist_pulse(timeout)`**: GET on 200 OK, JSON parse, read **`pulse.outputValue`** hex, take **first 32 bytes** of decoded hex (`hex` crate). Any failure → `None`.

### `EntropyProvider`

- Fields: `nist_timeout`, `nist_disabled`, `nist_pulse_override`
- **`generate_sovereign_entropy_from_anchor`**: computes `floor`; if NIST disabled → return `(floor, false)`. Else pulse from override or **`fetch_nist_pulse`**; if `Some(p)` → **`final = xor32(floor, p)`** and `(final, true)`; else **`(floor, false)`**.
- Convenience: **`generate_sovereign_entropy(kaspa_hash, local_bytes)`** uses `KaspaParentBlockHash`.

### Free functions

`generate_sovereign_entropy`, `generate_sovereign_entropy_from_anchor` delegate to **`EntropyProvider::default()`**.

## Other public modules (summary)

Re-exports in `lib.rs` include: **`binding`** (sovereign digest / witness), **`predicate`** (`eval_predicate`, …), **`template`**, **`merkle`** (MS Merkle depth constants), **`blake3_compress`**, **`blake3_native`**, **`lattice_bridge`** (feature-gated `verify_handshake_with_le`), **`r1cs`**, **`prover_json`**.

## Features

- **`lattice-bridge`**: optional dependency on `qssm-le` for handshake verification in `lattice_bridge.rs`.

## Consumers

`qssm-desktop` depends on `qssm-gadget` with **`lattice-bridge`** enabled (`crates/qssm-desktop/src-tauri/Cargo.toml`).
