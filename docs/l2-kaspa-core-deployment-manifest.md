# Kaspa L2 core — deployment file manifest

Copy the following from the **qssm-rs** workspace to bootstrap a new Kaspa-anchored L2 that reuses the **QSSM gadget** stack (Merkle parent BLAKE3 witness, Sovereign Digest limb, R1CS manifest, Engine A handoff).

## Required crate (library)

| Path | Role |
|------|------|
| [`crates/qssm-gadget/`](../crates/qssm-gadget/) | Entire crate: `bits`, `blake3_native`, `blake3_compress`, `binding`, `merkle`, `r1cs`, `prover_json`, `error`. |
| [`crates/qssm-gadget/Cargo.toml`](../crates/qssm-gadget/Cargo.toml) | Manifest (depends on `qssm-utils`, `serde`, `serde_json`, `hex`, `thiserror`). |

## Required dependency crate

| Path | Role |
|------|------|
| [`crates/qssm-utils/`](../crates/qssm-utils/) | `hash_domain`, `merkle_parent`, `DOMAIN_MERKLE_PARENT`, `DOMAIN_MSSQ_ROLLUP_CONTEXT`, `blake3_hash`, etc. |
| [`crates/qssm-utils/Cargo.toml`](../crates/qssm-utils/Cargo.toml) | Manifest (`blake3`). |

## Workspace / versions

| File | Role |
|------|------|
| Root [`Cargo.toml`](../Cargo.toml) | Workspace `members` entry for `crates/qssm-gadget` and `crates/qssm-utils`; `[workspace.dependencies]` entries used by the gadget: `blake3`, `hex`, `serde`, `serde_json`, `thiserror`. |

## Normative docs (recommended)

| File | Role |
|------|------|
| [`docs/blake3-lattice-gadget-rust-plan.md`](./blake3-lattice-gadget-rust-plan.md) | Implementation law (phases, Merkle + Sovereign + R1CS). |
| [`docs/blake3-lattice-gadget-spec.md`](./blake3-lattice-gadget-spec.md) | Design spec cross-link. |
| This file | Copy list for L2 teams. |

## Reference example (optional but useful)

| Path | Role |
|------|------|
| [`crates/qssm-gadget/examples/l2_handshake.rs`](../crates/qssm-gadget/examples/l2_handshake.rs) | End-to-end: simulated Kaspa block id → `merkle_parent` witness → `SovereignWitness` → **`prover_package.json`**, **`sovereign_witness.json`**, **`merkle_parent_witness.json`**, **`r1cs_merkle_parent.manifest.txt`**. Runs on a **32 MiB** worker thread stack (large compress + JSON). Command: `cargo run -p qssm-gadget --example l2_handshake`. |

## Engine A (lattice) — not in this repo

You still need your **LE / lattice** proving stack (e.g. `qssm-le` or replacement) that consumes:

- **`message_limb_u30`** from the sovereign JSON, and  
- Optional ingestion of **`r1cs_merkle_parent.manifest.txt`** / full witness JSON per your prover backend.

## Minimum new-workspace `members`

At least:

```toml
[workspace]
members = ["crates/qssm-utils", "crates/qssm-gadget"]
resolver = "2"

[workspace.dependencies]
blake3 = "1.5"
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1.0"
```

Then add your L2 application crate with `qssm-gadget = { path = "../qssm-gadget" }` (or equivalent).
