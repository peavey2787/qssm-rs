# qssm-gadget v1.0.0 — FROZEN

**Freeze date:** 2026-04-17
**Version:** 1.0.0
**Tag:** `qssm-gadget-v1.0.0-frozen`
**Status:** Locked for institutional use. No further changes without a new audit cycle.

---

## What this means

This crate is **frozen**. The code, the security checklist, and the audit artifact are
locked at this tag. Any modification to `truth-engine/qssm-gadget/` after the freeze tag
requires a new audit, a new tag, and a new build artifact.

## Invariants locked at freeze

| Invariant | Status |
|-----------|--------|
| All modules `pub(crate)` — facade only | Locked |
| `#![forbid(unsafe_code)]` crate-wide | Locked |
| All digest comparisons constant-time (`subtle::ConstantTimeEq`) | Locked |
| All secrets `Zeroize`/`ZeroizeOnDrop` with `[REDACTED]` Debug | Locked |
| All seam fields validated (8 all-zero + commitment recompute) | Locked |
| All trait methods return `Result` — no panics in production | Locked |
| All entropy validated (`validate_entropy_full`) | Locked |
| All transcripts canonical (compile-time layout version assert) | Locked |
| All domain separators unique and present | Locked |
| 99 tests passing (45 lib + 54 integration), 0 failures | Locked |
| Constraint counts pinned (regression gates) | Locked |
| 4 downstream crates compile clean | Locked |

## Audit artifacts

| Artifact | Location |
|----------|----------|
| Security checklist (all items [x]) | [`SECURITY_CHECKLIST.md`](SECURITY_CHECKLIST.md) |
| Reproducible build record | [`audit/qssm-gadget-build-2026-04-17.txt`](../../audit/qssm-gadget-build-2026-04-17.txt) |
| Crate source | `truth-engine/qssm-gadget/` at tag `qssm-gadget-v1.0.0-frozen` |

## Reproducibility

To reproduce the frozen build:

```sh
git checkout qssm-gadget-v1.0.0-frozen
cargo build -p qssm-gadget --release
# Compare SHA256 of target/release/deps/libqssm_gadget-*.rlib
# against the value in audit/qssm-gadget-build-2026-04-17.txt
```

## Scope

`qssm-gadget` is **internal machinery** — not a public API. All downstream consumers
import via the facade API (`truth-engine/api`). The crate provides:

- Degree-2 bit witnesses and BLAKE3 compression gadgets
- MS Merkle Phase 0 path verification (depth-7, 128-leaf tree)
- Truth digest binding and coefficient vector mapping
- Seam commit-then-open operator (Engine B → Engine A)
- Entropy injection with distribution validation
- R1CS IR emission for proving backends

## Dependencies (production)

| Crate | Version | Purpose |
|-------|---------|---------|
| `qssm-utils` | workspace | Hashing, BLAKE3, Merkle, entropy validation |
| `serde` | workspace | Serialization |
| `serde_json` | workspace | JSON transcript canonicalization |
| `subtle` | 2 | Constant-time equality for verifier-reachable paths |
| `thiserror` | workspace | Error type derivation |
| `zeroize` | 1 (derive) | Secret zeroization on drop |
| `hex` | workspace | Hex encoding |

## Contact

For audit inquiries, institutional licensing, or HSM integration questions,
contact the QSSM project maintainers.

---

**This crate is safe for institutional, bank-grade, and HSM-adjacent deployment.**
