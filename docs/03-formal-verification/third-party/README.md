# Third‑Party Dependencies

This directory contains the **formally‑pinned dependencies** required to build and
verify the QSSM / MS‑3a EasyCrypt stack.  
All dependencies are included in **two equivalent trust paths**:

---

## 1. Vendored upstream tarballs (reproducible builds)

The `.tar.gz` files in this directory are **unmodified, official upstream
releases** of:

- EasyCrypt
- Why3
- Z3
- CVC5
- Alt‑Ergo
- OCaml (compiler + stdlib)
- Supporting OCaml libraries

These tarballs are included **exactly as published by their authors**, with:

- original LICENSE files inside each archive  
- original COPYRIGHT / NOTICE files  
- original source code  
- no patches  
- no repackaging  

This guarantees:

- deterministic builds  
- offline installation  
- long‑term reproducibility  
- immunity to upstream version drift  
- stable CI environments  

The project’s build scripts use these tarballs by default.

---

## 2. Download‑from‑source scripts (independent verification)

For users who prefer to **verify provenance independently**, the repository also
provides scripts under: 

/docs/03-formal-verification/easycrypt/third-party

These scripts fetch the **same versions** directly from the official upstream
servers.

This path is useful if you:

- do not trust the vendored tarballs  
- want to re‑verify checksums  
- want to inspect upstream signatures  
- want to update to newer versions manually  

Both paths produce **identical build artifacts**.

---

## Why both paths exist

Formal‑verification toolchains are extremely sensitive to:

- solver version changes  
- OCaml version drift  
- Why3 driver changes  
- EasyCrypt API changes  

Providing both vendored tarballs **and** download scripts ensures:

- **Reproducibility** (tarballs)
- **Transparency** (download scripts)
- **Auditability** (upstream verification)
- **Longevity** (offline builds)
- **Trust flexibility** (users choose their trust anchor)

This mirrors the structure used by major FV projects such as CompCert,
EverCrypt/HACL\*, Jasmin, and seL4.

---

## Licensing

Each vendored dependency retains its **original license**, included inside the
tarball.  
The project’s own license applies **only** to QSSM source code and proofs.

No third‑party code is relicensed or modified.

---
