qssm‑api — Security Checklist (Façade Edition)
Crate: qssm-api (Layer 6 — The Façade)
Revision: 3 (byte-array-only public surface)

Public Surface (Façade Contract)
[x] #![forbid(unsafe_code)] — crate‑wide

[x] Exactly 5 public functions — nothing else

compile(template_id: &str) -> Result<Vec<u8>, String>

commit(secret: &[u8], salt: &[u8; 32]) -> Vec<u8>

prove(secret: &[u8], salt: &[u8; 32], blueprint: &[u8]) -> Result<Vec<u8>, String>

verify(proof: &[u8], blueprint: &[u8]) -> bool

open(secret: &[u8], salt: &[u8; 32]) -> Vec<u8>

[x] Zero public types — no structs, enums, or traits exported

[x] No re‑exports of any kind from any engine crate

[x] All engine types (ProofContext, Proof, ProofBundle, ZkError, etc.) are completely invisible to consumers

[x] All data exchanged via byte arrays (Vec<u8> / &[u8]) and primitives (bool, String)

Architectural Purity (Façade Pattern)
[x] qssm-api contains no prover or verifier logic

[x] All 5 façade functions delegate internally to engine crates

[x] No Layer 1/2/3/4/5 types appear in the public API

[x] Engine crates remain fully internal:

qssm-le

qssm-ms

qssm-gadget

qssm-local-prover

qssm-local-verifier

qssm-entropy

qssm-utils

[x] Façade signatures are stable and human‑friendly

[x] Engine signatures are hidden and free to evolve

Error Handling
[x] compile() and prove() return Result<Vec<u8>, String> — never panic

[x] verify() returns bool — all internal errors collapse to false

[x] No public error types — internal ZkError is mapped to String

[x] No WireFormatError or engine error enums are public

Proof Artifact (Wire Format Encapsulation)
[x] The proof is an opaque byte array (Vec<u8>)

Developers cannot inspect or construct it manually

[x] The blueprint is an opaque byte array (Vec<u8>)

[x] Internally, proof encoding is:

versioned

validated

JSON-serialized (ProofBundle)

[x] All wire‑format validation happens inside engine crates

[x] No public JSON schema, hex fields, or polynomial counts

Security Model
[x] Façade holds no secrets beyond the lifetime of a call

[x] All secret handling occurs in engine crates

[x] No RNG implemented in façade — entropy is delegated to qssm-entropy

[x] Cross‑engine binding enforced internally

[x] Façade does not expose protocol version or internal constants

Secrets & Zeroization
[x] No public types exist — nothing for consumers to mishandle

[x] All zeroization guarantees live in engine crates (ProofContext uses ZeroizeOnDrop)

[x] Façade does not persist secrets beyond the lifetime of a call; long‑lived secret handling is in engine crates

[x] Blueprint byte array contains seed material — consumers are responsible for protecting it at rest

Test Coverage
[x] Unit tests for the 5 façade functions

[x] compile() returns Err for unknown templates

[x] commit/open round-trip via == comparison

[x] Proof byte array round-trips through prove → verify

[x] No engine types leak into public API — there are no public types at all

Dependencies (Façade Only)
Crate	Purpose
qssm-local-prover	Internal proof generation + wire format
qssm-local-verifier	Internal verification
qssm-templates	Internal predicate templates
qssm-entropy	Internal hardware entropy harvesting
qssm-utils	Internal hashing utilities
serde	Internal serialization
serde_json	Internal JSON handling
hex	Internal hex encoding for wire format
None of these are re‑exported. qssm-api does NOT depend on qssm-le, qssm-ms, or qssm-gadget.

Final Certification
[x] Public API surface = exactly 5 functions + byte arrays

[x] Zero public types

[x] No re‑exports

[x] No engine types exposed

[x] Proof artifact is an opaque byte array

[x] All engine logic internal

[x] Façade is stable, sealed, and safe