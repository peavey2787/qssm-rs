# Hybrid Wrapper Schema v1 (Reflector Lite)

Status: Normative wrapper schema for proverless accumulation over existing `prover_package.json` outputs, designed for zero-rework migration to future IVC.

## 1. Goals

- Reuse current `prover_package.json` shape with no breaking changes.
- Ingest Engine A, Engine B, and seam artifacts into one deterministic step hash.
- Keep recursion out of the current 65k R1CS budget by doing wrapper accumulation off-circuit.
- Make `rollup_context_digest` the primary isolation key so cross-context mixing is impossible by construction.

## 2. Canonical StepEnvelope

`StepEnvelope` MUST include the exact current `prover_package.json` payload plus a wrapper extension block.

```json
{
  "prover_package": { "... current prover_package.json fields, unchanged ..." },
  "wrapper_v1": {
    "rollup_context_digest_hex": "0x...",
    "context_domain": "QSSM-WRAP-CONTEXT-v1",
    "step_index": 0,
    "ms_binding": {
      "ms_root_hex": "0x...",
      "ms_fs_v2_challenge_hex": "0x..."
    },
    "seam_binding": {
      "seam_commitment_digest_hex": "0x...",
      "seam_open_digest_hex": "0x...",
      "seam_binding_digest_hex": "0x..."
    },
    "engine_a_binding": {
      "engine_a_public_message_limb_u30": 0,
      "engine_a_public_digest_coeff_vector_u4": [0, 0, 0]
    },
    "artifact_hashes": {
      "sovereign_witness_json_blake3_hex": "0x...",
      "merkle_parent_witness_json_blake3_hex": "0x...",
      "r1cs_manifest_blake3_hex": "0x..."
    },
    "schema_version": "qssm-hybrid-wrapper-v1"
  }
}
```

### 2.1 `prover_package` mirror requirement

`prover_package` MUST preserve existing keys and semantics from `ProverPackageBuilder`:

- `package_version`
- `description`
- `sim_kaspa_parent_block_id_hex`
- `merkle_leaf_left_hex`
- `merkle_leaf_right_hex`
- `rollup_state_root_hex`
- `nist_beacon_included`
- `engine_a_public`
  - `message_limb_u30`
  - `digest_coeff_vector_u4` (when present in current transcript map)
- `artifacts`
- `witness_wire_counts`
- `r1cs`
- `poly_ops`
- `refresh_metadata`
- `warnings`

Wrapper implementations MUST NOT mutate meanings of these fields.

### 2.2 EngineABindingOutput fields in `StepEnvelope`

`wrapper_v1.seam_binding` MUST be populated from `EngineABindingOutput`:

- `seam_commitment_digest_hex` <- `EngineABindingOutput.seam_commitment_digest`
- `seam_open_digest_hex` <- `EngineABindingOutput.seam_open_digest`
- `seam_binding_digest_hex` <- `EngineABindingOutput.seam_binding_digest`

### 2.3 MsGhostMirror fields in `StepEnvelope`

`wrapper_v1.ms_binding` MUST include:

- `ms_root_hex` <- `MsGhostMirrorOutput.root`
- `ms_fs_v2_challenge_hex` <- `MsGhostMirrorOutput.fs_v2_challenge`

## 3. Canonical step hash (`step_i`)

`step_i` is defined as:

`BLAKE3( DOMAIN_STEP_V1 || canonical_bytes(StepEnvelope) )`

Where:

- `DOMAIN_STEP_V1 = "QSSM-WRAP-STEP-v1"`
- `canonical_bytes` uses stable JSON canonicalization:
  - UTF-8
  - lexicographically sorted object keys
  - arrays preserved in source order
  - lowercase hex with `0x` prefix for all digest/root fields

If canonicalization differs, step hashes are invalid.

## 4. Accumulator chain and checkpoints

## 4.1 Rolling chain

Define:

- `acc_-1 = BLAKE3("QSSM-WRAP-ACC-GENESIS-v1" || rollup_context_digest)`
- `acc_i = BLAKE3("QSSM-WRAP-ACC-v1" || rollup_context_digest || le_u64(step_index=i) || acc_{i-1} || step_i)`

This hard-binds every step to its context and index.

## 4.2 Checkpoint frequency

Default checkpoint interval:

- `checkpoint_every = 100` steps

Meaning a checkpoint is emitted at indices:

- 99, 199, 299, ...

`checkpoint_every` MAY be lowered for low-latency sessions but MUST be constant per context stream.

## 4.3 AccumulatorCheckpoint format

```json
{
  "schema_version": "qssm-hybrid-wrapper-v1",
  "rollup_context_digest_hex": "0x...",
  "context_domain": "QSSM-WRAP-CONTEXT-v1",
  "checkpoint_every": 100,
  "checkpoint_step_index": 199,
  "checkpoint_accumulator_hex": "0x...",
  "window_start_step_index": 100,
  "window_end_step_index": 199,
  "window_step_hashes_blake3_hex": "0x...",
  "created_unix_ms": 0
}
```

`window_step_hashes_blake3_hex` is:

`BLAKE3("QSSM-WRAP-WINDOW-v1" || step_100 || ... || step_199)`

This allows compact window integrity checks without full replay.

## 4.4 Storage format

For each `rollup_context_digest`, store:

1. `steps/<rollup_context_digest>.jsonl`  
   One canonical `StepEnvelope` JSON per line.
2. `checkpoints/<rollup_context_digest>.jsonl`  
   One `AccumulatorCheckpoint` per emitted checkpoint.

Writers MUST append-only; no in-place mutation.

## 5. Sovereign alignment and context isolation

`rollup_context_digest_hex` is the primary key for every wrapper record.

Rules:

1. A wrapper stream MUST contain exactly one context digest.
2. `step_i` and `acc_i` MUST both include the same digest in preimage.
3. A verifier MUST reject any chain where a step envelope digest differs from stream digest.
4. Cross-context merge is invalid even if all other fields match.

This prevents cross-context contamination (for example, Game vs Payment sessions).

## 6. Compiler-friendly shape (macro/decorator ready)

The wrapper is intentionally a two-layer contract:

- Layer A: existing `prover_package` mirror (stable source of truth)
- Layer B: `wrapper_v1` deterministic enrichment

This enables a future macro/decorator model:

- Rust derive macro on `StepEnvelope` for canonical bytes and `step_i`.
- JS decorator that injects `wrapper_v1` from runtime outputs and computes `step_i`/`acc_i`.

No business logic should rely on mutable maps; only canonicalized schema structs.

## 7. Verification algorithm (proverless)

Given a stream and checkpoints:

1. Parse each line to canonical `StepEnvelope`.
2. Verify `rollup_context_digest_hex` invariant on every record.
3. Recompute `step_i`.
4. Recompute rolling `acc_i`.
5. At checkpoint boundaries, verify `checkpoint_accumulator_hex` and `window_step_hashes_blake3_hex`.
6. For sampled steps, run native Engine B verify and Engine A verify against referenced artifacts.

If all pass, the wrapper chain is valid without recursive prover machinery.

## 8. Mechanical implementation contract (Rust + JS)

This section is normative for runtime implementers.

### 8.1 Canonical JSON is mandatory

Do not rely on `JSON.stringify` object insertion order in JavaScript engines.  
Do not rely on ad-hoc map ordering in Rust serializers.

`step_i` MUST be derived from RFC 8785 JCS canonical bytes.

Required libraries:

- Rust: `serde_jcs`
- JavaScript/TypeScript: `jcs` (or another RFC 8785 compliant implementation)

If a platform cannot produce RFC 8785 bytes, it is non-compliant for wrapper hashing.

### 8.2 Rust API sketch (`serde_jcs`)

```rust
use serde::{Deserialize, Serialize};
use blake3::Hasher;

const DOMAIN_STEP_V1: &[u8] = b"QSSM-WRAP-STEP-v1";
const DOMAIN_ACC_V1: &[u8] = b"QSSM-WRAP-ACC-v1";
const DOMAIN_ACC_GENESIS_V1: &[u8] = b"QSSM-WRAP-ACC-GENESIS-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepEnvelope {
    /// Strongly typed **`qssm-l2-handshake-v1`** mirror of `prover_package.json` (`qssm-wrapper::L2HandshakeProverPackageV1`).
    pub prover_package: L2HandshakeProverPackageV1,
    pub wrapper_v1: WrapperV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperV1 {
    pub rollup_context_digest_hex: String,
    pub context_domain: String,
    pub step_index: u64,
    pub ms_binding: MsBinding,
    pub seam_binding: SeamBinding,
    pub engine_a_binding: EngineABinding,
    pub artifact_hashes: ArtifactHashes,
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsBinding {
    pub ms_root_hex: String,
    pub ms_fs_v2_challenge_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeamBinding {
    pub seam_commitment_digest_hex: String,
    pub seam_open_digest_hex: String,
    pub seam_binding_digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineABinding {
    pub engine_a_public_message_limb_u30: u64,
    pub engine_a_public_digest_coeff_vector_u4: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactHashes {
    pub sovereign_witness_json_blake3_hex: String,
    pub merkle_parent_witness_json_blake3_hex: String,
    pub r1cs_manifest_blake3_hex: String,
}

pub fn canonical_step_bytes(step: &StepEnvelope) -> Result<Vec<u8>, serde_jcs::Error> {
    serde_jcs::to_vec(step)
}

pub fn step_hash(step: &StepEnvelope) -> Result<[u8; 32], serde_jcs::Error> {
    let canonical = canonical_step_bytes(step)?;
    let mut h = Hasher::new();
    h.update(DOMAIN_STEP_V1);
    h.update(&canonical);
    Ok(*h.finalize().as_bytes())
}

pub fn accumulator_genesis(rollup_context_digest: [u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_ACC_GENESIS_V1);
    h.update(&rollup_context_digest);
    *h.finalize().as_bytes()
}

pub fn accumulator_next(
    rollup_context_digest: [u8; 32],
    step_index: u64,
    prev_acc: [u8; 32],
    step_hash: [u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_ACC_V1);
    h.update(&rollup_context_digest);
    h.update(&step_index.to_le_bytes());
    h.update(&prev_acc);
    h.update(&step_hash);
    *h.finalize().as_bytes()
}
```

### 8.3 JS/TS decorator sketch (`jcs`)

```ts
import canonicalize from "jcs";
import { blake3 } from "@noble/hashes/blake3";

const DOMAIN_STEP_V1 = new TextEncoder().encode("QSSM-WRAP-STEP-v1");
const DOMAIN_ACC_V1 = new TextEncoder().encode("QSSM-WRAP-ACC-v1");
const DOMAIN_ACC_GENESIS_V1 = new TextEncoder().encode("QSSM-WRAP-ACC-GENESIS-v1");

export type StepEnvelope = {
  prover_package: Record<string, unknown>;
  wrapper_v1: {
    rollup_context_digest_hex: string;
    context_domain: string;
    step_index: number;
    ms_binding: {
      ms_root_hex: string;
      ms_fs_v2_challenge_hex: string;
    };
    seam_binding: {
      seam_commitment_digest_hex: string;
      seam_open_digest_hex: string;
      seam_binding_digest_hex: string;
    };
    engine_a_binding: {
      engine_a_public_message_limb_u30: number;
      engine_a_public_digest_coeff_vector_u4: number[];
    };
    artifact_hashes: {
      sovereign_witness_json_blake3_hex: string;
      merkle_parent_witness_json_blake3_hex: string;
      r1cs_manifest_blake3_hex: string;
    };
    schema_version: "qssm-hybrid-wrapper-v1";
  };
};

export function canonicalStepBytes(step: StepEnvelope): Uint8Array {
  const json = canonicalize(step); // RFC 8785 JCS canonical string
  return new TextEncoder().encode(json);
}

export function stepHash(step: StepEnvelope): Uint8Array {
  const bytes = canonicalStepBytes(step);
  const data = new Uint8Array(DOMAIN_STEP_V1.length + bytes.length);
  data.set(DOMAIN_STEP_V1, 0);
  data.set(bytes, DOMAIN_STEP_V1.length);
  return blake3(data);
}

export function accumulatorGenesis(rollupContextDigest: Uint8Array): Uint8Array {
  const data = new Uint8Array(DOMAIN_ACC_GENESIS_V1.length + rollupContextDigest.length);
  data.set(DOMAIN_ACC_GENESIS_V1, 0);
  data.set(rollupContextDigest, DOMAIN_ACC_GENESIS_V1.length);
  return blake3(data);
}

export function accumulatorNext(
  rollupContextDigest: Uint8Array,
  stepIndex: bigint,
  prevAcc: Uint8Array,
  stepHashBytes: Uint8Array
): Uint8Array {
  const idx = new Uint8Array(8);
  const view = new DataView(idx.buffer);
  view.setBigUint64(0, stepIndex, true); // little-endian

  const data = new Uint8Array(
    DOMAIN_ACC_V1.length + rollupContextDigest.length + idx.length + prevAcc.length + stepHashBytes.length
  );
  let off = 0;
  data.set(DOMAIN_ACC_V1, off); off += DOMAIN_ACC_V1.length;
  data.set(rollupContextDigest, off); off += rollupContextDigest.length;
  data.set(idx, off); off += idx.length;
  data.set(prevAcc, off); off += prevAcc.length;
  data.set(stepHashBytes, off);
  return blake3(data);
}
```

### 8.4 Cross-platform conformance tests (must-have)

Implementers MUST ship golden vectors:

1. Fixed `StepEnvelope` fixture JSON.
2. Canonical JCS bytes hex.
3. `step_i` hash hex.
4. `acc_0`, `acc_1`, `acc_99` hash hex.

Rust and JS pipelines must match all vectors byte-for-byte before deployment.

Golden vector fixture (for the canonical fixture in `qssm-wrapper` test):

- `rollup_context_digest_hex` = `0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- `acc_99` = `0xc7fb700b81891b4d7249ca2c0f2dd7cd2ebc76390fb4feed1576289d95e4f5c0`

### 8.5 Additional determinism constraints

- All digest fields MUST be lowercase hex with `0x` prefix.
- Numeric fields MUST be finite integers in their declared range (no float representations).
- Arrays MUST preserve original order (never sorted unless explicitly defined).
- Unknown extension fields MUST be namespaced under `wrapper_v1_ext` and included in canonical bytes only when the schema version explicitly allows them.
