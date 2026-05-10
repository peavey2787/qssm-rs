//! `qssm-gadget`: degree-2 bit witnesses, MS Merkle Phase 0, BLAKE3 compression, truth binding, and seam operators.
//!
//! **Internal crate — do not use directly.** Use the facade API (`truth-engine/api`) instead.
//! Workspace-internal sibling crates may depend on the `#[doc(hidden)]` plumbing surface,
//! but external consumers must not rely on any hidden symbol.
//!
//! Layout: **`primitives`** (bits, BLAKE3 kernels, entropy), **`lattice`** (bridge math),
//! **`circuit`** (R1CS, binding, seam operators).

#![forbid(unsafe_code)]
#![allow(
    dead_code,
    unused_imports,
    clippy::needless_range_loop,
    clippy::manual_is_multiple_of,
    clippy::too_many_arguments,
    clippy::needless_bool,
    clippy::match_like_matches_macro,
    clippy::double_must_use
)]

pub(crate) mod circuit;
pub(crate) mod lattice;
pub(crate) mod primitives;

pub(crate) mod error;
pub(crate) mod merkle;

// ── Facade re-exports (stable public surface) ─────────────────────────────

// circuit::binding
pub use circuit::binding::{
    digest_coeff_vector_from_truth_digest, encode_proof_metadata_v2,
    message_limb_from_truth_digest_normative, truth_digest, TruthWitness, DIGEST_COEFF_VECTOR_SIZE,
    DOMAIN_TRUTH_LIMB_V2,
};

// circuit::binding_ms_v2 (MS v2 predicate-only → LE; no v1 coordinates)
pub use circuit::binding_ms_v2::{
    digest_bitness_global_challenges_v2, encode_ms_v2_truth_metadata,
    encode_ms_v2_truth_metadata_from_statement_proof, truth_digest_ms_v2, TruthWitnessMsV2,
    DOMAIN_TRUTH_LIMB_MS_V2, MS_V2_TRUTH_METADATA_LEN,
};

// circuit::binding_contract
pub use circuit::binding_contract::{
    BindingLabel, BindingPhase, BindingReservoir, Nomination, PublicBindingContract,
};

// circuit::context
pub use circuit::context::{
    CopyRefreshMeta, PolyOpContext, PolyOpError, DEFAULT_REFRESH_PRESSURE_WARN_RATIO,
};

// circuit::handshake
pub use circuit::handshake::{
    EngineAPublicJson, MerkleParentBlake3Output, StateRoot32, TruthPipeOutput,
    TRANSCRIPT_MAP_LAYOUT_VERSION,
};

// circuit::lattice_polyop
pub use circuit::lattice_polyop::{LatticePolyOp, LatticePolyOpThen, OpPipe};

// circuit::operators
pub use circuit::operators::truth_limb::{effective_external_entropy, xor32};
pub use circuit::operators::{
    merkle_truth_pipe, EngineABindingInput, EngineABindingOp, EngineABindingOutput,
    EntropyInjectionOp, EntropyInjectionOutput, MerkleParentBlake3Op, MerkleTruthPipe,
    TruthLimbV2Params, TruthLimbV2Stage,
};

// circuit::operators::ms_predicate_v2_bridge
pub use circuit::operators::ms_predicate_v2_bridge::{
    MsPredicateOnlyV2BridgeInput, MsPredicateOnlyV2BridgeOp, MsPredicateOnlyV2BridgeOutput,
};

// primitives::entropy
pub use primitives::entropy::EntropyAnchor;

// merkle
pub use merkle::{
    assert_ms_leaf_index_matches_opening, MerklePathWitness, MERKLE_DEPTH_MS, MERKLE_WIDTH_MS,
};

// error
pub use error::GadgetError;

// ── Internal plumbing (do not depend on — subject to change) ──────────────
// Exported for truth-engine sibling crates and integration tests only.
//
// SECURITY-CONCESSION: These symbols are `#[doc(hidden)]` but technically `pub`.
// Rust lacks `pub(workspace)` visibility. Only sibling-crate `#[cfg(test)]` blocks
// depend on them (e.g. `package_builder.rs`, `ms_verifier.rs`, unit_tests/*.rs`).
// External consumers must not rely on any hidden symbol — the facade API
// (`truth-engine/api`) is the only supported entry point.
// Audited 2026-04-17: no downstream production code imports these.

#[doc(hidden)]
pub use circuit::r1cs::{Blake3Gadget, ConstraintSystem, VarId, VarKind};

#[doc(hidden)]
pub use circuit::cs_tracing::PolyOpTracingCs;

#[doc(hidden)]
pub use primitives::blake3_compress::{hash_merkle_parent_witness, MerkleParentHashWitness};
