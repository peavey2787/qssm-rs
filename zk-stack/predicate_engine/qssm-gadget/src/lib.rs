//! `qssm-gadget`: degree‑2 bit witnesses, MS Merkle Phase 0, BLAKE3 compress (Phase 5), Sovereign Digest limb (Engine B → A).
//!
//! Layout: **`primitives`** (bits, BLAKE3 kernels, entropy), **`lattice`** (handshake + predicates), **`circuit`** (R1CS, binding, **poly_ops**, templates), **`io`** (prover JSON).
//! Thin **`binding`**, **`bits`**, … modules re-export those layers for stable `qssm_gadget::binding::…` paths.
//! Normative plan: `docs/blake3-lattice-gadget-rust-plan.md` (workspace root).

#![forbid(unsafe_code)]

pub mod circuit;
pub mod io;
pub mod lattice;
pub mod primitives;

pub mod error;
pub mod merkle;

/// Stable `qssm_gadget::binding::…` path → [`circuit::binding`](crate::circuit::binding).
pub mod binding {
    pub use crate::circuit::binding::*;
}
/// Stable `qssm_gadget::bits::…` path.
pub mod bits {
    pub use crate::primitives::bits::*;
}
pub mod blake3_compress {
    pub use crate::primitives::blake3_compress::*;
}
pub mod blake3_native {
    pub use crate::primitives::blake3_native::*;
}
pub mod entropy {
    pub use crate::primitives::entropy::*;
}
pub mod lattice_bridge {
    pub use crate::lattice::lattice_bridge::*;
}
pub mod predicate {
    pub use crate::lattice::predicate::*;
}
/// Standard predicate scripts (Millionaire’s Duel, age gate, simple math, …).
pub mod predicate_templates {
    pub use crate::lattice::predicate_templates::*;
}
pub mod prover_json {
    pub use crate::io::prover_json::*;
}
pub mod r1cs {
    pub use crate::circuit::r1cs::*;
}
pub mod poly_ops {
    pub use crate::circuit::poly_ops::*;
}
pub mod template {
    pub use crate::circuit::template::*;
}

pub use binding::{
    digest_coeff_vector_from_sovereign_digest, encode_proof_metadata_v1, encode_proof_metadata_v2,
    message_limb_from_sovereign_digest_normative, sovereign_digest, sovereign_message_limb_v1,
    SovereignDigest, SovereignWitness, DIGEST_COEFF_VECTOR_SIZE, DOMAIN_SOVEREIGN_LIMB_V1,
    DOMAIN_SOVEREIGN_LIMB_V2,
};
pub use bits::{
    constraint_and, constraint_or, constraint_xor, from_le_bits, to_le_bits, FullAdder,
    RippleCarryWitness, XorWitness,
};
pub use blake3_compress::{
    hash_merkle_parent_witness, CompressionWitness, MerkleParentHashWitness, MSG_PERMUTATION,
    MSG_SCHEDULE, MSG_SCHEDULE_ROW,
};
pub use blake3_native::{
    bit_wire_rotate, g_function, Add32ChainedWitness, BitRotateWitness, GFunctionResult, GWitness,
    QuarterRoundWitness,
};
pub use entropy::{
    entropy_floor, fetch_nist_pulse, generate_sovereign_entropy,
    generate_sovereign_entropy_from_anchor, EntropyAnchor, EntropyProvider, DEFAULT_NIST_TIMEOUT,
    NIST_BEACON_LAST_PULSE_URL,
};
pub use error::GadgetError;
#[cfg(feature = "lattice-bridge")]
pub use lattice_bridge::verify_handshake_with_le;
pub use lattice_bridge::{
    limb_to_q_coeff0, verify_limb_binding_json, LatticeBridgeError, BRIDGE_Q, MAX_LIMB_EXCLUSIVE,
};
pub use merkle::{
    assert_ms_leaf_index_matches_opening, MerklePathWitness, MERKLE_DEPTH_MS, MERKLE_WIDTH_MS,
};
pub use poly_ops::{
    effective_sovereign_entropy, l2_merkle_sovereign_pipe,
    merkle_parent_hash_witness_to_prover_json_with_refresh,
    merkle_parent_hash_witness_value_with_refresh, BindingLabel, BindingPhase, BindingReservoir,
    CopyRefreshMeta, DegreeExceeded, EngineABindingInput, EngineABindingOp, EngineABindingOutput,
    EngineAPublicJson, EntropyInjectionOp, EntropyInjectionOutput, L2BuildOptions,
    L2HandshakeArtifacts,
    L2MerkleSovereignPipe, L2PipeOutput, LatticePolyOp, LatticePolyOpThen, MerkleParentBlake3Op,
    MerkleParentBlake3Output, Nomination, OpPipe, PolyOpContext, PolyOpError, PolyOpTracingCs,
    ProverPackageBuilder, PublicBindingContract, SovereignLimbV2Op, SovereignLimbV2Params,
    SovereignLimbV2Stage, StateRoot32, DEFAULT_REFRESH_PRESSURE_WARN_RATIO,
    TRANSCRIPT_MAP_LAYOUT_VERSION,
};
#[cfg(feature = "ms-engine-b")]
pub use poly_ops::{MsGhostMirrorInput, MsGhostMirrorOp, MsGhostMirrorOutput};
pub use predicate::{
    eval_all_predicates, eval_predicate, json_at_path, predicate_blocks_from_template_value, CmpOp,
    PredicateBlock, PredicateError,
};
pub use predicate_templates::{
    age_gate_kaspa_script, millionaires_duel_script, parametric_age_gate_vk,
    parametric_millionaires_duel_vk, parse_template_id_param, simple_math_script,
    standard_library_script,
};
pub use prover_json::{
    compression_private_wire_count, compression_witness_to_prover_json,
    merkle_parent_hash_witness_to_prover_json, merkle_parent_hash_witness_value,
    merkle_parent_private_wire_count, sovereign_private_wire_count, sovereign_witness_value,
};
pub use r1cs::{Blake3Gadget, ConstraintSystem, MockProver, R1csLineExporter, VarId, VarKind};
pub use template::{QssmTemplate, TemplateAnchorKind, QSSM_TEMPLATE_VERSION};
