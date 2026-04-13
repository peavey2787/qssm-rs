//! `qssm-gadget`: degree‑2 bit witnesses, MS Merkle Phase 0, BLAKE3 compress (Phase 5), Sovereign Digest limb (Engine B → A).
//!
//! Normative plan: `docs/blake3-lattice-gadget-rust-plan.md` (workspace root).

#![forbid(unsafe_code)]

pub mod binding;
pub mod bits;
pub mod blake3_compress;
pub mod blake3_native;
pub mod error;
pub mod lattice_bridge;
pub mod merkle;
pub mod prover_json;
pub mod r1cs;

pub use binding::{
    encode_proof_metadata_v1, message_limb_from_sovereign_digest_normative, sovereign_digest,
    sovereign_message_limb_v1, SovereignDigest, SovereignWitness, DOMAIN_SOVEREIGN_LIMB_V1,
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
pub use error::GadgetError;
#[cfg(feature = "lattice-bridge")]
pub use lattice_bridge::verify_handshake_with_le;
pub use lattice_bridge::{
    limb_to_q_coeff0, verify_limb_binding_json, LatticeBridgeError, BRIDGE_Q, MAX_LIMB_EXCLUSIVE,
};
pub use merkle::{
    assert_ms_leaf_index_matches_opening, MerklePathWitness, MERKLE_DEPTH_MS, MERKLE_WIDTH_MS,
};
pub use prover_json::{
    compression_private_wire_count, merkle_parent_hash_witness_value,
    merkle_parent_private_wire_count, sovereign_private_wire_count, sovereign_witness_value,
};
pub use r1cs::{Blake3Gadget, ConstraintSystem, MockProver, R1csLineExporter, VarId, VarKind};
