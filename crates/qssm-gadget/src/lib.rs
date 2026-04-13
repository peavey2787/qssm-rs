//! `qssm-gadget`: degree‑2 bit witnesses, MS Merkle Phase 0, Sovereign Digest limb (Engine B → A).
//!
//! Normative plan: `docs/blake3-lattice-gadget-rust-plan.md` (workspace root).

#![forbid(unsafe_code)]

pub mod binding;
pub mod bits;
pub mod blake3_native;
pub mod error;
pub mod merkle;
pub mod r1cs;

pub use binding::{
    encode_proof_metadata_v1, message_limb_from_sovereign_digest_normative, sovereign_digest,
    sovereign_message_limb_v1, SovereignDigest, SovereignWitness, DOMAIN_SOVEREIGN_LIMB_V1,
};
pub use blake3_native::{
    bit_wire_rotate, g_function, Add32ChainedWitness, BitRotateWitness, GFunctionResult, GWitness,
    QuarterRoundWitness,
};
pub use bits::{
    constraint_and, constraint_or, constraint_xor, from_le_bits, to_le_bits, FullAdder,
    RippleCarryWitness, XorWitness,
};
pub use error::GadgetError;
pub use merkle::{
    assert_ms_leaf_index_matches_opening, MerklePathWitness, MERKLE_DEPTH_MS, MERKLE_WIDTH_MS,
};
pub use r1cs::{Blake3Gadget, ConstraintSystem, MockProver, VarId, VarKind};
