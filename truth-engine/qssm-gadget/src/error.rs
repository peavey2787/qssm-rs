//! Errors for `qssm-gadget`.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum GadgetError {
    #[error("leaf index {index} is out of range for tree width {width}")]
    LeafIndexOutOfRange { index: usize, width: usize },

    #[error("Merkle path length {got} does not match depth {expected} for width {width}")]
    PathLengthMismatch {
        got: usize,
        expected: usize,
        width: usize,
    },

    #[error("Phase 0: LE bit-path parity does not match sibling orientation at a Merkle level")]
    IndexMismatch,

    #[error("Engine B opening: leaf_index {leaf_index} != 2*k + bit_at_k (k={k}, bit={bit_at_k})")]
    MsOpeningMismatch {
        leaf_index: usize,
        k: u8,
        bit_at_k: u8,
    },

    #[error("BLAKE3: byte slice length {got} is not a multiple of 4 (expected {expected})")]
    Blake3ByteLengthMismatch { got: usize, expected: usize },

    #[error("BLAKE3: compression output slice too short for first_8_words (got {got}, need 8)")]
    Blake3SliceTooShort { got: usize },

    #[error("Merkle recompute_root: index {idx} should be 0 after traversing all levels")]
    MerkleTrailingIndex { idx: usize },

    #[error("TruthWitness validation failed: {reason}")]
    TruthWitnessInvalid { reason: &'static str },
}
