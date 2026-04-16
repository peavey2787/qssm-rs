//! Errors for `qssm-gadget`.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
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
}
