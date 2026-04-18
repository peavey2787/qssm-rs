//! Lattice bridge math for lifting truth limbs into Engine A.

mod lattice_bridge;

pub use lattice_bridge::{limb_to_q_coeff0, LatticeBridgeError, BRIDGE_Q, MAX_LIMB_EXCLUSIVE};
