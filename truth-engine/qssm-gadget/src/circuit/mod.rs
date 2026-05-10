//! R1CS / truth digest binding and verification templates (gadget math, not codecs).

pub mod binding;
pub mod binding_contract;
pub mod binding_ms_v2;
pub mod context;
pub mod cs_tracing;
pub mod handshake;
pub mod lattice_polyop;
pub mod operators;
pub mod r1cs;

#[cfg(test)]
mod poly_ops_tests;
