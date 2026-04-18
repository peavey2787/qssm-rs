//! Strongly typed **`qssm-sovereign-handshake-v1`** prover package types.
//!
//! All canonical types live in the `sovereign-types` crate (shared-libs).

// Re-export the canonical types from the shared crate.
pub use sovereign_types::{
    ProverPackageError, SovereignHandshakeProverPackageV1,
    SOVEREIGN_HANDSHAKE_PACKAGE_VERSION, SOVEREIGN_TRANSCRIPT_MAP_LAYOUT_VERSION,
    DIGEST_COEFF_VECTOR_LEN, DIGEST_COEFF_MAX, PROTOCOL_VERSION,
    ProverEngineAPublicV1, ProverArtifactsV1, WitnessWireCountsV1,
    R1csManifestSummaryV1, PolyOpsSummaryV1, ProverRefreshMetadataEntryV1,
    StepValidationError,
};
