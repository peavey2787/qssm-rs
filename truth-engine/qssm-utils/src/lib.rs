//! Cryptographic utilities: versioned domain strings, BLAKE3, and Merkle trees.
#![forbid(unsafe_code)]

pub mod entropy_audit;
pub mod entropy_density;
pub mod entropy_stats;
pub mod hashing;
pub mod merkle;

pub use entropy_audit::{validate_entropy_full, EntropyAuditError};
pub use entropy_density::{verify_density, MIN_RAW_BYTES};
pub use entropy_stats::{validate_entropy_distribution, EntropyStatsError};
pub use hashing::{
    blake3_hash, hash_domain, DOMAIN_LE, DOMAIN_MERKLE_PARENT, DOMAIN_MS, DOMAIN_SDK_LE_MASK,
    DOMAIN_SDK_LE_WITNESS, DOMAIN_SDK_MS_SEED, LE_FS_PUBLIC_BINDING_LAYOUT_VERSION,
};
pub use merkle::{merkle_parent, MerkleError, PositionAwareTree};
