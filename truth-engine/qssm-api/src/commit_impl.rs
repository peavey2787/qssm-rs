//! Internal commit/open helpers for the façade.

use qssm_utils::hashing::hash_domain;

/// Domain tag for the commit/open scheme.
const DOMAIN_COMMIT: &str = "QSSM-COMMIT-v1";

/// Compute the commitment hash: `BLAKE3("QSSM-COMMIT-v1" ‖ secret ‖ salt)`.
pub(crate) fn commit_hash(secret: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    hash_domain(DOMAIN_COMMIT, &[secret, salt.as_slice()])
}
