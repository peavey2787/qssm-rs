//! Benchmark target and constant synchronization helpers.

use qssm_le::{N, Q};
use qssm_utils::hashing::DOMAIN_MERKLE_PARENT;

/// Current verification latency target language for docs and benchmarking.
pub const VERIFY_TARGET_LABEL: &str = "sub-1ms verification";
/// Hard cap representation used in benchmark reports.
pub const VERIFY_TARGET_MAX_MS: f64 = 1.0;

#[derive(Debug, Clone, PartialEq)]
pub struct VerificationBenchmarkRecord {
    pub bench_name: String,
    pub verify_ms: f64,
    pub r1cs_constraints: u64,
    pub proof_bytes: usize,
}

impl VerificationBenchmarkRecord {
    #[must_use]
    pub fn meets_sub_1ms_target(&self) -> bool {
        self.verify_ms < VERIFY_TARGET_MAX_MS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncedParameters {
    pub n: usize,
    pub q: u32,
    pub domain_merkle_parent: &'static str,
}

#[must_use]
pub fn synced_parameters() -> SyncedParameters {
    SyncedParameters {
        n: N,
        q: Q,
        domain_merkle_parent: DOMAIN_MERKLE_PARENT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synced_constants_match_expected_regime() {
        let p = synced_parameters();
        assert_eq!(p.n, 256);
        assert_eq!(p.q, 8_380_417);
        assert_eq!(p.domain_merkle_parent, "QSSM-MERKLE-PARENT-v1.0");
    }

    #[test]
    fn sub_1ms_target_check_works() {
        let ok = VerificationBenchmarkRecord {
            bench_name: "verify_lattice".into(),
            verify_ms: 0.88,
            r1cs_constraints: 65_184,
            proof_bytes: 2_080,
        };
        let slow = VerificationBenchmarkRecord {
            verify_ms: 1.01,
            ..ok.clone()
        };
        assert!(ok.meets_sub_1ms_target());
        assert!(!slow.meets_sub_1ms_target());
    }
}
