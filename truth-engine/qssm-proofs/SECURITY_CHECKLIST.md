# Security Checklist — qssm-proofs

| # | Claim | Struct | Test | Bits | Status |
|---|-------|--------|------|------|--------|
| 1 | MSIS perfectly binding (rank-1) | `MsisBound` | `msis_bound_perfectly_binding_for_current_params` | ∞ | Pass |
| 2 | FS soundness (ROM) | `FsReductionBound` | `fs_reduction_challenge_space` | 258.8 | Pass |
| 3 | LE composed soundness | `LeCommitmentSoundnessTheorem` | `le_commitment_soundness_meets_128` | 258.8 | Pass |
| 4 | Extraction (special soundness) | `LyubashevskyExtractionClaim` | `extraction_knowledge_error_below_neg128` | 322.8 | Pass |
| 5 | Witness-hiding gap ratio | `WitnessHidingClaim` | `witness_hiding_gap_ratio` | — | Pass |
| 6 | HVZK NOT met | `RejectionSamplingClaim` | `hvzk_not_met` | — | Pass |
| 7 | Rejection abort probability | `RejectionSamplingClaim` | `abort_probability_is_positive` | — | Pass |
| 8 | BLAKE3 binding (birthday) | `Blake3BindingReduction` | `binding_advantage_below_neg128` | 129 | Pass |
| 9 | MS soundness | `MsSoundnessClaim` | `ms_soundness_below_neg_112` | 248 | Pass |
| 10 | Security estimate ≥ 128 | `SecurityEstimate` | `security_estimate_for_current_params` | 258.8 | Pass |
| 11 | CI floor 112 bits | `system_audit()` | `ci_security_floor_112_bits` | 258.8 | Pass |
| 12 | Parameter drift guardrail | — | `tests/parameter_sync.rs` (11 tests) | — | Pass |
| 13 | Serialization round-trip | all claim structs | `all_claims_serialize_roundtrip` | — | Pass |
