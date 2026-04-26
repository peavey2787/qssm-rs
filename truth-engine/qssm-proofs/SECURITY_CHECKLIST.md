# Security Checklist — qssm-proofs

| # | Claim | Struct | Test | Bits | Status |
|---|-------|--------|------|------|--------|
| 1 | Parameter authority in `qssm_le::protocol::params` | Set B constants | `tests/parameter_sync.rs` | — | Required |
| 2 | Set B support containment | `LeHvzkConstraintAnalysis` | `set_b_parameter_invariants_match_encoded_formula` | — | Required |
| 3 | ZK FS floor under Set B | `LeHvzkConstraintAnalysis` | `set_b_parameter_invariants_match_encoded_formula` | 132.2 | Required |
| 4 | Soundness floor | `MsSoundnessClaim` | `ms_soundness_below_neg_112` | 121 | Required |
| 5 | Composed theorem closure | `ClosedZkTheorem` | `proof_closure_checker_*` tests | — | Required |
| 6 | Audit checklist passes | `run_audit_validation` | `audit_validation_returns_passing_checklist` | — | Required |
| 7 | Simulator witness isolation contract | `GlobalQssmSimulator` | `adversarial_simulator_witness_leak_detected_by_checklist` | — | Required |
| 8 | LE simulation single core path | `simulate_le_core` wrappers | `le_global_simulation_matches_baseline_transcript_bytes_on_fixed_seed` | — | Required |
| 9 | Canonical nested ZK source layout | `reduction_zk/{core,simulate,transcript,audit,tests}` | `cargo check -p qssm-proofs --all-targets` | — | Required |
