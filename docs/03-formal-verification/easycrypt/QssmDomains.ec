require import AllCore.

(* Domains from docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md *)
(* DOMAIN_MS matches truth-engine/qssm-utils/src/hashing.rs *)
op DOMAIN_ZK_SIM : string = "QSSM-ZK-SIM-v1.0".
op DOMAIN_MS : string = "QSSM-MS-v1.0".

op DOMAIN_LE_FS : string = "QSSM-LE-FS-LYU-v1.0".
op DOMAIN_LE_CHALLENGE_POLY : string = "QSSM-LE-CHALLENGE-POLY-v1.0".

op DOMAIN_SEAM_MS_V2_COMMIT : string = "QSSM-SEAM-MS-V2-COMMIT-v1".
op DOMAIN_SEAM_MS_V2_OPEN : string = "QSSM-SEAM-MS-V2-OPEN-v1".
op DOMAIN_SEAM_MS_V2_BINDING : string = "QSSM-SEAM-MS-V2-BINDING-v1".

(* Global simulator seed labels *)
op LABEL_QSSM_GLOBAL_SIM_MS_SEED : string = "qssm_global_sim_ms_seed".
op LABEL_QSSM_GLOBAL_SIM_LE_SEED : string = "qssm_global_sim_le_seed".

(* LE simulator labels *)
op LABEL_LE_GLOBAL_SIM_COMMITMENT_SHORT : string = "le_global_sim_commitment_short".
op LABEL_LE_GLOBAL_SIM_Z : string = "le_global_sim_z".
op LABEL_LE_GLOBAL_SIM_CHALLENGE_SEED : string = "le_global_sim_challenge_seed".
op LABEL_LE_PROGRAMMED_QUERY_DIGEST : string = "le_programmed_query_digest".

(* LE FS tags *)
op LABEL_CROSS_PROTOCOL_DIGEST_V1 : string = "cross_protocol_digest_v1".
op LABEL_FS_V2 : string = "fs_v2".
op LABEL_DST_LE_COMMIT : string = "QSSM-LE-V1-COMMIT...............". (* 32 bytes *)
op LABEL_DST_MS_VERIFY : string = "QSSM-MS-V1-VERIFY...............". (* 32 bytes *)

(* MS v2 labels *)
op LABEL_MS_V2_STATEMENT : string = "predicate_only_v2_statement".
op LABEL_MS_V2_BITNESS_QUERY : string = "predicate_only_v2_bitness_query".
op LABEL_MS_V2_COMPARISON_QUERY : string = "predicate_only_v2_comparison_query".
op LABEL_MS_V2_QUERY_SCALAR : string = "predicate_only_v2_query_scalar".
op LABEL_MS_V2_PROOF : string = "predicate_only_v2_proof".
