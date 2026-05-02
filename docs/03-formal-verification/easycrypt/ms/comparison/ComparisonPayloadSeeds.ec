(* MS-3c payload seed bundle (facade): component seed laws, Phase-1 from_seed,
   anchor lemmas, and comparison payload / schedule distributions.

   Logical modules:
   - ComparisonPayloadSeedTypes — component seed laws d_ms3c real/sim challenge and
     announcement, joint d_ms3c real/sim payload_seed, losslessness lemmata.
   - ComparisonPayloadFromSeed — ms3c_phase1_payload_from_public_input,
     ms3c_{real,sim}_payload_from_seed, d_ms3c_{real,sim}_comparison_payload,
     L_ms3c_cross_support_real_sim_payload_equal, schedule/surface ops,
     ms_comparison_exact_simulation_equiv.
   - ComparisonPayloadSeedAnchors — from_seed public-index and share-length anchors
     and index/length shape lemmata (A_ms3c_{real,sim}_from_seed_uses_*,
     L_ms3c_{real,sim}_seed_{index,length}_shape_valid).

   Discharge path: all four component laws d_ms3c_real_seed_challenge,
   d_ms3c_sim_seed_challenge, d_ms3c_real_seed_announcement, and
   d_ms3c_sim_seed_announcement are dunit tt on unit with proved losslessness
   lemmata (Phase-1 scaffolding; not final ROM, FS, or Schnorr announcement
   samplers). Real/sim index-shape are lemmata L_ms3c_{real,sim}_seed_index_shape_valid
   from ms3c_public_shape_ok (placeholder public ops) plus proved
   A_ms3c_{real,sim}_from_seed_uses_public_indices. Real/sim ann/share lengths are
   lemmata L_ms3c_{real,sim}_seed_length_shape_valid from proved
   A_ms3c_{real,sim}_from_seed_uses_share_length.

   Phase-1 constructors (`ms3c_phase1_payload_from_public_input`) are deterministic
   in the seed (`unit` carriers): indices and false-branch list lengths follow
   `ms3c_public_false_clause_indices x`; per-branch announcements/shares/digests
   are `witness` scaffolding only — not final Schnorr/ROM/transcript semantics.
   `mscp_query_digest` is `ms_comparison_query_digest (ms3c_public_stmt_digest x)`
   on the announcement digest list from `ms3c_make_clause_surface` of the same
   Phase-1 carriers (see `A_ms3c_clause_surface_query_digest_constructed`). *)

require export ComparisonPayloadSeedTypes.
require export ComparisonPayloadFromSeed.
require export ComparisonPayloadSeedAnchors.
