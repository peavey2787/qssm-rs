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
  d_ms3c_sim_seed_announcement now sample latent ROM/transcript scalar coins
  via dmap duni_scalar while keeping the payload-facing projections fixed to
  the native public comparison surface on support. Real/sim index-shape are
  lemmata L_ms3c_{real,sim}_seed_index_shape_valid from ms3c_public_shape_ok
  plus support-local proved lemmas A_ms3c_{real,sim}_from_seed_uses_public_indices.
  Real/sim ann/share lengths are lemmata L_ms3c_{real,sim}_seed_length_shape_valid
  from support-local proved lemmas A_ms3c_{real,sim}_from_seed_uses_share_length.

  Phase-1 constructors (`ms3c_phase1_payload_from_public_input`) now flow through
  the structured seed surface: `ms3c_{real,sim}_payload_from_seed` reads the
  payload-facing fields from the seed records, and support-local lemmas show
  that every sampled seed still maps back to the same native public Phase-1
  payload image.
   `mscp_query_digest` is `ms_comparison_query_digest (ms3c_public_stmt_digest x)`
   on the announcement digest list from `ms3c_make_clause_surface` of the same
   Phase-1 carriers (see `A_ms3c_clause_surface_query_digest_constructed`). *)

require export ComparisonPayloadSeedTypes.
require export ComparisonPayloadFromSeed.
require export ComparisonPayloadSeedAnchors.
