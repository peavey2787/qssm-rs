require import AllCore.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests.

(* MS-3c seed component types (challenge vs announcement material).
   ms3c_real_seed_challenge is intentionally unit for now: the real comparison
   challenge-side randomness (FS scalars, digests, share splits) will move into
   this carrier when transcript wiring lands; the law is dunit on unit (see
   ComparisonPayloadSeeds.ec) so losslessness is proved without axioms.
   Remaining seed component types stay abstract until the same refinement pass. *)
type ms3c_real_seed_challenge = unit.
type ms3c_real_seed_announcement.
type ms3c_sim_seed_challenge.
type ms3c_sim_seed_announcement.

type ms3c_real_payload_seed = (ms3c_real_seed_challenge * ms3c_real_seed_announcement).
type ms3c_sim_payload_seed = (ms3c_sim_seed_challenge * ms3c_sim_seed_announcement).
