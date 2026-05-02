require import AllCore.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests.

(* MS-3c seed component types (challenge vs announcement material).
   ms3c_real_seed_challenge and ms3c_sim_seed_challenge are intentionally unit for
   now: challenge-side randomness for real and sim will move into richer carriers
   when transcript and ROM wiring land; laws are dunit on unit (see
   ComparisonPayloadSeeds.ec) so losslessness is proved without axioms.
   ms3c_real_seed_announcement and ms3c_sim_seed_announcement are unit for
   Phase-1 scaffolding only; not the final semantic announcement or Schnorr
   samplers (transcript and simulator wiring still open). *)
type ms3c_real_seed_challenge = unit.
type ms3c_real_seed_announcement = unit.
type ms3c_sim_seed_challenge = unit.
type ms3c_sim_seed_announcement = unit.

type ms3c_real_payload_seed = (ms3c_real_seed_challenge * ms3c_real_seed_announcement).
type ms3c_sim_payload_seed = (ms3c_sim_seed_challenge * ms3c_sim_seed_announcement).
