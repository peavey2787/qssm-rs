require import AllCore.
require import QssmTypes.

(* Dedicated owner for the abstract additive point interface. This centralizes
   the point-group assumptions without changing the current abstract carrier. *)

op sch_neutral_pt : sch_point.
op sch_opp_pt : sch_point -> sch_point.
op sch_add_pt : sch_point -> sch_point -> sch_point.

axiom sch_addA (x y z : sch_point) :
  sch_add_pt x (sch_add_pt y z) = sch_add_pt (sch_add_pt x y) z.

axiom sch_addC (x y : sch_point) :
  sch_add_pt x y = sch_add_pt y x.

axiom sch_neutralL (x : sch_point) :
  sch_add_pt sch_neutral_pt x = x.

axiom sch_oppL (x : sch_point) :
  sch_add_pt (sch_opp_pt x) x = sch_neutral_pt.
