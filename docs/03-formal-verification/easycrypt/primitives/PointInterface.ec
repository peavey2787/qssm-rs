require import AllCore.
require import QssmTypes.

(* Dedicated owner for the abstract additive point interface. This centralizes
   the point-group assumptions without changing the current abstract carrier. *)

op sch_neutral_pt : sch_point = SchPointGroup.e.
op sch_opp_pt : sch_point -> sch_point = SchPointGroup.inv.
op sch_add_pt : sch_point -> sch_point -> sch_point = SchPointGroup.( * ).

lemma sch_addA (x y z : sch_point) :
  sch_add_pt x (sch_add_pt y z) = sch_add_pt (sch_add_pt x y) z.
proof. exact (SchPointGroup.mulcA x y z). qed.

lemma sch_addC (x y : sch_point) :
  sch_add_pt x y = sch_add_pt y x.
proof. exact (SchPointGroup.mulcC x y). qed.

lemma sch_neutralL (x : sch_point) :
  sch_add_pt sch_neutral_pt x = x.
proof. exact (SchPointGroup.mul1c x). qed.

lemma sch_oppL (x : sch_point) :
  sch_add_pt (sch_opp_pt x) x = sch_neutral_pt.
proof. exact (SchPointGroup.mulVc x). qed.
