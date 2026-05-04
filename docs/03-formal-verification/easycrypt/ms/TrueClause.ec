(* Stable facade for the MS-3b true-clause split. Downstream theories import
   `TrueClause` instead of the leaf modules under `ms/true_clause/`. *)
require export TrueClauseTypes.
require export TrueClauseMSB.
require export TrueClauseTheorem.
