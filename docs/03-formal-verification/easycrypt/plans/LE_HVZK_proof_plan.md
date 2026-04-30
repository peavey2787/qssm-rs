# LE HVZK Proof Plan

## Objective

Refine the LE Set-B HVZK boundary into narrower, named obligations while keeping
`epsilon_le` as the final budget for the `G1 -> G2` hop.

## Current Layering

`le/LEModel.ec` now uses the following layered obligations:

- `A_LE_SetB_params_sound`
- `A_LE_rejection_sampling_hiding_bound`
- `A_LE_fs_programming_bound`
- `A_LE_real_sim_transcript_equiv_bound`

From these, `A_LE_SetB_HVZK_bound` is derived as a **lemma** (no longer an axiom),
and then `A_LE_HVZK_transition_bound` remains the game-facing wrapper lemma.

## Intended Discharge Path

1. **Set-B parameter soundness**
   - Connect `set_b_parameter_well_formed` to concrete qssm-le parameter side
     conditions (size, span, noise bounds, ordering constraints).
2. **Rejection-sampling hiding bound**
   - Isolate the statistical distance contribution from rejection sampling.
   - Keep the contribution explicitly budgeted under `epsilon_le`.
3. **FS programming bound**
   - Tie LE transcript/programmed-digest consistency to the FS programmability
     surface used in this model.
4. **Transcript equivalence to HVZK advantage**
   - Convert real/sim transcript alignment assumptions into the final game-hop
     inequality `le_game_hop_adv x s D <= epsilon_le`.

## Remaining LE Proof Debt

- All four obligations above are still axiomatized.
- `A_game_pr_LE_projection_semantics` in `games/GameLEBridge.ec` remains the
  single non-crypto interface boundary (out of scope for this plan).

## Exit Criteria

- Replace one or more LE-HVZK axioms with proved lemmas from narrower concrete
  assumptions without changing theorem-facing statements.
- Preserve `A_LE_HVZK_transition_bound` and keep checker passing.
