# MS-3d Proof Plan (EasyCrypt)

This note tracks the next MS-side game-layer phase after MS-3c. **MS-3c is now closed at the game boundary**: **`games/GameAdvantage.ec`** projects **`game_pr`** from the concrete **`game_view`** surface, **`games/GameMSHopTypes.ec`** proves the MS-3c AfterComparison/Sim collapse and zero-advantage bound as lemmas, and no MS-3c bridge axiom remains. MS-3d therefore starts from a stable comparison/public-observable boundary and focuses on the remaining MS game-hop assumption debt outside the comparison lane.

**Initialization status:** lower MS1/MS2 bridge installation is complete. **`games/GameAdvantage.ec`** now carries the lower bridge axioms **`A_MS1_hash_binding_game_pr_core_bound`** and **`A_MS2_rom_programming_game_pr_core_bound`** on the abstract **`game_pr_ms_core`** surface. In **`games/GameMSHopTypes.ec`**, **`A_MS1_hash_binding_concrete_pair_advantage_bound`** and **`A_MS2_rom_programming_concrete_pair_advantage_bound`** are now proved lemmas derived from those lower bridge axioms, and the step/canonical bounds remain proved lemmas above them. The remaining proof debt is lower: these two new bridge axioms are still **not** reducible to the current repo assumptions in **`ms/MS.ec`**, **`primitives/FS.ec`**, or **`theorem/MainTheorem.ec`**.

## Objective

Discharge the remaining MS-side game-layer axioms so the composed MS transition theorem

- **`A_G0_to_G1_ms_transition_bound`** in **`games/GameMSHopComposition.ec`**

depends only on named cryptographic budgets and proved MS-3a / MS-3b / MS-3c statements, not on residual game-layer axioms.

## MS-3c handoff status

- **Stable projection layer:** **`games/GameAdvantage.ec`** now owns **`ms3a_game_pr_stage`**, **`ms3b_game_pr_stage`**, **`ms3c_game_pr_stage`**, **`game_pr`**, **`Adv`**, **`A_adv_ms_hop_telescope`**, and the lower MS1/MS2 bridge axioms **`A_MS1_hash_binding_game_pr_core_bound`** / **`A_MS2_rom_programming_game_pr_core_bound`** on **`game_pr_ms_core`**.
- **Public-observable bridge:** **`L_ms3c_game_view_public_obs_aligns_v2`**, **`L_ms3c_public_obs_seed_alignment`**, and **`L_ms3c_public_obs_payload_alignment`** close the current public game boundary for the native comparison slice and native comparison openings.
- **Closed MS-3c hop:** **`A_MS3c_comparison_bundle_implies_game_pr_equality`** and **`A_MS3c_canonical_comparison_exact_bound`** are proved lemmas in **`games/GameMSHopTypes.ec`**.
- **Comparison-local execution package:** the comparison-side execution-seed package remains below **`ms/SourceModel.ec`**. MS-3d does not need to thread that package into the game layer because the compared public/share surface and public observable are already closed.

## Current game-layer blocker set

| Item | Location | Current status | MS-3d consequence |
|------|----------|----------------|-------------------|
| **`A_MS1_hash_binding_game_pr_core_bound`** | **`games/GameAdvantage.ec`** | axiom | Remaining MS1 lower theorem surface: all public fields stay fixed and only **`game_pr_ms_core`** changes stage **`Real -> AfterBinding`**. The explicit **`GV_ms`** pair theorem in **`games/GameMSHopTypes.ec`** is now a lemma derived from this lower bridge. |
| **`A_MS2_rom_programming_game_pr_core_bound`** | **`games/GameAdvantage.ec`** | axiom | Remaining MS2 lower theorem surface: all public fields stay fixed and only **`game_pr_ms_core`** changes stage **`AfterBinding -> AfterRom`**. The explicit **`GV_ms`** pair theorem in **`games/GameMSHopTypes.ec`** is now a lemma derived from this lower bridge. |
| **`game_pr_ms_core`** / **`game_pr_g2_core`** | **`games/GameAdvantage.ec`** | abstract operators, not axioms | Stable interface boundary for now. Not an immediate MS-3d blocker unless this phase aims to give concrete semantics to **`game_pr`** itself. |

## What is already closed on the MS side

- **MS-3a:** **`A_MS3a_canonical_bitness_exact_bound`** is a proved lemma in **`games/GameMSHopTypes.ec`**.
- **MS-3b:** **`A_MS3b_canonical_true_clause_bound`** is a proved lemma in **`games/GameMSHopTypes.ec`**.
- **MS-3c:** **`A_MS3c_canonical_comparison_exact_bound`** is a proved lemma in **`games/GameMSHopTypes.ec`**.
- **MS telescope:** **`A_adv_ms_hop_telescope`** is a proved lemma in **`games/GameAdvantage.ec`**.
- **Debt reduction already achieved:** the MS1/MS2 game-layer axiom surface in **`games/GameMSHopTypes.ec`** dropped from six provisional axioms to zero: the explicit concrete stage-pair theorems, the generic step-bound surfaces, and the canonical pair bounds are now all lemmas. The remaining MS1/MS2 axioms live only at the lower **`game_pr_ms_core`** boundary in **`games/GameAdvantage.ec`**.
- **Composed MS transition theorem:** **`A_G0_to_G1_ms_transition_bound`** is already a proved lemma in **`games/GameMSHopComposition.ec`**, but its remaining MS1/MS2 assumption debt now flows through the lower bridge axioms in **`games/GameAdvantage.ec`**.

## Relevant dependencies to carry from MS-3c into MS-3d

- **`L_ms3c_game_view_public_obs_aligns_v2`** in **`games/GameAdvantage.ec`**
- **`L_ms3c_public_obs_seed_alignment`** in **`games/GameAdvantage.ec`**
- **`L_ms3c_public_obs_payload_alignment`** in **`games/GameAdvantage.ec`**
- **`A_MS3c_comparison_bundle_implies_game_pr_equality`** in **`games/GameMSHopTypes.ec`**
- **`A_MS3c_canonical_comparison_exact_bound`** in **`games/GameMSHopTypes.ec`**
- **`MS_3c_exact_comparison_simulation`** in **`ms/MS.ec`**

These should be treated as stable handoff facts. MS-3d should not reopen the comparison lane unless the canonical public stage surface itself changes.

## Boundary assessment

The remaining blocker set is **not** in the comparison execution package, nor in the public comparison observable. It is concentrated in the earlier game hops:

- **MS1** now depends on one lower Real/AfterBinding **`game_pr_ms_core`** bridge axiom.
- **MS2** now depends on one lower AfterBinding/AfterRom **`game_pr_ms_core`** bridge axiom.
- **MS3a / MS3b / MS3c** are already exact zero-advantage canonical lemmas on the current **`game_pr`** projection.

This means the correct MS-3d direction is to finalize the lower MS boundary by discharging the surviving **`game_pr_ms_core`** bridge axioms, not by adding new MS-3c structure or by widening the comparison-side execution boundary.

## Exact lower-theorem boundary

The repo now exposes the correct lower MS1/MS2 theorem surfaces, but it still stops one layer too high to prove them.

- **Import-cycle audit:** the missing MS1/MS2 semantics can be added below **`game_pr_ms_core`** without creating a module cycle. **`games/GameAdvantage.ec`** already imports downward into **`MS.ec`**, **`FS.ec`**, and **`ms/source/*`**, while those lower theories do **not** import **`GameAdvantage.ec`**. The blocker is therefore semantic, not dependency-directional.
- **Installed lower surface skeleton:** **`ms/MSProbabilitySurface.ec`** now carries **`ms_distinguisher_event`**, **`ms_view_distinguish_pr`**, and **`d_ms_game_stage_observable_v2`**. Real/Sim use the existing MS-3a observable distributions; **`MSGameStageAfterBinding`** now reuses the real-source law and repacks through **`ms3a_pack_observable_with_digest`**, while **`MSGameStageAfterRom`** now samples the real-source law together with **`d_ms3c_real_seed_challenge`** and uses the seed's programmed-challenge field as the comparison-global observable field. **`MSGameStageAfterBitness`** and **`MSGameStageAfterComparison`** remain point masses.
- **Concrete precedent already present:** the source layer already exposes concrete MS-3a observable laws such as **`d_ms3a_bitness_real_observable_v2`** / **`d_ms3a_bitness_sim_observable_v2`** and the real-execution packaging boundary **`d_ms3a_real_execution_public_seed`**, so the missing surface is specifically the absence of analogous **stage-indexed MS1/MS2** execution semantics.
- **Stage-law audit:** **`MSGameStageReal`** already reuses **`d_ms3a_bitness_real_observable_v2`**. **`MSGameStageAfterBinding`** is now a digest-normalized pushforward of **`d_ms3a_bitness_real_source`**, and **`MSGameStageAfterRom`** is now a pushforward of **`d_ms3a_bitness_real_source`** paired with **`d_ms3c_real_seed_challenge`**. The blocker is no longer the absence of sampled stage laws. The lower MS1 theorem is now proved on this surface, and the remaining lower-theorem debt is MS2 plus the still-abstract bridge from this concrete surface to **`game_pr_ms_core`**.
- **MS1 lower closure after validation:** the public transcript digest is now canonical by construction rather than an unconstrained stored field. **`ms/SourceTypes.ec`** adds **`ms_public_bitness_global_digests`**, **`ms_public_transcript_digest_canonical`**, **`ms_make_public_input`**, and **`ms_make_public_input_transcript_digest_canonical`**; **`ms/SourceModel.ec`** proves **`ms3a_public_transcript_digest_by_construction`** and unconditional **`ms3a_public_transcript_shape_ok_holds`**; **`ms/source/SourceRealExecutionGameLink.ec`** mirrors that as **`ms3a_game_public_bitness_source_transcript_digest_canonical`** and **`ms3a_game_public_bitness_source_transcript_shape`**; and **`ms/MSProbabilitySurface.ec`** now proves **`L_ms1_hash_binding_bad_event_zero`**, **`L_ms1_hash_binding_stage_zero`**, and **`A_MS1_hash_binding_bad_event_bound`**. No new assumption was introduced. The remaining MS1 gap is one layer higher: relating abstract **`game_pr_ms_core`** to the concrete lower probability surface.
- **Smallest missing lower objects:**
	- **Installed:** **`op ms_distinguisher_event (D : distinguisher) : ms_v2_transcript_observable -> bool`** as the MS-side analogue of LE's **`le_distinguisher_event`**.
	- **Installed:** **`op ms_view_distinguish_pr (d : ms_v2_transcript_observable distr) (D : distinguisher) : real`** as the MS-side probability interface built from **`mu`**.
	- **Installed skeleton:** **`op d_ms_game_stage_observable_v2 (x : qssm_public_input) (s : seed) (xms : ms_public_input) (st : ms_game_stage) : ms_v2_transcript_observable distr`** as the minimal stage-indexed MS execution interface below **`game_pr_ms_core`**.
	- **Installed named stage law:** **`op d_ms_after_binding_observable_v2 (x : qssm_public_input) (s : seed) (xms : ms_public_input) : ms_v2_transcript_observable distr`**.
	- **Installed named stage law:** **`op d_ms_after_rom_observable_v2 (x : qssm_public_input) (s : seed) (xms : ms_public_input) : ms_v2_transcript_observable distr`**.
	- **Installed sampled MS1 law:** **`d_ms_after_binding_observable_v2`** is now a **`dmap`** of **`d_ms3a_bitness_real_source xms`** through **`ms3a_after_binding_observable_of_source`**, using **`ms3a_pack_observable_with_digest`** to normalize the transcript digest by construction.
	- **Installed sampled MS2 law:** **`d_ms_after_rom_observable_v2`** is now a **`dmap`** of **`d_ms3a_bitness_real_source xms `*` d_ms3c_real_seed_challenge xms`** through **`ms3a_after_rom_observable_of_source_challenge`**, using the challenge seed's **`ms3csc_programmed_challenge`** as the comparison-global observable field.
	- **Installed lower MS1 theorem:** **`lemma A_MS1_hash_binding_bad_event_bound`** now bounds the Real/AfterBinding stage gap by **`epsilon_ms_hash_binding`**.
	- **Still missing theorem debt:** the sampled MS2 stage law is not yet connected to a lower cryptographic bound, and the concrete lower MS surface is not yet tied back to abstract **`game_pr_ms_core`**.
	- **`lemma A_MS2_rom_programming_transition_bound`** to bound the AfterBinding/AfterRom stage gap by **`epsilon_ms_rom_programmability`**.

- **Why MS1 is still blocked at `game_pr_ms_core`:** **`game_pr_ms_core`** in **`games/GameAdvantage.ec`** is still an abstract operator, and the new concrete lower theorem **`A_MS1_hash_binding_bad_event_bound`** lives on **`ms_view_distinguish_pr (d_ms_game_stage_observable_v2 ...)`** rather than directly on **`game_pr_ms_core`**. The remaining MS1 semantic boundary is therefore the projection bridge from the abstract game-layer operator to this concrete lower probability surface, not the digest-normalization step.
- **Why MS2 is still blocked:** **`game_pr_ms_core`** is still abstract, and the existing ROM surfaces only assert **`0%r <= epsilon_ms_rom_programmability`** plus **`A2_programmable_oracle_exists`** for scalar response existence at a ROM query point. The new lower axiom **`A_MS2_rom_programming_game_pr_core_bound`** is therefore the current semantic boundary rather than a proved lemma.
- **Where the lower theorems should live:** **`games/GameAdvantage.ec`**, adjacent to **`game_pr_ms_core`** and the existing MS3a/MS3b/MS3c stage-collapse semantics, because that is the lowest layer naming the projected MS probability surface directly.
- **Proposed MS1 lower theorem:** **`A_MS1_hash_binding_game_pr_core_bound`**.
- **Exact MS1 lower theorem:**
	`forall (x : qssm_public_input) (s : seed) (xms : ms_public_input) (obs : ms_v2_transcript_observable) (lep : le_transcript_observable option) (D : distinguisher), 0%r <= epsilon_ms_hash_binding => game_pr_ms_core x s xms obs MSGameStageReal lep D - game_pr_ms_core x s xms obs MSGameStageAfterBinding lep D <= epsilon_ms_hash_binding.`
- **Now discharges:** **`A_MS1_hash_binding_concrete_pair_advantage_bound`** in **`games/GameMSHopTypes.ec`**.
- **Proposed MS2 lower theorem:** **`A_MS2_rom_programming_game_pr_core_bound`**.
- **Exact MS2 lower theorem:**
	`forall (x : qssm_public_input) (s : seed) (xms : ms_public_input) (obs : ms_v2_transcript_observable) (lep : le_transcript_observable option) (D : distinguisher), 0%r <= epsilon_ms_rom_programmability => game_pr_ms_core x s xms obs MSGameStageAfterBinding lep D - game_pr_ms_core x s xms obs MSGameStageAfterRom lep D <= epsilon_ms_rom_programmability.`
- **Now discharges:** **`A_MS2_rom_programming_concrete_pair_advantage_bound`** in **`games/GameMSHopTypes.ec`**.

## Recommended proof order

1. **Keep `games/GameAdvantage.ec` fixed** as the stable projection layer unless a concrete semantics for **`game_pr_ms_core`** is explicitly required. The current stage-collapsing design already closes MS-3a / MS-3b / MS-3c.
2. **Completed:** **`A_MS1_hash_binding_concrete_pair_advantage_bound`** is now a proved lemma in **`games/GameMSHopTypes.ec`**, derived from the lower bridge axiom **`A_MS1_hash_binding_game_pr_core_bound`**.
3. **Completed:** **`A_MS2_rom_programming_concrete_pair_advantage_bound`** is now a proved lemma in **`games/GameMSHopTypes.ec`**, derived from the lower bridge axiom **`A_MS2_rom_programming_game_pr_core_bound`**.
4. **Current blocker:** discharge **`A_MS1_hash_binding_game_pr_core_bound`** and **`A_MS2_rom_programming_game_pr_core_bound`** from concrete cryptographic semantics below **`game_pr_ms_core`**, then re-check **`A_G0_to_G1_ms_transition_bound`** with no remaining MS1/MS2 axioms anywhere in the game layer.
	The newly added **`ms/MSProbabilitySurface.ec`** is the intended lower entry point for that next patch; **`game_pr_ms_core`** remains abstract in this phase. Do not use **`d_ms_game_stage_observable_v2`** to concretize it until the abstract projection bridge is supplied and **`A_MS2_rom_programming_transition_bound`** is also proved.
	For MS1 specifically, the digest-normalization obligation is now closed by construction. The next proof obligation is the exact bridge from **`game_pr_ms_core`** to **`ms_view_distinguish_pr (d_ms_game_stage_observable_v2 ...)`** so that the proved lower theorem **`A_MS1_hash_binding_bad_event_bound`** can discharge the remaining abstract axiom.
5. **Defer non-MS interfaces**: LE bridge assumptions, such as the projected LE probability interface, remain tracked in the LE/game plans and are not the immediate MS-3d blocker set.

## Exit criteria

- No remaining MS-3c game-layer axiom or bridge gap.
- Remaining MS-side game-layer assumption debt reduced to the two lower **`game_pr_ms_core`** cryptographic bridge axioms for MS1/MS2, or those axioms fully discharged.
- **`A_G0_to_G1_ms_transition_bound`** depends on the MS1/MS2 cryptographic budgets plus proved MS-3a / MS-3b / MS-3c lemmas, with no additional MS-3c-specific game assumptions.
- **`./check_easycrypt.sh`** passes after the planning updates and after each subsequent MS-3d proof step.