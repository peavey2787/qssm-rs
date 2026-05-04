# MS-3d Proof Plan (EasyCrypt)

This note tracks the next MS-side game-layer phase after MS-3c. **MS-3c is now closed at the game boundary**: **`games/GameAdvantage.ec`** projects **`game_pr`** from the concrete **`game_view`** surface, **`games/GameMSHopTypes.ec`** proves the MS-3c AfterComparison/Sim collapse and zero-advantage bound as lemmas, and no MS-3c bridge axiom remains. MS-3d therefore starts from a stable comparison/public-observable boundary and focuses on the remaining MS game-hop assumption debt outside the comparison lane.

**Initialization status:** the lower MS1/MS2 bridge installation is complete, and both halves are now discharged. **`games/GameAdvantage.ec`** defines **`game_pr_ms_core`** from **`ms_view_distinguish_pr (d_ms_game_stage_observable_v2 ...)`** and proves both **`A_MS1_hash_binding_game_pr_core_bound`** and **`A_MS2_rom_programming_game_pr_core_bound`** as lemmas. In **`games/GameMSHopTypes.ec`**, **`A_MS1_hash_binding_concrete_pair_advantage_bound`**, **`A_MS2_rom_programming_concrete_pair_advantage_bound`**, **`A_MS3a_canonical_bitness_exact_bound`**, **`A_MS3b_canonical_true_clause_bound`**, **`A_MS3c_comparison_bundle_implies_game_pr_equality`**, and **`A_MS3c_canonical_comparison_exact_bound`** are all proved lemmas. There is no remaining MS-specific game-layer axiom declaration.

## Objective

Carry the closed MS game-hop boundary forward so the composed MS transition theorem

- **`A_G0_to_G1_ms_transition_bound`** in **`games/GameMSHopComposition.ec`**

depends only on named cryptographic budgets and proved MS-3a / MS-3b / MS-3c statements, not on residual game-layer axioms.

## MS-3c handoff status

- **Stable projection layer:** **`games/GameAdvantage.ec`** now owns **`ms3a_game_pr_stage`**, **`ms3b_game_pr_stage`**, **`ms3c_game_pr_stage`**, **`game_pr`**, **`Adv`**, **`A_adv_ms_hop_telescope`**, the concrete MS probability core **`game_pr_ms_core`**, and the proved lower bridge lemmas **`A_MS1_hash_binding_game_pr_core_bound`** and **`A_MS2_rom_programming_game_pr_core_bound`**.
- **Public-observable bridge:** **`L_ms3c_game_view_public_obs_aligns_v2`**, **`L_ms3c_public_obs_seed_alignment`**, and **`L_ms3c_public_obs_payload_alignment`** close the current public game boundary for the native comparison slice and native comparison openings.
- **Closed MS-3c hop:** **`A_MS3c_comparison_bundle_implies_game_pr_equality`** and **`A_MS3c_canonical_comparison_exact_bound`** are proved lemmas in **`games/GameMSHopTypes.ec`**.
- **Comparison-local execution package:** the comparison-side execution-seed package remains below **`ms/SourceModel.ec`**. MS-3d does not need to thread that package into the game layer because the compared public/share surface and public observable are already closed.

## Current game-layer blocker set

| Item | Location | Current status | MS-3d consequence |
|------|----------|----------------|-------------------|
| **`A_MS1_hash_binding_game_pr_core_bound`** | **`games/GameAdvantage.ec`** | lemma | Proved MS1 lower bridge theorem: all public fields stay fixed and only **`game_pr_ms_core`** changes stage **`Real -> AfterBinding`**. The explicit **`GV_ms`** pair theorem in **`games/GameMSHopTypes.ec`** is a lemma derived from this lower bridge. |
| **`A_MS2_rom_programming_game_pr_core_bound`** | **`games/GameAdvantage.ec`** | lemma | Closed MS2 lower theorem surface: all public fields stay fixed and only **`game_pr_ms_core`** changes stage **`AfterBinding -> AfterRom`**. The explicit **`GV_ms`** pair theorem in **`games/GameMSHopTypes.ec`** is a lemma derived from this lower bridge. |
| **`game_pr_ms_core`** / **`game_pr_g2_core`** | **`games/GameAdvantage.ec`** | one concrete operator and one abstract operator, not axioms | **`game_pr_ms_core`** is now concrete on **`ms/MSProbabilitySurface.ec`**; **`game_pr_g2_core`** remains abstract. |

## What is already closed on the MS side

- **MS-3a:** **`A_MS3a_canonical_bitness_exact_bound`** is a proved lemma in **`games/GameMSHopTypes.ec`**.
- **MS-3b:** **`A_MS3b_canonical_true_clause_bound`** is a proved lemma in **`games/GameMSHopTypes.ec`**.
- **MS-3c:** **`A_MS3c_comparison_bundle_implies_game_pr_equality`** and **`A_MS3c_canonical_comparison_exact_bound`** are proved lemmas in **`games/GameMSHopTypes.ec`**.
- **MS telescope:** **`A_adv_ms_hop_telescope`** is a proved lemma in **`games/GameAdvantage.ec`**.
- **Debt reduction already achieved:** the MS1/MS2 game-layer axiom surface in **`games/GameMSHopTypes.ec`** dropped from six provisional axioms to zero, and the lower **`game_pr_ms_core`** boundary in **`games/GameAdvantage.ec`** is now also axiom-free for MS1/MS2.
- **Composed MS transition theorem:** **`A_G0_to_G1_ms_transition_bound`** is already a proved lemma in **`games/GameMSHopComposition.ec`**. Its MS1/MS2 dependence now flows only through proved lower bridge lemmas in **`games/GameAdvantage.ec`**.

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

- **MS1** no longer depends on a game-layer axiom; its lower Real/AfterBinding **`game_pr_ms_core`** bridge is now proved.
- **MS2** no longer depends on a lower AfterBinding/AfterRom **`game_pr_ms_core`** bridge axiom; that bridge is now a proved lemma.
- **MS3a / MS3b / MS3c** are already exact zero-advantage canonical lemmas on the current **`game_pr`** projection.

This means the MS-3d milestone on the MS1/MS2 lane is complete: the lower MS boundary is now closed for both **`Real -> AfterBinding`** and **`AfterBinding -> AfterRom`**, without adding new axioms or widening the comparison-side execution boundary.

## Exact lower-theorem boundary

The repo now exposes the correct lower MS1/MS2 theorem surfaces, but it still stops one layer too high to prove them.

- **Import-cycle audit:** the missing MS1/MS2 semantics can be added below **`game_pr_ms_core`** without creating a module cycle. **`games/GameAdvantage.ec`** already imports downward into **`MS.ec`**, **`FS.ec`**, and **`ms/source/*`**, while those lower theories do **not** import **`GameAdvantage.ec`**. The blocker is therefore semantic, not dependency-directional.
- **Installed lower surface skeleton:** **`ms/MSProbabilitySurface.ec`** now carries **`ms_distinguisher_event`**, **`ms_view_distinguish_pr`**, and **`d_ms_game_stage_observable_v2`**. Real/Sim use the existing MS-3a observable distributions; **`MSGameStageAfterBinding`** now reuses the real-source law and repacks through **`ms3a_pack_observable_with_digest`**, while **`MSGameStageAfterRom`** now samples the real-source law together with **`d_ms3c_real_seed_challenge`** and uses the seed's programmed-challenge field as the comparison-global observable field. **`MSGameStageAfterBitness`** and **`MSGameStageAfterComparison`** remain point masses.
- **Concrete precedent already present:** the source layer already exposes concrete MS-3a observable laws such as **`d_ms3a_bitness_real_observable_v2`** / **`d_ms3a_bitness_sim_observable_v2`** and the real-execution packaging boundary **`d_ms3a_real_execution_public_seed`**, so the missing surface is specifically the absence of analogous **stage-indexed MS1/MS2** execution semantics.
- **Stage-law audit:** **`MSGameStageReal`** already reuses **`d_ms3a_bitness_real_observable_v2`**. **`MSGameStageAfterBinding`** is now a digest-normalized pushforward of **`d_ms3a_bitness_real_source`**, and **`MSGameStageAfterRom`** is now a pushforward of **`d_ms3a_bitness_real_source`** paired with **`d_ms3c_real_seed_challenge`**. The blocker is no longer the absence of sampled stage laws. The lower MS1 theorem is now proved on this surface and wired into **`game_pr_ms_core`**; the remaining lower-theorem debt is MS2.
- **MS1 lower closure after validation:** the public transcript digest is now canonical by construction rather than an unconstrained stored field. **`ms/SourceTypes.ec`** adds **`ms_public_bitness_global_digests`**, **`ms_public_transcript_digest_canonical`**, **`ms_make_public_input`**, and **`ms_make_public_input_transcript_digest_canonical`**; **`ms/SourceModel.ec`** proves **`ms3a_public_transcript_digest_by_construction`** and unconditional **`ms3a_public_transcript_shape_ok_holds`**; **`ms/source/SourceRealExecutionGameLink.ec`** mirrors that as **`ms3a_game_public_bitness_source_transcript_digest_canonical`** and **`ms3a_game_public_bitness_source_transcript_shape`**; **`ms/MSProbabilitySurface.ec`** proves **`L_ms1_hash_binding_bad_event_zero`**, **`L_ms1_hash_binding_stage_zero`**, and **`A_MS1_hash_binding_bad_event_bound`**; and **`games/GameAdvantage.ec`** now proves **`A_MS1_hash_binding_game_pr_core_bound`** over the concrete **`game_pr_ms_core`** definition. No new assumption was introduced.
- **Smallest missing lower objects:**
	- **Installed:** **`op ms_distinguisher_event (D : distinguisher) : ms_v2_transcript_observable -> bool`** as the MS-side analogue of LE's **`le_distinguisher_event`**.
	- **Installed:** **`op ms_view_distinguish_pr (d : ms_v2_transcript_observable distr) (D : distinguisher) : real`** as the MS-side probability interface built from **`mu`**.
	- **Installed skeleton:** **`op d_ms_game_stage_observable_v2 (x : qssm_public_input) (s : seed) (xms : ms_public_input) (st : ms_game_stage) : ms_v2_transcript_observable distr`** as the minimal stage-indexed MS execution interface below **`game_pr_ms_core`**.
	- **Installed named stage law:** **`op d_ms_after_binding_observable_v2 (x : qssm_public_input) (s : seed) (xms : ms_public_input) : ms_v2_transcript_observable distr`**.
	- **Installed named stage law:** **`op d_ms_after_rom_observable_v2 (x : qssm_public_input) (s : seed) (xms : ms_public_input) : ms_v2_transcript_observable distr`**.
	- **Installed sampled MS1 law:** **`d_ms_after_binding_observable_v2`** is now a **`dmap`** of **`d_ms3a_bitness_real_source xms`** through **`ms3a_after_binding_observable_of_source`**, using **`ms3a_pack_observable_with_digest`** to normalize the transcript digest by construction.
	- **Installed sampled MS2 law:** **`d_ms_after_rom_observable_v2`** is now a **`dmap`** of **`d_ms3a_bitness_real_source xms `*` d_ms3c_real_seed_challenge xms`** through **`ms3a_after_rom_observable_of_source_challenge`**, using the challenge seed's **`ms3csc_programmed_challenge`** as the comparison-global observable field.
	- **Installed lower MS1 theorem:** **`lemma A_MS1_hash_binding_bad_event_bound`** now bounds the Real/AfterBinding stage gap by **`epsilon_ms_hash_binding`**.
	- **Installed lower MS2 theorem:** **`lemma A_MS2_rom_programming_transition_bound`** now bounds the AfterBinding/AfterRom stage gap by **`epsilon_ms_rom_programmability`**.

- **Why MS2 closed without a new ROM axiom:** on the current challenge-seed surface, **`ms3csc_programmed_challenge`** is already pinned to the public comparison-global digest on support, and the real source law is already the canonical point mass. This yields the exact lower equality **`d_ms_after_rom_observable_v2 = d_ms_after_binding_observable_v2`**, so **`A_MS2_rom_programming_transition_bound`** follows immediately from zero gap plus **`A2_ms_rom_programmability_nonneg`**.
- **Where the lower theorems should live:** **`games/GameAdvantage.ec`**, adjacent to **`game_pr_ms_core`** and the existing MS3a/MS3b/MS3c stage-collapse semantics, because that is the lowest layer naming the projected MS probability surface directly.

- **Installed MS1 lower theorem:** **`A_MS1_hash_binding_game_pr_core_bound`**.
- **Exact MS1 lower theorem:**
	`forall (x : qssm_public_input) (s : seed) (xms : ms_public_input) (obs : ms_v2_transcript_observable) (lep : le_transcript_observable option) (D : distinguisher), 0%r <= epsilon_ms_hash_binding => game_pr_ms_core x s xms obs MSGameStageReal lep D - game_pr_ms_core x s xms obs MSGameStageAfterBinding lep D <= epsilon_ms_hash_binding.`
- **Now discharges:** **`A_MS1_hash_binding_concrete_pair_advantage_bound`** in **`games/GameMSHopTypes.ec`**.
- **Closed MS2 lower bridge theorem:** **`A_MS2_rom_programming_game_pr_core_bound`**.
- **Exact MS2 lower theorem:**
	`forall (x : qssm_public_input) (s : seed) (xms : ms_public_input) (obs : ms_v2_transcript_observable) (lep : le_transcript_observable option) (D : distinguisher), 0%r <= epsilon_ms_rom_programmability => game_pr_ms_core x s xms obs MSGameStageAfterBinding lep D - game_pr_ms_core x s xms obs MSGameStageAfterRom lep D <= epsilon_ms_rom_programmability.`
- **Now discharges:** **`A_MS2_rom_programming_concrete_pair_advantage_bound`** in **`games/GameMSHopTypes.ec`**.

## Recommended proof order

1. **Completed:** **`games/GameAdvantage.ec`** now gives concrete MS semantics to **`game_pr_ms_core`** through **`ms/MSProbabilitySurface.ec`**.
2. **Completed:** **`A_MS1_hash_binding_concrete_pair_advantage_bound`** is now a proved lemma in **`games/GameMSHopTypes.ec`**, derived from the lower bridge lemma **`A_MS1_hash_binding_game_pr_core_bound`**.
3. **Completed:** **`A_MS2_rom_programming_concrete_pair_advantage_bound`** is now a proved lemma in **`games/GameMSHopTypes.ec`**, derived from the lower bridge lemma **`A_MS2_rom_programming_game_pr_core_bound`**.
4. **Completed:** **`A_MS2_rom_programming_game_pr_core_bound`** is discharged from concrete semantics below **`game_pr_ms_core`**, and **`A_G0_to_G1_ms_transition_bound`** continues to check with no remaining MS1/MS2 axioms anywhere in the game layer.
	The active lower entry point remains **`ms/MSProbabilitySurface.ec`**. The key closing fact is the exact lower equality between the AfterBinding and AfterRom observable laws on the current seed surface.
5. **Defer non-MS interfaces**: LE bridge assumptions, such as the projected LE probability interface, remain tracked in the LE/game plans and are not the immediate MS-3d blocker set.

## Exit criteria

- No remaining MS-3c game-layer axiom or bridge gap.
- Remaining MS-side game-layer assumption debt is no longer in the MS1/MS2 **`game_pr_ms_core`** bridge.
- **`A_G0_to_G1_ms_transition_bound`** depends on the MS1/MS2 cryptographic budgets plus proved MS-3a / MS-3b / MS-3c lemmas, with no additional MS-3c-specific game assumptions.
- **`./check_easycrypt.sh`** passes after the planning updates and after each subsequent MS-3d proof step.