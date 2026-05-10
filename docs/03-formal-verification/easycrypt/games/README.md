# `games/`

Navigation: [EasyCrypt README](../README.md)

This directory holds the abstract game layer above the MS and LE theories: frozen views, advantage arithmetic, MS-hop transitions, the LE bridge, and the top-level game facade used by `theorem/MainTheorem.ec`.

Current freeze checkpoint, May 2026: the canonical/demo game route remains live, and the parameterized companions now support both the internal staged/public-endpoint MS lane and the closed canonical parameterized route. `GameAdvantage.ec`, `GameMSHopTypes.ec`, `GameMSHopTransitions.ec`, and `GameMSHopComposition.ec` remain the live canonical `G0 -> G1` MS route used by `theorem/MainTheorem.ec`. The parameterized companions `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec` still expose the staged/public-endpoint MS lane, but they now do so over live MS1 and live MS2 lower lanes while also closing a canonical `Adv_G0_G1_MS` replacement through a budgeted public AfterRom to canonical AfterRom landing. `theorem/MainTheoremParameterized.ec : qssm_main_theorem_le_parameterized_budget` remains the LE-only intermediate theorem, and `theorem/MainTheoremParameterized.ec : qssm_main_theorem_parameterized_budget` closes the full parameterized route with the explicit budget `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_le_parameterized`, which evaluates to `3%r / 8%r` under the active live profiles. Public AfterRom is still only budget-close to canonical AfterRom, not zero-equal, so there is still no zero-cost identification at the game layer.

Prefer these stable interfaces when importing from outside this directory:

- `GameMSHops.ec` for the MS-only hop chain.
- `Games.ec` for the top-level game-layer closure.

The internal flow is intentionally linear:

- `GameTypes.ec`, `GameViews.ec`, and `GameAdvantage.ec` define the base game/view surface.
- `GameMSHopTypes.ec`, `GameMSHopTransitions.ec`, and `GameMSHopComposition.ec` implement the MS hop chain surfaced by `GameMSHops.ec`.
- `GameLEBridge.ec` connects the generic game layer to the LE projected-probability surface.

Exact compile order still comes from `../check_easycrypt.sh`.