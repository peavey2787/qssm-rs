# `games/`

Navigation: [EasyCrypt README](../README.md)

This directory holds the abstract game layer above the MS and LE theories: frozen views, advantage arithmetic, MS-hop transitions, the LE bridge, and the top-level game facade used by `theorem/MainTheorem.ec`.

Current freeze checkpoint, May 2026: the canonical/demo game route and the parameterized game route are intentionally split. `GameAdvantage.ec`, `GameMSHopTypes.ec`, `GameMSHopTransitions.ec`, and `GameMSHopComposition.ec` remain the live canonical `G0 -> G1` MS route used by `theorem/MainTheorem.ec`. The parameterized companions `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec` expose only the staged/public-endpoint MS lane; they do not claim a canonical `Adv_G0_G1_MS` replacement. That omission is intentional because the lower MS public AfterRom observable is only budget-close to the canonical AfterRom observable, not zero-equal. By contrast, the LE parameterized lane does close through `GameLEBridgeParameterized.ec`, and `theorem/MainTheoremParameterized.ec : qssm_main_theorem_le_parameterized_budget` keeps the canonical/demo MS contribution unchanged while parameterizing only the LE side.

Prefer these stable interfaces when importing from outside this directory:

- `GameMSHops.ec` for the MS-only hop chain.
- `Games.ec` for the top-level game-layer closure.

The internal flow is intentionally linear:

- `GameTypes.ec`, `GameViews.ec`, and `GameAdvantage.ec` define the base game/view surface.
- `GameMSHopTypes.ec`, `GameMSHopTransitions.ec`, and `GameMSHopComposition.ec` implement the MS hop chain surfaced by `GameMSHops.ec`.
- `GameLEBridge.ec` connects the generic game layer to the LE projected-probability surface.

Exact compile order still comes from `../check_easycrypt.sh`.