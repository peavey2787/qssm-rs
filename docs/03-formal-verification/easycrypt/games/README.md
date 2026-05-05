# `games/`

Navigation: [EasyCrypt README](../README.md)

This directory holds the abstract game layer above the MS and LE theories: frozen views, advantage arithmetic, MS-hop transitions, the LE bridge, and the top-level game facade used by `theorem/MainTheorem.ec`.

Prefer these stable interfaces when importing from outside this directory:

- `GameMSHops.ec` for the MS-only hop chain.
- `Games.ec` for the top-level game-layer closure.

The internal flow is intentionally linear:

- `GameTypes.ec`, `GameViews.ec`, and `GameAdvantage.ec` define the base game/view surface.
- `GameMSHopTypes.ec`, `GameMSHopTransitions.ec`, and `GameMSHopComposition.ec` implement the MS hop chain surfaced by `GameMSHops.ec`.
- `GameLEBridge.ec` connects the generic game layer to the LE projected-probability surface.

Exact compile order still comes from `../check_easycrypt.sh`.