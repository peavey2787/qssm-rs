# `ms/comparison/`

Navigation: [EasyCrypt README](../../README.md)

This directory holds the split MS-3c comparison layer: comparison types and digests, payload construction, payload-support facts, coupling laws, and the packaged comparison theorem surface.

External clients should normally import `../Comparison.ec`, which is the stable top-level facade for this subtree.

The internal split is organized by role:

- `ComparisonTypes.ec`, `ComparisonDigests.ec`, and `ComparisonPayloadTypes.ec` define the core comparison surface.
- `ComparisonPayloadSeedTypes.ec`, `ComparisonPayloadFromSeed.ec`, `ComparisonPayloadSeedAnchors.ec`, and `ComparisonPayloadSeeds.ec` form the payload-seed chain.
- `ComparisonPayloadSupportTypes.ec`, `ComparisonPayloadSupportPublic.ec`, `ComparisonPayloadSupportShares.ec`, and `ComparisonPayloadSupport.ec` package payload-support facts.
- `ComparisonCouplingTypes.ec`, `ComparisonCouplingAxioms.ec`, `ComparisonCouplingMarginals.ec`, `ComparisonCouplingSchedule.ec`, `ComparisonCouplingTheorem.ec`, and `ComparisonCoupling.ec` form the coupling chain.
- `ComparisonPayloadFalseClause.ec`, `ComparisonPayload.ec`, and `ComparisonTheorem.ec` package the payload and theorem surfaces used by the outer MS layer.

Exact compile order still comes from `../../check_easycrypt.sh`.