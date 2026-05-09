# `ms/comparison/`

Navigation: [EasyCrypt README](../../README.md)

This directory holds the split MS-3c comparison layer: comparison types and digests, payload construction, payload-support facts, coupling laws, and the packaged comparison theorem surface.

External clients should normally import `../Comparison.ec`, which is the stable top-level facade for this subtree.

The internal split is organized by role:

- `ComparisonTypes.ec`, `ComparisonDigests.ec`, and `ComparisonPayloadTypes.ec` define the core comparison surface.
- `ComparisonPayloadSeedTypes.ec` defines the stable seed-side payload surface, `ComparisonPayloadExecutionSeedTypes.ec` owns the execution-seed package/types/laws, `ComparisonPayloadExecutionLaw.ec` owns the execution payload law transport, `ComparisonPayloadFromSeed.ec` remains the stable payload/schedule facade, and `ComparisonPayloadSeedAnchors.ec` plus `ComparisonPayloadSeeds.ec` complete the payload-seed chain.
- `ComparisonPayloadSemanticSlotMass.ec` owns the MS2 ROM semantic local slot/mass law, while `ComparisonPayloadSemanticBridge.ec` consumes that owner to package the comparison-local execution-owned bridge.
- `ComparisonPayloadSupportTypes.ec`, `ComparisonPayloadSupportPublic.ec`, `ComparisonPayloadSupportShares.ec`, and `ComparisonPayloadSupport.ec` package payload-support facts.
- `ComparisonCouplingTypes.ec`, `ComparisonCouplingAxioms.ec`, `ComparisonCouplingMarginals.ec`, `ComparisonCouplingSchedule.ec`, `ComparisonCouplingTheorem.ec`, and `ComparisonCoupling.ec` form the coupling chain.
- `ComparisonPayloadFalseClause.ec`, `ComparisonPayload.ec`, and `ComparisonTheorem.ec` package the payload and theorem surfaces used by the outer MS layer.

Exact compile order still comes from `../../check_easycrypt.sh`.