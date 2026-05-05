# `ms/source/`

Navigation: [EasyCrypt README](../../README.md)

This directory holds the split MS-3a source layer: source-record types, payload/seed laws, coupling lemmas, execution/public-spine bridges, schedule obligations, and the packaged MS-3a theorem surface.

Prefer these stable interfaces when importing from outside this directory:

- `SourceDistributions.ec` for payload, coupling, bitness, support, and observable distribution facts.
- `SourceScheduleObligations.ec` for the schedule chain.
- `SourceObligations.ec` for the bundled programmed-seed, paired public-field, and schedule obligations.
- `SourceTheorem.ec` for the packaged MS-3a theorem layer.

Internal grouping is by proof role:

- `SourceTypes.ec` and `SourceConstructors.ec` define the source records and Phase-1 constructors.
- `SourcePayloadDistributions.ec`, `SourceCoupling*.ec`, `SourceBitnessDistributions.ec`, `SourceDistributionLemmas.ec`, and `SourceObservableDistributions.ec` implement the distribution layer surfaced by `SourceDistributions.ec`.
- `SourceExecutionLink.ec`, `SourcePublicBitness*.ec`, `SourceRealExecutionGameLink.ec`, and `SourceRealExecutionSeed.ec` sit on the execution/public-spine boundary.
- `SourceProgrammedObligations.ec`, `SourcePublicFieldObligations.ec`, `SourceSchedule*.ec`, and `SourceObligations.ec` package the proof obligations consumed by `SourceTheorem.ec`.

Exact compile order still comes from `../../check_easycrypt.sh`.