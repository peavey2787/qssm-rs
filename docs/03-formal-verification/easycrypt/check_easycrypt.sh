#!/usr/bin/env bash
# Validate all QSSM EasyCrypt scaffold theories in dependency order.
# Run from Git Bash, WSL, Linux, or macOS. Uses only paths inside this directory.
# Theories are resolved by basename under subdirectories (-R .).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EC="${EASYCRYPT:-easycrypt}"

if ! command -v "$EC" >/dev/null 2>&1; then
  if command -v ec >/dev/null 2>&1; then
    EC="ec"
  else
    echo "ERROR: EasyCrypt not found. Install EasyCrypt (see README.md) or set EASYCRYPT to the binary path." >&2
    exit 2
  fi
fi

FILES=(
  primitives/Domains.ec
  primitives/ScalarOwner.ec
  primitives/QssmTypes.ec
  primitives/ScalarSampler.ec
  primitives/Algebra.ec
  primitives/FS.ec
  ms/SchnorrBranch.ec
  ms/BitnessOne.ec
  ms/BitnessVector.ec
  ms/TranscriptObservable.ec
  ms/SourceTypes.ec
  ms/true_clause/TrueClauseTypes.ec
  ms/true_clause/TrueClauseMSB.ec
  ms/true_clause/TrueClauseTheorem.ec
  ms/TrueClause.ec
  ms/comparison/ComparisonTypes.ec
  ms/comparison/ComparisonDigests.ec
  ms/comparison/ComparisonPayloadTypes.ec
  ms/comparison/ComparisonPayloadSeedTypes.ec
  ms/comparison/ComparisonPayloadFromSeed.ec
  ms/comparison/ComparisonPayloadSeedAnchors.ec
  ms/comparison/ComparisonPayloadSeeds.ec
  ms/comparison/ComparisonPayloadSupportTypes.ec
  ms/comparison/ComparisonPayloadSupportPublic.ec
  ms/comparison/ComparisonPayloadSupportShares.ec
  ms/comparison/ComparisonPayloadSupport.ec
  ms/comparison/ComparisonPayloadFalseClause.ec
  ms/comparison/ComparisonPayload.ec
  ms/comparison/ComparisonCouplingTypes.ec
  ms/comparison/ComparisonCouplingAxioms.ec
  ms/comparison/ComparisonCouplingMarginals.ec
  ms/comparison/ComparisonCouplingSchedule.ec
  ms/comparison/ComparisonCouplingTheorem.ec
  ms/comparison/ComparisonCoupling.ec
  ms/comparison/ComparisonTheorem.ec
  ms/Comparison.ec
  ms/SourceModel.ec
  ms/source/SourceConstructors.ec
  ms/source/SourcePayloadDistributions.ec
  ms/source/SourceCouplingTypes.ec
  ms/source/SourceCouplingAxioms.ec
  ms/source/SourceCouplingTheorem.ec
  ms/source/SourceBitnessDistributions.ec
  ms/source/SourceDistributionLemmas.ec
  ms/source/SourceObservableDistributions.ec
  ms/source/SourceDistributions.ec
  ms/source/SourceExecutionLink.ec
  ms/source/SourcePublicBitnessConstructors.ec
  ms/source/SourcePublicBitnessExecution.ec
  ms/source/SourceRealExecutionGameLink.ec
  ms/source/SourceRealExecutionSeed.ec
  ms/source/SourceProgrammedObligations.ec
  ms/source/SourcePublicFieldObligations.ec
  ms/source/SourceScheduleSeed.ec
  ms/source/SourceSchedulePayload.ec
  ms/source/SourceScheduleTheorem.ec
  ms/source/SourceScheduleObligations.ec
  ms/source/SourceObligations.ec
  ms/source/SourceTheorem.ec
  ms/MSProbabilitySurface.ec
  ms/MS.ec
  le/LERealExecution.ec
  le/LESurface.ec
  le/LERejectionSampler.ec
  le/LEFsProgrammingSurface.ec
  le/LESetB.ec
  le/LERejection.ec
  le/LEFsProgramming.ec
  le/LEViewIndist.ec
  le/LEStatisticalDistance.ec
  le/LEHVZK.ec
  le/LEModel.ec
  sim/Simulator.ec
  games/GameTypes.ec
  games/GameViews.ec
  games/GameAdvantage.ec
  games/GameMSHopTypes.ec
  games/GameMSHopTransitions.ec
  games/GameMSHopComposition.ec
  games/GameMSHops.ec
  games/GameLEBridge.ec
  games/Games.ec
  theorem/MainTheorem.ec
)

cd "$SCRIPT_DIR"

for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: missing $f in $SCRIPT_DIR" >&2
    exit 1
  fi
  echo "==> Checking $f ..."
  "$EC" compile -R . "$f"
done

echo "OK: checked ${#FILES[@]} theories in $SCRIPT_DIR"
