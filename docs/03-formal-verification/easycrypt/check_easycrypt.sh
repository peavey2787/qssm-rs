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
  primitives/QssmTypes.ec
  primitives/Algebra.ec
  primitives/FS.ec
  ms/SchnorrBranch.ec
  ms/BitnessOne.ec
  ms/BitnessVector.ec
  ms/TranscriptObservable.ec
  ms/TrueClause.ec
  ms/Comparison.ec
  ms/SourceModel.ec
  ms/source/SourceTypes.ec
  ms/source/SourceConstructors.ec
  ms/source/SourceDistributions.ec
  ms/source/SourceObligations.ec
  ms/source/SourceTheorem.ec
  ms/MS.ec
  le/LEModel.ec
  sim/Simulator.ec
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
