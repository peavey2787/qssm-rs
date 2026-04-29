#!/usr/bin/env bash
# Validate all QSSM EasyCrypt scaffold theories in dependency order.
# Run from Git Bash, WSL, Linux, or macOS. Uses only paths inside this directory.
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
  QssmDomains.ec
  QssmTypes.ec
  QssmSchnorrSingleBit.ec
  QssmFS.ec
  QssmMSBitnessSingle.ec
  QssmMSBitnessVector.ec
  QssmMSTranscriptObservable.ec
  QssmMS.ec
  QssmLE.ec
  QssmSim.ec
  QssmGames.ec
  QssmTheorem.ec
)

cd "$SCRIPT_DIR"

for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: missing $f in $SCRIPT_DIR" >&2
    exit 1
  fi
  echo "==> Checking $f ..."
  # Type-check / verify this theory (EasyCrypt loads sibling theories from CWD).
  "$EC" "$f"
done

echo "OK: checked ${#FILES[@]} theories in $SCRIPT_DIR"
