#!/usr/bin/env bash
# Usage: repro.sh <regex|json> <input-file>...
# Replays inputs through the harness outside of AFL and prints full exception details.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: repro.sh <regex|json> <input-file>...}"
shift

export DOTNET_ROOT="$HERE/.work/dotnet"
export PATH="$DOTNET_ROOT:$PATH"
exec dotnet "$HERE/.work/harness/SharpFuzzHarness.dll" "$TARGET" --repro "$@"
