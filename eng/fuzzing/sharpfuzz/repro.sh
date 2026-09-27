#!/usr/bin/env bash
# Usage: repro.sh <target> <input-file>...
# Replays inputs through the harness outside of AFL and prints full exception details.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: repro.sh <target> <input-file>...}"
shift

export DOTNET_ROOT="${SHARPFUZZ_WORK:-$HERE/.work}/dotnet"
export PATH="$DOTNET_ROOT:$PATH" TZ="${TZ:-UTC}"
# Same heap cap as fuzz.sh, so runaway allocations throw OutOfMemoryException instead of
# getting the whole replay killed.
export DOTNET_GCHeapHardLimit="${DOTNET_GCHeapHardLimit:-0x40000000}"
PIN=()
[ -n "${SHARPFUZZ_CPUS:-}" ] && PIN=(taskset -c "$SHARPFUZZ_CPUS")
exec "${PIN[@]}" dotnet "$(dirname "$DOTNET_ROOT")/harness/SharpFuzzHarness.dll" "$TARGET" --repro "$@"
