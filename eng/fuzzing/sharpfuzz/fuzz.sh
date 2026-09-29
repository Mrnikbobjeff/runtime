#!/usr/bin/env bash
# Usage: fuzz.sh <regex|json> [seconds=3600] [instances=2]
# Runs one AFL++ main instance plus (instances-1) secondaries against the SharpFuzz harness.
# Findings land in out/<target>/<instance>/{crashes,hangs,queue}. Run setup.sh first.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: fuzz.sh <regex|json> [seconds] [instances]}"
SECONDS_BUDGET="${2:-3600}"
INSTANCES="${3:-2}"
WORK="$HERE/.work"
OUT="$HERE/out/$TARGET"

export DOTNET_ROOT="$WORK/dotnet"
# SharpFuzz's out-of-process server re-launches "dotnet" from PATH, so the private root goes first.
export PATH="$WORK/dotnet:$PATH"
export AFL_SKIP_BIN_CHECK=1 AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_AFFINITY="${AFL_NO_AFFINITY:-}"

INPUT="$HERE/seeds/$TARGET"
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
    INPUT="-"   # resume the previous session
fi
mkdir -p "$OUT"

pids=()
for i in $(seq 1 "$INSTANCES"); do
    if [ "$i" -eq 1 ]; then role=(-M main); else role=(-S "sec$i"); fi
    afl-fuzz -i "$INPUT" -o "$OUT" "${role[@]}" -x "$HERE/dict/$TARGET.dict" -t 5000 -m none \
        -V "$SECONDS_BUDGET" -- dotnet "$WORK/harness/SharpFuzzHarness.dll" "$TARGET" \
        > "$OUT/afl-${role[1]}.log" 2>&1 &
    pids+=($!)
done

echo "Started ${#pids[@]} afl-fuzz instance(s) for $TARGET (${SECONDS_BUDGET}s); logs in $OUT/afl-*.log"
wait "${pids[@]}" || true
afl-whatsup -s "$OUT" || true
