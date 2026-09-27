#!/usr/bin/env bash
# Usage: fuzz.sh <target> [seconds=3600] [instances=2]
# Runs one AFL++ main instance plus (instances-1) secondaries against the SharpFuzz harness.
# Findings land in out/<target>/<instance>/{crashes,hangs,queue}. Run setup.sh first.
#
# Secondaries alternate between the machine's full ISA and runs with AVX-512 (sec2, sec5, ...)
# or AVX2 (sec3, sec6, ...) disabled, so the Vector512/256/128 code paths of the vectorized
# CoreLib helpers all get exercised against the same checks.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: fuzz.sh <target> [seconds] [instances]}"
SECONDS_BUDGET="${2:-3600}"
INSTANCES="${3:-2}"
WORK="${SHARPFUZZ_WORK:-$HERE/.work}"
OUT="${SHARPFUZZ_OUT:-$HERE/out}/$TARGET"
# SHARPFUZZ_HARNESS: a frozen copy of the harness build, so the harness can be rebuilt while a campaign runs.
HARNESS="${SHARPFUZZ_HARNESS:-$WORK/harness}"

export DOTNET_ROOT="$WORK/dotnet"
# SharpFuzz's out-of-process server re-launches "dotnet" from PATH, so the private root goes first.
export PATH="$WORK/dotnet:$PATH"
export AFL_SKIP_BIN_CHECK=1 AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_AFFINITY="${AFL_NO_AFFINITY:-}"
# Deterministic local time for the date/time target, and a heap cap so inputs that make a
# parser allocate gigabytes fail fast with OutOfMemoryException instead of starving the box.
export TZ="${TZ:-UTC}" DOTNET_GCHeapHardLimit="${DOTNET_GCHeapHardLimit:-0x40000000}"

INPUT="$HERE/seeds/$TARGET"
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
    INPUT="-"   # resume the previous session
fi
mkdir -p "$OUT"

DICT=()
[ -f "$HERE/dict/$TARGET.dict" ] && DICT=(-x "$HERE/dict/$TARGET.dict")

pids=()
for i in $(seq 1 "$INSTANCES"); do
    isa=()
    if [ "$i" -eq 1 ]; then
        role=(-M main)
    else
        role=(-S "sec$i")
        case $((i % 3)) in
            2) isa=(DOTNET_EnableAVX512=0) ;;
            0) isa=(DOTNET_EnableAVX2=0) ;;
        esac
    fi
    env "${isa[@]}" afl-fuzz -i "$INPUT" -o "$OUT" "${role[@]}" "${DICT[@]}" -t 5000 -m none \
        -V "$SECONDS_BUDGET" -- dotnet "$HARNESS/SharpFuzzHarness.dll" "$TARGET" \
        > "$OUT/afl-${role[1]}.log" 2>&1 &
    pids+=($!)
done

echo "Started ${#pids[@]} afl-fuzz instance(s) for $TARGET (${SECONDS_BUDGET}s); logs in $OUT/afl-*.log"
wait "${pids[@]}" || true
afl-whatsup -s "$OUT" || true
