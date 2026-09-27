#!/usr/bin/env bash
# Usage: fuzz-many.sh <seconds> <instances-per-target> <target>...
# Runs fuzz.sh for each target, PARALLEL (default 4) targets at a time, then prints a summary.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECONDS_BUDGET="${1:?usage: fuzz-many.sh <seconds> <instances> <target>...}"
INSTANCES="${2:?usage: fuzz-many.sh <seconds> <instances> <target>...}"
shift 2
[ $# -gt 0 ] || { echo "no targets given" >&2; exit 2; }

printf '%s\n' "$@" | xargs -P "${PARALLEL:-4}" -I{} "$HERE/fuzz.sh" {} "$SECONDS_BUDGET" "$INSTANCES" > /dev/null

OUT="${SHARPFUZZ_OUT:-$HERE/out}"
printf '%-16s %12s %10s %8s %8s %8s %8s\n' target execs execs/s edges corpus crashes hangs
for t in "$@"; do
    awk -v t="$t" -F' *: *' '
        $1 == "execs_done" { e += $2 } $1 == "execs_per_sec" { s += $2 } $1 == "edges_found" && $2 > edges { edges = $2 }
        $1 == "corpus_count" { c += $2 } $1 == "saved_crashes" { cr += $2 } $1 == "saved_hangs" { h += $2 }
        END { printf "%-16s %12d %10.0f %8d %8d %8d %8d\n", t, e, s, edges, c, cr, h }' "$OUT/$t"/*/fuzzer_stats
done
