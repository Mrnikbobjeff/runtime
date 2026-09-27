#!/usr/bin/env bash
# Usage: triage.sh <target>
# Replays every saved crash for a target and buckets them by exception type plus the top
# System.* frames, printing one example input per bucket.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: triage.sh <target>}"
OUT="${SHARPFUZZ_OUT:-$HERE/out}/$TARGET"
shopt -s nullglob
crashes=("$OUT"/*/crashes/id:*)
if [ ${#crashes[@]} -eq 0 ]; then
    echo "No crashes for $TARGET."
    exit 0
fi

# Replay in batches of 50. If an input takes the process down (stack overflow, fail-fast, ...),
# the inputs of that batch that didn't get replayed are retried one process each, and the one
# that kills its process is reported as "ProcessDied" with the last lines it printed.
replay() { "$HERE/repro.sh" "$TARGET" "$@" > "$OUT/triage.batch" 2>&1 || true; cat "$OUT/triage.batch" >> "$OUT/triage.log"; }
replayed() { grep -qxF -e "OK    $1" -e "CRASH $1" "$OUT/triage.batch"; }
: > "$OUT/triage.log"
for ((i = 0; i < ${#crashes[@]}; i += 50)); do
    batch=("${crashes[@]:i:50}")
    replay "${batch[@]}"
    missing=()
    for f in "${batch[@]}"; do replayed "$f" || missing+=("$f"); done
    for f in "${missing[@]}"; do
        replay "$f"
        replayed "$f" || printf 'CRASH %s\nProcessDied: %s\n' "$f" "$(tail -n 3 "$OUT/triage.batch" | tr '\n' ' ')" >> "$OUT/triage.log"
    done
done
rm -f "$OUT/triage.batch"

python3 - "$OUT/triage.log" <<'EOF'
import re, sys, collections
text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
buckets = collections.OrderedDict()
for block in re.split(r'^(?=OK    |CRASH )', text, flags=re.M):
    if not block.startswith('CRASH '):
        continue
    lines = block.splitlines()
    path, exc = lines[0][6:], lines[1] if len(lines) > 1 else '?'
    kind = exc.split(':')[0]
    if kind.endswith('ConsistencyException'):
        # Bucket differential failures by what differed, not by the input-specific message:
        # drop the " for <input>" tail, quoted strings, hex blobs and numbers.
        what = exc[exc.find(':') + 1:].split(' for ')[0]
        what = re.sub(r'"(?:[^"\\]|\\.)*"', '"…"', what)
        what = re.sub(r'0x[0-9A-Fa-f]+|\d+', '#', what)
        kind += ' / ' + what.strip()[:110]
    frames = [l.strip() for l in lines[2:] if l.strip().startswith('at System.')][:3]
    key = kind + ' | ' + ' <- '.join(f.split('(')[0][3:] for f in frames)
    buckets.setdefault(key, []).append((path, exc))
for key, items in buckets.items():
    print(f'[{len(items)}] {key}\n      e.g. {items[0][0]}\n      {items[0][1][:300]}\n')
print(f'{sum(len(v) for v in buckets.values())} crashing inputs, {len(buckets)} buckets')
EOF
