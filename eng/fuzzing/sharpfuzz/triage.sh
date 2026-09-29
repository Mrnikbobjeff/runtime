#!/usr/bin/env bash
# Usage: triage.sh <regex|json>
# Replays every saved crash for a target and buckets them by exception type plus the top
# System.* frames, printing one example input per bucket.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:?usage: triage.sh <regex|json>}"
shopt -s nullglob
crashes=("$HERE"/out/"$TARGET"/*/crashes/id:*)
if [ ${#crashes[@]} -eq 0 ]; then
    echo "No crashes for $TARGET."
    exit 0
fi

"$HERE/repro.sh" "$TARGET" "${crashes[@]}" > "$HERE/out/$TARGET/triage.log" 2>&1 || true

python3 - "$HERE/out/$TARGET/triage.log" <<'EOF'
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
        # Bucket differential failures by what differed, not by the input-specific message.
        m = re.search(r'(mismatch for|differ at|\bnot\b|false|!=|accepted|rejected)', exc)
        kind += ' / ' + (exc.split(':')[1].strip()[:60] if m is None else exc[exc.find(':')+1:].split(' for ')[0].strip()[:60])
    frames = [l.strip() for l in lines[2:] if l.strip().startswith('at System.')][:3]
    key = kind + ' | ' + ' <- '.join(f.split('(')[0][3:] for f in frames)
    buckets.setdefault(key, []).append((path, exc))
for key, items in buckets.items():
    print(f'[{len(items)}] {key}\n      e.g. {items[0][0]}\n      {items[0][1][:300]}\n')
print(f'{sum(len(v) for v in buckets.values())} crashing inputs, {len(buckets)} buckets')
EOF
