# API review transcript: dotnet/runtime#85487

**Status: not yet transcribed.**

- Source: GitHub Quick Reviews, 2023-06-01, <https://www.youtube.com/watch?v=cAbUh4CD0Qg>
- Segment: 17:22 to 35:03 (the next agenda item, runtime#85525, starts at 35:03)

YouTube was blocked by the network policy of the environment this analyzer was built in, so the captions couldn't be downloaded. Nothing below has been filled in from memory or guesswork.

To fill this in from a machine that can reach YouTube:

```sh
pip install youtube-transcript-api
python - <<'EOF'
from youtube_transcript_api import YouTubeTranscriptApi
for s in YouTubeTranscriptApi().fetch("cAbUh4CD0Qg"):
    if 17*60+22 <= s.start < 35*60+3:
        m, sec = divmod(int(s.start), 60)
        print(f"[{m:02d}:{sec:02d}] {s.text}")
EOF
```

Then compare what was said with the design in [README.md](README.md), especially anything about a code fix, exclusions, or message wording.

## Official written notes for this segment

From [dotnet/apireviews 2023/06-01-quick-reviews](https://github.com/dotnet/apireviews/blob/main/2023/06-01-quick-reviews/README.md):

> **Approved** | [#runtime/85487](https://github.com/dotnet/runtime/issues/85487#issuecomment-1572516140) | [Video](https://www.youtube.com/watch?v=cAbUh4CD0Qg&t=0h17m22s)
>
> Out of a concern of false positives, it seems like the initial version of this analyzer should be limited to those callsites where a count was passed into `string.Split`, as that pattern has a perfect analogue in the span-based split.
>
> Using uncounted string.Split in a foreach would be better handled by an iterator-based split (which we don't have yet). Other uses of uncounted split might be analyzable, but they're harder to describe, so they should probably be a different diagnostic ID (once the pattern can be analyzed) just to keep the docs/explanation sane.
>
> The suggestion regarding Trim/TrimEnd/TrimStart may have merit, but seems like it might need some more thought (as it depends heavily on what happens after the call to Trim)... and should be addressed in a separate issue, with more details/examples.
>
> Category: Performance
> Severity: Info

## Transcript

_Pending._
