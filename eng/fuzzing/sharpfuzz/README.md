# SharpFuzz harness for System.Text.RegularExpressions and System.Text.Json

Coverage-guided fuzzing of the **shipped** .NET runtime libraries (default: .NET 11.0 RC1,
`11.0.0-rc.1.26425.128`) with [SharpFuzz](https://github.com/metalnem/sharpfuzz) and AFL++.
Results of the first campaign are in [FINDINGS.md](FINDINGS.md).

This directory is self-contained and deliberately isolated from the repo's Arcade build (it has
its own `Directory.Build.props/targets`, `NuGet.config` and `global.json`). Everything it needs
comes from nuget.org, GitHub and the Ubuntu archive, so it works on a box that can't reach the
dnceng feeds.

## How it works

1. `setup.sh` downloads the `Microsoft.NETCore.App.Runtime.linux-x64` and `Microsoft.NETCore.App.Ref`
   packages for the chosen version and assembles a private dotnet root in `.work/dotnet`.
2. The framework assemblies ship as ReadyToRun (mixed-mode) images, which SharpFuzz refuses to
   instrument. `tools/StripR2R` uses dnlib to rewrite them as plain IL-only AnyCPU images (all IL
   is still present in R2R images; only the precompiled code and the OS-specific PE machine value
   are dropped). `sharpfuzz` then instruments `System.Text.RegularExpressions.dll` and
   `System.Text.Json.dll`, and the instrumented copies replace the originals in the private root.
3. `SharpFuzzHarness` is built with the .NET 8 SDK but compiled against the .NET 11 reference pack
   and pinned (`RuntimeFrameworkVersion`, `RollForward=Disable`) to the private runtime, so it can
   use .NET 11 APIs. It runs under AFL++ through `Fuzzer.OutOfProcess.Run`, which survives
   process-killing failures such as stack overflows.

## Targets

| Target  | Input layout | What is checked |
|---------|--------------|-----------------|
| `regex` | `[options][engines] pattern \0 input [\0 replacement]` | Parser, interpreter, `RegexCompiler` and `NonBacktracking`. On one instance, `IsMatch`/`Count`/`Match`/`EnumerateMatches` must agree. Interpreter vs `Compiled` must agree on matches, all groups/captures, `Replace` and `Split`. Interpreter vs `NonBacktracking` must agree on overall matches. `Regex.Escape`/`Unescape` round trip. |
| `json`  | `[option flags][segmentation seed] payload` | `Utf8JsonReader` contiguous vs multi-segment vs incremental (`isFinalBlock=false`) token streams, including every typed accessor. `JsonDocument` vs reader validity. Write/re-parse idempotence and `DeepEquals`. `DeepEquals` on numbers against an arbitrary-precision reference. `JsonNode` parse/serialize/`DeepClone`. `JsonSerializer` over several shapes and a POCO with ~25 property types, with a serialize/deserialize round trip. |

Only documented exceptions are swallowed (`RegexParseException`, `RegexMatchTimeoutException`,
`JsonException`, lazily-detected invalid UTF-8/UTF-16 in strings, ...). Anything else, and any
disagreement between code paths, is reported to AFL as a crash. Findings that are already
understood are suppressed so they don't drown out new ones; set
`SHARPFUZZ_REPORT_KNOWN_ISSUES=1` to turn the suppressions off.

## Usage

```bash
./setup.sh                    # idempotent; DOTNET_VERSION=... to fuzz another runtime build
./fuzz.sh regex 3600 2        # target, seconds, AFL++ instances (1 main + N-1 secondaries)
./fuzz.sh json 3600 2
./triage.sh regex             # replay out/regex/*/crashes and bucket by exception + top frames
./repro.sh json path/to/input # replay single inputs with full stack traces
```

Running `fuzz.sh` again resumes from the existing `out/<target>` corpus. For a self-test of the
crash path, run with `SHARPFUZZ_HARNESS_SELFTEST=1`: any input starting with `CRASHME` then throws.

`findings/Repro` is a plain console app (no instrumentation) that reproduces every finding in
FINDINGS.md on whatever .NET 8+ runtime runs it.

## Layout

```
setup.sh fuzz.sh triage.sh repro.sh   driver scripts
SharpFuzzHarness/                     the harness (Program.cs, RegexTarget.cs, JsonTarget.cs)
tools/StripR2R/                       ReadyToRun -> IL-only rewriter (dnlib)
seeds/regex, seeds/json               seed corpora (regex seeds derived from AttRegexTests.cs)
dict/                                 AFL++ dictionaries
findings/                             minimized crash inputs and the standalone Repro app
.work/, out/                          toolchain and AFL++ output (git-ignored)
```
