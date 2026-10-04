# SharpFuzz harness for the .NET runtime libraries

Coverage-guided fuzzing of the **shipped** .NET runtime libraries (default: .NET 11.0 RC1,
`11.0.0-rc.1.26425.128`) with [SharpFuzz](https://github.com/metalnem/sharpfuzz) and AFL++.
Results: [FINDINGS.md](FINDINGS.md) (Regex, JSON) and [FINDINGS-CORELIB.md](FINDINGS-CORELIB.md)
(System.Private.CoreLib, System.Numerics.Tensors, span and array APIs).

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
   are dropped). `sharpfuzz` then instruments `System.Text.RegularExpressions`, `System.Text.Json`,
   `System.Linq` and `System.Collections`, and the instrumented copies replace the originals in the
   private root.
3. `System.Private.CoreLib` needs an explicit type list: every top-level type from
   `StripR2R --list-types` except the runtime-infrastructure prefixes in `corelib-exclude.txt`
   (instrumenting those recurses during startup). CoreLib embeds its own copy of SharpFuzz's trace
   class, which `SharpFuzzHarness/CoreLibTrace.cs` connects to the AFL map only while a target runs,
   so the harness plumbing doesn't pollute the coverage. `INSTRUMENT_CORELIB=0` keeps the stock one.
4. `System.Numerics.Tensors` is a NuGet package, so `setup.sh` fetches it, instruments it and the
   harness references the instrumented copy. `TENSORS_DLL=<path>` fuzzes a local build instead
   (e.g. of a PR branch).
5. `SharpFuzzHarness` is built with the .NET 8 SDK but compiled against the .NET 11 reference pack
   and pinned (`RuntimeFrameworkVersion`, `RollForward=Disable`) to the private runtime, so it can
   use .NET 11 APIs. It runs under AFL++ through `Fuzzer.OutOfProcess.Run`, which survives
   process-killing failures such as stack overflows.

## Targets

| Target  | Input layout | What is checked |
|---------|--------------|-----------------|
| `regex` | `[options][engines] pattern \0 input [\0 replacement]` | Parser, interpreter, `RegexCompiler` and `NonBacktracking`. On one instance, `IsMatch`/`Count`/`Match`/`EnumerateMatches` must agree. Interpreter vs `Compiled` must agree on matches, all groups/captures, `Replace` and `Split`. Interpreter vs `NonBacktracking` must agree on overall matches. `Regex.Escape`/`Unescape` round trip. |
| `json`  | `[option flags][segmentation seed] payload` | `Utf8JsonReader` contiguous vs multi-segment vs incremental (`isFinalBlock=false`) token streams, including every typed accessor. `JsonDocument` vs reader validity. Write/re-parse idempotence and `DeepEquals`. `DeepEquals` on numbers against an arbitrary-precision reference. `JsonNode` parse/serialize/`DeepClone`. `JsonSerializer` over several shapes and a POCO with ~25 property types, with a serialize/deserialize round trip. |
| `number`, `datetime`, `guid`, `version`, `enum` | see each `*Target.cs` | CoreLib parsing and formatting: all overloads (string, UTF-16 and UTF-8 spans) agree, with fuzzed `NumberFormatInfo`/`DateTimeFormatInfo`; references (BigInteger, component-wise comparison); format/parse round trips; `TryFormat` into exact and short buffers. |
| `base64`, `encoding`, `searchvalues`, `compositeformat`, `resources` | see each `*Target.cs` | Base64/Base64Url/hex against reference decoders, including streaming; `Encoding`/`Encoder`/`Decoder` chunked vs one-shot with custom fallbacks; `SearchValues` vs naive search; `CompositeFormat` vs `string.Format`; `ResourceReader` vs `ResourceSet` on raw `.resources` files. |
| `base64guard` | `[flags][dest size][seed] payload` (see `Base64GuardTarget.cs`) | Every Base64/Base64Url decoding entry point with guard-page sources and destinations of fuzzed size (run with `SHARPFUZZ_GUARD=1`), against plain arrays and the reference decoder. |
| `tensorprimitives` | `[type][op][flags][extra] elements` | Every `TensorPrimitives` element type against scalar references from `T`'s own operators: element-wise ops, min/max reductions, `IndexOf*`, bit ops, conversions exactly; floating-point sums and dot products within the rounding error bound of any summation order; in-place, misaligned, short and overlapping spans. |
| `spanops` | `[type][op][flags][k] elements` | `MemoryExtensions` over all primitive types (search, `*InRange`, `Count`, compare, `Replace`, `Reverse`, `Sort`, `BinarySearch`, `Split`/`SplitAny`, `Trim`), `System.Text.Ascii`, `BitArray`, `BinaryPrimitives.ReverseEndianness` and vectorized `Enumerable.Sum/Min/Max/Average`, against plain loops. |

Only documented exceptions are swallowed (`RegexParseException`, `RegexMatchTimeoutException`,
`JsonException`, lazily-detected invalid UTF-8/UTF-16 in strings, ...). Anything else, and any
disagreement between code paths, is reported to AFL as a crash. Findings that are already
understood are suppressed so they don't drown out new ones; set
`SHARPFUZZ_REPORT_KNOWN_ISSUES=1` to turn the suppressions off.

## Usage

```bash
./setup.sh                    # idempotent; DOTNET_VERSION=... to fuzz another runtime build
./fuzz.sh regex 3600 2        # target, seconds, AFL++ instances (1 main + N-1 secondaries)
./fuzz-many.sh 1800 3 number guid version searchvalues   # PARALLEL (default 4) targets at a time
./triage.sh regex             # replay out/regex/*/crashes and bucket by exception + top frames
./repro.sh json path/to/input # replay single inputs with full stack traces
```

Secondaries alternate between `DOTNET_EnableAVX512=0` and `DOTNET_EnableAVX2=0`, so the 512-, 256-
and 128-bit vector paths are all fuzzed. Running `fuzz.sh` again resumes from the existing
`out/<target>` corpus; the crashes and hangs of the previous run are first copied to
`out/<target>/archive/<time>/`, because afl-fuzz empties those directories when it resumes.

Environment variables:

| Variable | Used by | Meaning |
|---|---|---|
| `SHARPFUZZ_WORK`, `SHARPFUZZ_OUT` | all | toolchain directory (default `.work`) and AFL++ output root (default `out`) |
| `SHARPFUZZ_CPUS` | `fuzz.sh`, `repro.sh` | taskset CPU list (e.g. `0-5`) that caps the CPUs the fuzzers and replays use |
| `SHARPFUZZ_HARNESS` | `fuzz.sh`, `repro.sh` | harness build to use, e.g. a frozen copy so the harness can be rebuilt during a campaign |
| `SHARPFUZZ_SEEDS` | `fuzz.sh` | seed directory, e.g. the queue of an earlier campaign |
| `TENSORS_DLL` | `setup.sh` | local System.Numerics.Tensors build to instrument instead of the package |
| `SHARPFUZZ_REPORT_KNOWN_ISSUES` | harness | report the suppressed known issues |
| `SHARPFUZZ_HARNESS_SELFTEST` | harness | inputs starting with `CRASHME` throw (checks the crash path) |

`findings/Repro` is a plain console app (no instrumentation) that reproduces the findings in
FINDINGS.md and FINDINGS-CORELIB.md (except the TensorPrimitives ones, which need the package) on
whatever .NET 8+ runtime runs it.

## Layout

```
setup.sh fuzz.sh fuzz-many.sh triage.sh repro.sh   driver scripts
SharpFuzzHarness/                     the harness (Program.cs and one *Target.cs per target)
tools/StripR2R/                       ReadyToRun -> IL-only rewriter and CoreLib type lister (dnlib)
corelib-exclude.txt                   CoreLib type prefixes that are not instrumented
seeds/<target>                        seed corpora
dict/                                 AFL++ dictionaries
findings/                             minimized crash inputs and the standalone Repro app
.work/, out/                          toolchain and AFL++ output (git-ignored)
```
