# SharpFuzz findings: System.Text.RegularExpressions and System.Text.Json (.NET 11 RC1)

Campaign date: 2026-09-26. Harness and scripts: this directory (see [README.md](README.md)).

## Environment

| | |
|---|---|
| Runtime under test | .NET `11.0.0-rc.1.26425.128` (`Microsoft.NETCore.App.Runtime.linux-x64` from nuget.org), R2R stripped and SharpFuzz-instrumented `System.Text.RegularExpressions.dll` and `System.Text.Json.dll` |
| Fuzzer | AFL++ 4.09c (Ubuntu 24.04 package), SharpFuzz 2.3.0 (`Fuzzer.OutOfProcess`) |
| Build toolchain | .NET SDK 8.0.131, harness compiled against the .NET 11 RC1 reference pack |
| Machine | 4 vCPU, 15 GB RAM; each target ran 1 main + 1 secondary AFL++ instance, both targets concurrently |

This repository's `master` (Aug 2020) could not be built here, because the dnceng package feeds and
the SDK download CDN are blocked from this machine. So the campaign targeted the shipped .NET 11
RC1 binaries instead. Where it was easy to tell, the notes below say whether the same code is
present in this fork's 2020 sources.

## Campaign statistics

_Campaign still running when this draft was committed; final numbers follow in the next commit._

## Summary of findings

| ID | Component | Kind | Severity (my assessment) | Also in |
|----|-----------|------|--------------------------|---------|
| [REGEX-1](#regex-1) | `RegexParser` | Unhandled `IndexOutOfRangeException` from the `Regex` constructor | Low | .NET 8, 9, 10; this fork's 2020 source |
| [REGEX-2](#regex-2) | `NonBacktracking` | Wrong match result (leftmost match skipped) | Medium | .NET 8, 9, 10 |
| [REGEX-3](#regex-3) | `NonBacktracking` | Wrong match result (alternation priority with an empty branch) | Medium | .NET 8, 9, 10 |
| [REGEX-4](#regex-4) | `NonBacktracking` | Successful match reports a mandatory group as unmatched | Medium | .NET 8, 9, 10 |
| [REGEX-5](#regex-5) | Interpreter and `RegexCompiler` | Match timeout not enforced for forward-only counted loops | Medium (DoS with untrusted patterns) | .NET 8 |
| [JSON-1](#json-1) | `JsonElement/JsonNode.DeepEquals` | `ArgumentOutOfRangeException` for valid numbers with large exponents | Low | .NET 9, 10 |
| [JSON-2](#json-2) | `JsonSerializer` | Out-of-range literals read as ±Infinity but can't be written back | Informational (by design) | .NET 8, 9, 10 |
| [JSON-3](#json-3) | `JsonElement/JsonNode.DeepEquals` | Wrong result: int overflow makes different numbers compare equal | Low–Medium | .NET 9, 10 |

"Also in" was checked by running [`findings/Repro`](findings/Repro) on the stock runtimes
8.0.31, 9.0.20, 10.0.12 and 11.0.0-rc.1 (`DeepEquals` only exists from .NET 9). None of these
has been checked against the dotnet/runtime issue tracker; github.com web access was blocked
from the fuzzing machine. Minimized harness inputs are in [`findings/inputs`](findings/inputs);
replay them with `SHARPFUZZ_REPORT_KNOWN_ISSUES=1 ./repro.sh <target> findings/inputs/<ID>`.

---

### REGEX-1

**`new Regex("[^", RegexOptions.ECMAScript)` throws `IndexOutOfRangeException` instead of `RegexParseException`.**

```csharp
new Regex("[^", RegexOptions.ECMAScript);   // System.IndexOutOfRangeException
new Regex("[^");                            // RegexParseException (UnterminatedBracket), as expected
```

```
System.IndexOutOfRangeException: Index was outside the bounds of the array.
   at System.Text.RegularExpressions.RegexParser.ScanCharClass(Boolean caseInsensitive, Boolean scanOnly)
   at System.Text.RegularExpressions.RegexParser.CountCaptures(RegexOptions& optionsFoundInPattern)
   at System.Text.RegularExpressions.RegexParser.Parse(String pattern, RegexOptions options, CultureInfo culture)
   at System.Text.RegularExpressions.Regex..ctor(String pattern, RegexOptions options, TimeSpan matchTimeout)
```

Root cause: after consuming the `^` of a negated class, `ScanCharClass` checks
`_pattern[_pos] == ']'` for the ECMAScript "`[^]`" rule without first checking
`_pos < _pattern.Length`. The same check for nested subtraction classes, a few lines further
down, does include the bounds check. It's the same in dotnet/runtime `main` (`33baf8ee`,
2026-09-26) and in this fork's 2020 source
(`src/libraries/System.Text.RegularExpressions/src/System/Text/RegularExpressions/RegexParser.cs:568`,
`CharAt(_currentPos) == ']'`). Any ECMAScript pattern that ends in `[^` triggers it (`a[^`,
`(?:[^`, ...). Code that validates untrusted patterns by catching `ArgumentException` will let
this exception escape. Suggested fix: `_pos < _pattern.Length && _pattern[_pos] == ']'`.

### REGEX-2

**NonBacktracking skips the leftmost match when an earlier character could have started one.**

```csharp
Regex.Match("0axx", "0?x").Index                                   // 2
Regex.Match("0axx", "0?x", RegexOptions.NonBacktracking).Index     // 3   <-- wrong
Regex.Matches("0axx", "0?x", RegexOptions.NonBacktracking)         // only [3..4), the match at 2 is lost
Regex.Match("braa", "(b?)a", RegexOptions.NonBacktracking).Index   // 3 (backtracking: 2)
```

The shape is: an optional prefix char `c?` followed by `x`, and an input where `c` occurs, is
followed by a non-matching char, and then `xx` comes. The shortest failing inputs over `{0,?,x,a}`
all look like `0?xx`, `0axx`, `00?xx`, `0?x?x`. The first match found is wrong, not only
later ones, so `IsMatch` agrees but `Match`, `Matches`, `Replace`, `Split` and `Count` give
different answers than the backtracking engines. The documentation says NonBacktracking finds
the same matches.

### REGEX-3

**NonBacktracking ignores alternation priority when a middle branch is empty.**

```csharp
Regex.Match("hh", "(x||.)h")                                    // 0:1  (empty branch, then 'h')
Regex.Match("hh", "(x||.)h", RegexOptions.NonBacktracking)      // 0:2  <-- '.' branch preferred
Regex.Match("x",  "(a||.)*", RegexOptions.NonBacktracking)      // 0:1  (backtracking: 0:0)
```

Two-branch forms (`(x|)h`, `(|.)h`) behave correctly. Three or more branches with an empty
branch before a non-empty one don't. The fuzzer produced about a dozen variants (`(e||.)*`,
`((..)||(.))*`, `(\u001E||.)*`, ...) that all reduce to this.

### REGEX-4

**NonBacktracking reports a successful match in which a mandatory capture group didn't participate.**

```csharp
var m = Regex.Match("xx", @"x*(\Bx)", RegexOptions.NonBacktracking);
// m.Success == true, m.Value == "xx", but m.Groups[1].Success == false
// backtracking: Groups[1] == "x" at 1
Regex.Split("aaaa", @"a*(\Ba.|a`)", RegexOptions.NonBacktracking)   // ["", ""]  (backtracking: ["", "aa", ""])
```

It needs a `*` loop followed by a group starting with a `\B` anchor. `a+(\Ba)`, `a(\Ba)` and
`a*(\B.)` are fine. The overall match is right, but the capture pass loses the group, so any
code that reads the group (including `Split`, `Replace` with `$1`, `Groups`) gets wrong
results. This is beyond the documented NonBacktracking capture differences, which only concern
which iteration a capture reflects, not whether a mandatory group matched.

### REGEX-5

**The match timeout is not enforced for forward-only counted loops.**

```csharp
var r = new Regex("(a*){22222222}(x)", RegexOptions.None, TimeSpan.FromMilliseconds(250));
r.IsMatch("x");   // returns true after ~3.7 s; no RegexMatchTimeoutException
// RegexOptions.Compiled: ~16.7 s. Time grows linearly with the repeat count.
```

AFL++ flagged this as a hang (the harness uses a 250 ms match timeout and AFL a 5 s execution
limit). Under the instrumented harness the saved input runs for ~38 s. Minimal forms: `(){N}x`,
`(a?){N}x`, `(a*){N}` with N in the millions. The group must be capturing, because
`(?:a*){N}` is optimized away.

Root cause (interpreter): `CheckTimeout()` is only called in `Backtrack()`, once per starting
position in `Scan`, and in lookarounds. A counted loop that hasn't reached its minimum takes the
forward `Branchcount` path (`StackPush(runtextpos, count + 1); Goto(...)`) N times without ever
backtracking, so no timeout check runs. `RegexCompiler` appears to have the same structure.

Match timeouts are the documented mitigation for running untrusted patterns
([best practices](https://learn.microsoft.com/dotnet/standard/base-types/best-practices-regex#use-time-out-values)),
and one ~20-character pattern can hold a thread for minutes regardless of the timeout. Because
this is a denial-of-service against the documented mitigation, consider reporting it privately
(MSRC) rather than in a public issue.

Side observation: on .NET 8.0.31, `(?:){2222222}x` also crashes the interpreter with
`IndexOutOfRangeException` in `RegexInterpreter.TrackPush`. That no longer reproduces on 11 RC1.

### JSON-1

**`JsonElement.DeepEquals` / `JsonNode.DeepEquals` throw for valid JSON numbers whose exponent doesn't fit in an `int`.**

```csharp
using var a = JsonDocument.Parse("0e99999999999");
JsonElement.DeepEquals(a.RootElement, a.RootElement);
// ArgumentOutOfRangeException: The exponent value in the specified JSON number is too large. (Parameter 'exponent')
```

`JsonHelpers.AreEqualJsonNumbers` parses the exponent with `Utf8Parser.TryParse(..., out int)`
and throws when that fails. The throw is explicit (`ThrowArgumentOutOfRangeException_JsonNumberExponentTooLarge`),
so it may be an intentional limitation. Still, the document parsed fine; comparing an element
with *itself* throws; the exception names a parameter (`exponent`) that `DeepEquals` doesn't
have; and `0e99999999999` is just zero. A `BigInteger` or saturating exponent comparison would
avoid it.

### JSON-2

**Out-of-range numeric literals deserialize to ±Infinity but can't be serialized back with default options.**

```csharp
double d = JsonSerializer.Deserialize<double>("1e400");   // double.PositiveInfinity
JsonSerializer.Serialize(d);                               // ArgumentException: .NET number values such as positive and negative infinity cannot be written as valid JSON
```

This follows from the IEEE-compliant parsing change in .NET Core 3.0 (overflow rounds to
infinity, and `Utf8JsonReader.TryGetDouble` returns `true`). It's recorded as by design and
suppressed in the harness, but it's a read/write asymmetry worth knowing about: a payload
accepted by `Deserialize` can make a later `Serialize` of the same object graph throw.

### JSON-3

**`DeepEquals` returns `true` for different numbers because the normalized exponent overflows.**

```csharp
static bool Eq(string a, string b) => JsonElement.DeepEquals(JsonDocument.Parse(a).RootElement, JsonDocument.Parse(b).RootElement);
Eq("10e2147483647", "1e-2147483648");    // true   (1e2147483648 vs 1e-2147483648)
Eq("0.1e-2147483648", "1e2147483647");   // true   (1e-2147483649 vs 1e2147483647)
Eq("100e2147483647", "1e-2147483647");   // true
// JsonNode.DeepEquals behaves the same
```

Found while analysing JSON-1. The harness's `DeepEquals` reference oracle (arbitrary-precision
exponents) now catches it. In `AreEqualJsonNumbers`/`ParseNumber`, the exponent is parsed into
an `int` and then adjusted with unchecked arithmetic: `exp += intg.Length - fz` (trailing zeros),
`exp -= lz + 1` (leading fractional zeros) and `exp -= frac.Length`. Near `int.MaxValue` or
`int.MinValue` these wrap, so a huge number and a tiny one normalize to the same
(sign, digits, exponent) triple. `DeepEquals` is used to compare untrusted documents, for example
de-duplication and change detection, so a silent wrong `true` is worse than the exception in
JSON-1. Doing the arithmetic in `long` (or `checked`, falling back to a slow path) fixes both.

---

## Harness false positives fixed during the campaign

These were raised by the first versions of the harness and turned out to be documented
behaviour; the harness now accepts them:

- `Utf8JsonReader.GetString()`/`GetComment()`/`CopyString()` and `JsonDocument` validate UTF-8 and
  `\uXXXX` surrogate pairs lazily. Invalid text surfaces as `InvalidOperationException` when a
  string is materialized, not as `JsonException` while reading.
- `JsonObject` can't hold duplicate (or, with `PropertyNameCaseInsensitive`, case-insensitively
  duplicate) keys. `JsonNode.Parse` succeeds and the `ArgumentException` surfaces when the object
  is first enumerated.

## Limitations

- The fork's own `master` (Aug 2020) was not fuzzed, because it can't be built without the
  dnceng feeds. REGEX-1 is confirmed in its source; the NonBacktracking engine (REGEX-2..4) and
  `DeepEquals` (JSON-1, JSON-3) didn't exist yet in 2020.
- Stripping ReadyToRun code means everything in the two target assemblies is JIT-compiled with
  instrumentation, and only those two assemblies are instrumented. Coverage inside CoreLib
  (e.g. `double.Parse`, `Utf8Parser`, `Base64`) doesn't guide the fuzzer.
- The NonBacktracking comparison only covers overall match positions plus `Replace`/`Split`.
  Capture positions are intentionally not compared, because their semantics differ by design.
- Campaign length was short (about 45 minutes per target, on 2 cores each). Longer runs, and
  AFL++ CmpLog (not available for managed code), would likely go deeper.
