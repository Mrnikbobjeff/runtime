# SharpFuzz findings: System.Private.CoreLib, System.Numerics.Tensors, span and array APIs (.NET 11 RC1)

Campaign date: 2026-09-26/27. Harness and scripts: this directory (see [README.md](README.md)). The
first campaign (Regex, JSON) is in [FINDINGS.md](FINDINGS.md).

## Environment

| | |
|---|---|
| Runtime under test | .NET `11.0.0-rc.1.26425.128` (`Microsoft.NETCore.App.Runtime.linux-x64`), with R2R stripped and SharpFuzz-instrumented `System.Private.CoreLib` (1,026 of 1,911 top-level types, see `corelib-exclude.txt`), `System.Linq`, `System.Collections`, `System.Text.RegularExpressions` and `System.Text.Json` |
| System.Numerics.Tensors | The `11.0.0-rc.1.26425.128` NuGet package, and local builds of the `tensorprimitives-block-reductions` and `argmin-blocks` branches (`TENSORS_DLL=...`) |
| Fuzzer | AFL++ 4.00c (Ubuntu 22.04 under WSL2), SharpFuzz 2.3.0 (`Fuzzer.OutOfProcess`) |
| Machine | Ryzen 7 7800X3D (8 cores / 16 threads, AVX-512). Fuzzers pinned with `SHARPFUZZ_CPUS` (taskset) to at most 12 threads. Each campaign ran one main instance with the full ISA and secondaries with `DOTNET_EnableAVX512=0` / `DOTNET_EnableAVX2=0`, so the Vector512/256/128 paths are all covered. |

Every finding below was reproduced on the stock (uninstrumented) runtimes 8.0.31, 9.0.20, 10.0.12
and 11.0 RC1 with [`findings/Repro`](findings/Repro) (CoreLib and LINQ findings) or with the
snippets shown (TensorPrimitives, which is a NuGet package). None of them has been checked against
the dotnet/runtime issue tracker yet.

## Campaign statistics

| Target | Assemblies | Wall-clock | Execs | Edges | Result |
|---|---|---|---|---|---|
| `number`, `guid`, `version`, `searchvalues` | CoreLib | 30 min each (3 instances) | 7.0 M / 6.6 M / 19.3 M / 27.7 M | 11.6 k / 4.2 k / 4.1 k / 10.5 k | NUMBER-NEGZERO-1, BIGINTEGER-EXP-1 (the 108 hangs), UTF8 symbol issue (withheld); guid crashes were all a harness false positive |
| `base64`, `compositeformat`, `resources` | CoreLib | 10–30 min (Sep 26) | | | BASE64-STREAM-1, COMPOSITEFORMAT-1/2, RESOURCES-1 |
| `datetime` (TimeSpan part) | CoreLib | 30 min (Sep 26) | | | TIMESPAN-1 |
| `tensorprimitives` | Tensors 11.0 RC1 package | 60 min (3 instances) | 51.9 M | 15.9 k | TENSORS-NUMBER-NAN-1, TENSORS-COPYSIGN-1, TENSORS-HALF-FMA-1 |
| `tensorprimitives` | Tensors, `tensorprimitives-block-reductions` branch | 60 min (2 instances) | 58.3 M | 16.3 k | no new findings |
| `tensorprimitives` | Tensors, `argmin-blocks` branch | 60 min (3 instances) | 46.3 M | 16.1 k | no new findings |
| `spanops` | CoreLib, System.Linq, System.Collections | 3 × 60 min (3 instances) | SPANOPS_EXECS | SPANOPS_EDGES | LINQ-SUM-1 |

CoreLib's `datetime`, `encoding` and `enum` targets were triaged by a parallel session on branch
`feature/sharpfuzz-corelib-instrument-fc6ce9` (see the FINDINGS.md there); those results are not
repeated or re-verified here.

## Summary of findings

| ID | Component | Kind | Severity (my assessment) | Also in |
|----|-----------|------|--------------------------|---------|
| [TIMESPAN-1](#timespan-1) | `TimeSpanParse` | `TimeSpan.TryParse` throws `IndexOutOfRangeException` | Medium | .NET 9, 10 (regression; 8 returns 0) |
| [COMPOSITEFORMAT-1](#compositeformat-1) | `CompositeFormat.Parse` | Index/alignment overflow: formats the wrong argument, throws `IndexOutOfRangeException` | Medium | .NET 8, 9, 10 |
| [BASE64-STREAM-1](#base64-stream-1) | `Base64`/`Base64Url.DecodeFromUtf8` | Streaming decode (`isFinalBlock: false`) rejects valid input with whitespace | Medium | .NET 8, 9, 10 |
| [TENSORS-NUMBER-NAN-1](#tensors-number-nan-1) | `TensorPrimitives` | `MaxNumber`/`MinNumber`/`Max`-/`MinMagnitudeNumber` reductions return NaN when any element is NaN | Medium | still in main and both branches |
| [TENSORS-COPYSIGN-1](#tensors-copysign-1) | `TensorPrimitives.CopySign` | Integer `CopySign(MinValue, +)` gives `MinValue` on the vector path, throws elsewhere | Low–Medium | |
| [TENSORS-HALF-FMA-1](#tensors-half-fma-1) | `TensorPrimitives.FusedMultiplyAdd` | `Half` FMA rounds twice on the vector path | Low | |
| [BIGINTEGER-EXP-1](#biginteger-exp-1) | `BigInteger.Parse` | Huge exponents are materialized: an 11-byte input takes a minute and 300 MB | Low–Medium (DoS with untrusted input) | not checked |
| [LINQ-SUM-1](#linq-sum-1) | `Enumerable.Sum` | Overflow detection is per SIMD lane: throws for sums that fit, depending on length and CPU | Low | .NET 8, 9, 10 |
| [RESOURCES-1](#resources-1) | `ResourceReader` | Unchecked header counts (~1 GB allocation from a 206-byte file) and undocumented exceptions on corrupt files | Low | .NET 8, 9, 10 |
| [NUMBER-NEGZERO-1](#number-negzero-1) | `Number.Parsing` | Unsigned `TryParse` accepts `"-0"`/`"-0e5"` but rejects `"-0.0"` | Low | .NET 8, 9, 10 |
| [COMPOSITEFORMAT-2](#compositeformat-2) | `CompositeFormat.Parse` | `"{0:}"` passes `""` where `string.Format` passes `null` | Informational | .NET 8, 9, 10 |

One further finding, in UTF-8 number parsing with custom `NumberFormatInfo` symbols, is not
described here because it may have security impact; it should go through the Microsoft Security
Response Center rather than a public issue. The harness suppresses it as `UTF8CASE-1`.

Replay the saved inputs with `SHARPFUZZ_REPORT_KNOWN_ISSUES=1 ./repro.sh <target> <input>`; without
that variable the harness suppresses every finding in this document so that new ones stand out.

---

### TIMESPAN-1

**`TimeSpan.TryParse("0:0:0.0000000123456789")` throws `IndexOutOfRangeException`.** `Parse` throws
it too, instead of `FormatException`/`OverflowException`.

`TimeSpanToken.NormalizeAndValidateFraction` (`TimeSpanParse.cs`) handles a fraction with 1–7
leading zeros and more than 7 significant digits by dividing by
`Pow10UpToMaxFractionDigits(totalDigitsCount - MaxFractionDigits)`, which indexes an 8-entry table.
With 7 zeros and 9 more digits, `totalDigitsCount - 7` is 9. The code only asserts
(`Debug.Assert(totalDigitsCount - MaxFractionDigits <= MaxFractionDigits)`) what the input can
violate. .NET 8 returned `00:00:00` for the same input, so this regressed in .NET 9. Anything that
parses user-supplied time spans with `TryParse` can be made to throw.

### COMPOSITEFORMAT-1

**`CompositeFormat.Parse` doesn't enforce `string.Format`'s index and alignment limits, so they
overflow `int`.**

```csharp
string.Format(null, "{4294967297}", "a", "b");                            // FormatException
string.Format(null, CompositeFormat.Parse("{4294967297}"), "a", "b");     // "b"
string.Format(null, CompositeFormat.Parse("{7777777771}"), "a", "b", "c"); // IndexOutOfRangeException (.NET 11); .NET 8-10 return the format text
CompositeFormat.Parse("{0,4294967298}");                                  // accepted as alignment 2
```

`ValueStringBuilder.AppendFormatHelper` and `StringBuilder.AppendFormat` stop accumulating digits at
`IndexLimit`/`WidthLimit` (1,000,000). The parsing loop copied into
`CompositeFormat.TryParseLiterals` dropped those limits, so `index = index * 10 + digit` wraps. A
wrapped index can be small and positive (silently selecting another argument), or negative, in
which case `MinimumArgumentCount` doesn't cover it and `string.Format<TArg0, TArg1, TArg2>` indexes
`args[index]` out of range. Alignments wrap the same way, and alignments between 1,000,000 and
`int.MaxValue` are accepted and allocated. This matters wherever format strings come from
resources or configuration.

### BASE64-STREAM-1

**Streaming `Base64.DecodeFromUtf8` / `Base64Url.DecodeFromUtf8` with `isFinalBlock: false` return
`InvalidData` for valid input that contains whitespace, depending on where the chunk ends.**

```csharp
byte[] input = "S\r\nGVsbG8gV29y"u8.ToArray();                  // "Hello Wor"
Base64.DecodeFromUtf8(input.AsSpan(0, 7), output, out int consumed, out int written, isFinalBlock: false);
// InvalidData (consumed 2, written 0); the whole input in one call decodes fine
Base64Url.DecodeFromUtf8("AAA AA"u8, output, out _, out _, isFinalBlock: false); // InvalidData
```

The same bytes decode in one call, so the problem is in how the whitespace fallback handles a chunk
that ends inside a whitespace-interrupted block when `isFinalBlock` is false; it should return
`NeedMoreData` (not root-caused further). A caller that
decodes a stream chunk by chunk, carrying unconsumed bytes over (the documented pattern), rejects
valid Base64 with line breaks depending on its buffer size.

### TENSORS-NUMBER-NAN-1

**`TensorPrimitives.MaxNumber`, `MinNumber`, `MaxMagnitudeNumber` and `MinMagnitudeNumber` (the span
reductions) return NaN as soon as any element is NaN.** They are documented to match IEEE
754:2019 `maximumNumber`/`minimumNumber`, which only return NaN if every element is NaN.

```csharp
float[] x = [1, 2, float.NaN, 4];
TensorPrimitives.MaxNumber<float>(x); // NaN, expected 4 (float.MaxNumber folded over x gives 4)
TensorPrimitives.MinNumber<float>(x); // NaN, expected 1
```

This happens at every length (scalar and vector paths), on every ISA, and for `float`, `double`
and `Half`. The four methods call `MinMaxCore<T, TOperator>` (or `TryMinMaxHalfAsInt16`), which
returns early with the first NaN it sees. That is right for `Max`/`Min`/`MaxMagnitude`/
`MinMagnitude`, which propagate NaN, but not for the `*Number` operators. The element-wise overloads
(`MaxNumber(x, y, destination)`) are correct. The code is unchanged in current main and in the
`tensorprimitives-block-reductions` branch, which rewrites `MinMaxCore`, so the fix could go there:
skip the NaN early exit (and ignore NaN lanes) when `TOperator` is a `*Number` operator.

### TENSORS-COPYSIGN-1

**For signed integers, `TensorPrimitives.CopySign(x, sign, destination)` turns
`CopySign(MinValue, +)` into `MinValue` on the vector path, and throws `OverflowException` on the
scalar path.** The method is documented as `destination[i] = T.CopySign(x[i], sign[i])`, and
`int.CopySign(int.MinValue, 1)` throws, as does `TensorPrimitives.Abs`.

```csharp
int[] x = [5, 5, 5, int.MinValue], sign = [1, 1, 1, 1], d = new int[4];
TensorPrimitives.CopySign<int>(x, sign, d); // d[3] = int.MinValue (negative)
// 3 elements, or DOTNET_EnableHWIntrinsic=0: OverflowException
```

So the result depends on the span length and on the hardware, and the vector result has the wrong
sign. Either throw consistently, as `Abs` does, or document the wrapping behaviour for all paths.

### TENSORS-HALF-FMA-1

**`TensorPrimitives.FusedMultiplyAdd` for `Half` rounds twice on the vector path (8+ elements):
once to `float`, then to `Half`.**

```csharp
Half x = (Half)8616f, y = (Half)0.00046420097f;          // x*y + x = 8619.99955...
Half[] xs = Enumerable.Repeat(x, 8).ToArray(), d = new Half[8];
TensorPrimitives.FusedMultiplyAdd<Half>(xs, Enumerable.Repeat(y, 8).ToArray(), xs, d);
// d[0] = 8624; Half.FusedMultiplyAdd(x, y, x) = 8616 (correctly rounded); 7 elements give 8616
```

The exact result 8619.99955 rounds to `float` as exactly 8620, which is a tie in `Half` and rounds
to even (8624). Computing the widened FMA in `double` (exact for `Half` inputs) before narrowing
would give single rounding. This only affects the last bit, but FMA's point is single rounding, and
the result again depends on the span length.

### BIGINTEGER-EXP-1

**`BigInteger.Parse`/`TryParse` with `NumberStyles.AllowExponent` (part of `Float` and `Any`)
compute the full value of the exponent, so a few bytes of input cost minutes of CPU
and hundreds of megabytes.**

| Input | Time | Peak RSS |
|---|---|---|
| `BigInteger.TryParse("1e10000000", NumberStyles.Float, ...)` | 2.4 s | 59 MB |
| `BigInteger.TryParse("1e100000000", NumberStyles.Float, ...)` | 57 s | 292 MB |
| `BigInteger.TryParse("50e854775808", NumberStyles.Float, ...)` | > 180 s (killed) | > 700 MB |

(Stock 11.0 RC1, one thread.) The primitive integer types reject the same strings in under a
millisecond. This was found indirectly: all 108 hangs saved by the `number` target were the
harness's `BigInteger` reference check running on such inputs. `BigInteger` values that large are
legitimate, but a parser that accepts untrusted text with `AllowExponent` gives an attacker a
cheap amplification. A documented cap on the exponent (or on the resulting size), or at least a
note in the docs, would help. Older runtimes were not measured.

### LINQ-SUM-1

**`Enumerable.Sum(int[])`/`Sum(long[])` throw `OverflowException` for inputs whose total fits and
whose running sum never overflows, depending on the array length and the CPU's vector width.**

```csharp
var x = new int[32];
x[0] = int.MinValue; x[1] = int.MaxValue; x[8] = -1;     // total -2
x.Sum();          // OverflowException on AVX2 (8 lanes): x[0] and x[8] share a lane
x[..31].Sum();    // -2: shorter than 4 vectors, so the scalar loop runs
// SSE only (DOTNET_EnableAVX2=0, 4 lanes): throws from 16 elements; DOTNET_EnableHWIntrinsic=0: -2
```

`SumSignedIntegersVectorized` tracks overflow per lane. That throws whenever a lane's partial sum
overflows, which is neither the documented condition ("the sum is larger than MaxValue") nor the
sequential one the scalar path uses. It has been like this since the vectorization in .NET 8. It is
a deliberate trade-off, but the behaviour depends on hardware, so it should at least be documented.

### RESOURCES-1

**`ResourceReader` trusts counts and offsets from the file header.** A valid 206-byte `.resources`
file with the resource count patched to `0x10000000` makes `new ResourceReader(stream)` allocate
1 GB (`_nameHashes = new int[_numResources]`, then `_namePositions`) before it fails with
`BadImageFormatException`. `int.MaxValue` counts throw `OutOfMemoryException` ("Array dimensions
exceeded supported range") instead. Corrupt offsets and lengths elsewhere surface as
`ArgumentOutOfRangeException` from `MemoryStream.Seek`/`Position` and `BinaryReader.ReadBytes(-1)`,
or as `IOException` from `BinaryReader.ReadString`/`ReadDecimal`, instead of
`BadImageFormatException`. Validating counts against the stream length would fix both the
allocation and the exception types. Low severity, because `.resources` files normally come from
the application itself.

### NUMBER-NEGZERO-1

**Unsigned integer parsing accepts `"-0"` and `"-0e5"` but rejects `"-0."`/`"-0.0"`** with
`NumberStyles.Float`, while signed types, `decimal` and `BigInteger` accept all of them as 0. Minor,
but inconsistent: a negative zero is either acceptable for unsigned types or it isn't.

### COMPOSITEFORMAT-2

**For an empty item format (`"{0:}"`), `string.Format` passes `format: null` to
`IFormattable.ToString`, but `CompositeFormat` passes `""`** (`CompositeFormat.cs` uses
`.ToString()` on the empty slice; `ValueStringBuilder.AppendFormatHelper` keeps `null`). Custom
`IFormattable` implementations that distinguish the two format differently depending on the API.

---

## Harness false positives fixed during the campaign

These were raised by the first versions of the targets and turned out to be documented behaviour:

- `Base64Url.TryDecodeFromChars`/`TryDecodeFromUtf8` throw `FormatException` for invalid input
  (documented); they return `false` only for a short destination. `Base64Url` accepts partial and
  `%` padding (`"QQ="`, `"QQ%%"`).
- `new Guid(string)` throws `OverflowException` (not `FormatException`) for an overflowing component
  of the `{0x...}` format: deliberate compat behaviour (`GuidParseThrowStyle.All`).
- `SplitAny` with no separators splits `char` spans on all Unicode whitespace (documented).
- `Enumerable.Sum` checks overflow of running sums, not only of the total.
- `TensorPrimitives.SumOfMagnitudes` throws `OverflowException` for integer `MinValue` (as `T.Abs`
  does). Integer `Divide` may report the `MinValue / -1` overflow or the zero divisor first.

## Limitations

- `datetime`, `encoding` and `enum` findings from the Sep 26 runs were triaged by the parallel
  session (branch `feature/sharpfuzz-corelib-instrument-fc6ce9`), not here.
- Coverage feedback only comes from managed code, so the JIT's lowering of vector intrinsics is
  exercised only through the differential checks and the ISA-varied secondaries.
- Campaigns were short (30–60 minutes per target) and shared 12 hardware threads.
