# SharpFuzz findings: System.Private.CoreLib, System.Numerics.Tensors, span and array APIs (.NET 11 RC1)

Campaign dates: 2026-09-26/27 (CoreLib, Tensors, span APIs), 2026-09-28 morning (collections, Uri, BigInteger, ASN.1, metadata) and 2026-09-28 afternoon ([round 3](#round-3-2026-09-28)) and evening ([round 4](#round-4-2026-09-28-evening-more-code-built-on-unsafe--pointers)). Harness and scripts: this directory (see [README.md](README.md)). The
first campaign (Regex, JSON) is in [FINDINGS.md](FINDINGS.md).

## Environment

| | |
|---|---|
| Runtime under test | .NET `11.0.0-rc.1.26425.128` (`Microsoft.NETCore.App.Runtime.linux-x64`), with R2R stripped and SharpFuzz-instrumented `System.Private.CoreLib` (1,026 of 1,911 top-level types, see `corelib-exclude.txt`), `System.Linq`, `System.Collections`, `System.Collections.Immutable`, `System.Private.Uri`, `System.Runtime.Numerics`, `System.Formats.Asn1`, `System.Reflection.Metadata`, `System.Text.RegularExpressions` and `System.Text.Json`; in round 3 also `System.Net.ServerSentEvents`, `System.Data.Common`, `System.Diagnostics.DiagnosticSource`, `System.Net.Mail`, `System.Text.Encoding.CodePages`, `System.Memory`, `System.Net.Primitives`, `System.Web.HttpUtility`, `System.Linq.AsyncEnumerable`, `System.Private.Xml`, `System.Private.DataContractSerialization`, `System.Security.Cryptography`, `System.Threading.Channels` and `System.Text.Encodings.Web`, and the NuGet packages `System.Formats.Cbor`, `System.IO.Hashing`, `System.Security.Cryptography.Pkcs` and `System.Security.Cryptography.Cose` (11.0 RC1) |
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
| `tensorprimitives` | Tensors 10.0.12 and 11.0 RC1 packages | 60 min (3 instances) | 51.9 M | 15.9 k | TENSORS-NUMBER-NAN-1, TENSORS-COPYSIGN-1, TENSORS-HALF-FMA-1 |
| `tensorprimitives` | Tensors, `tensorprimitives-block-reductions` branch | 60 min (2 instances) | 58.3 M | 16.3 k | no new findings |
| `tensorprimitives` | Tensors, `argmin-blocks` branch | 60 + 120 min (3 instances) | 134.4 M | 16.1 k | no new findings |
| `utf8parser` | CoreLib (`Utf8Parser`, `Utf8Formatter`) | 40 + 60 min (2–3 instances) | 103.2 M | 10.1 k | UTF8PARSER-FLOAT-1, UTF8PARSER-DECIMAL-1 |
| `spanops` | CoreLib, System.Linq, System.Collections | 3 × 60 min (3 instances) | 141.6 M | 16.3 k | LINQ-SUM-1 |
| `collections` | System.Collections.Immutable (Frozen*, Immutable*), OrderedDictionary | 60 min (3 instances) | 7.2 M | 9.9 k | no findings |
| `uri` | System.Private.Uri | 3 runs, 85 min total (2–3 instances) | 49.8 M | 10.2 k | URI-HOST-1, URI-IDN-1, URI-FILE-1, URI-CANON-1 |
| `biginteger` | System.Runtime.Numerics | 3 runs, 100 min total (2–3 instances) | 13.0 M | 10.0 k | no new findings (UTF8FMT-1 and BIGINTEGER-EXP-1 again) |
| `asn1` | System.Formats.Asn1 | 2 runs, 90 min total (2 instances) | 49.6 M | 9.1 k | ASN1-GENTIME-1 |
| `metadata` | System.Reflection.Metadata | 2 runs, 80 min total (3 instances) | 50.6 M | 14.3 k | METADATA-1..3 |

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
| [UTF8PARSER-FLOAT-1](#utf8parser-float-1) | `Utf8Parser` (double/float) | Exact ties round up instead of to even when there are zeros after the decimal point | Low–Medium | .NET 8, 9, 10 |
| [UTF8PARSER-DECIMAL-1](#utf8parser-decimal-1) | `Utf8Parser` (decimal) | Excess digits round half away from zero; `decimal.Parse` rounds half to even | Low | .NET 8, 9, 10 |
| [BIGINTEGER-EXP-1](#biginteger-exp-1) | `BigInteger.Parse` | Huge exponents are materialized: an 11-byte input takes a minute and 300 MB | Low–Medium (DoS with untrusted input) | not checked |
| [LINQ-SUM-1](#linq-sum-1) | `Enumerable.Sum` | Overflow detection is per SIMD lane: throws for sums that fit, depending on length and CPU | Low | .NET 8, 9, 10 |
| [RESOURCES-1](#resources-1) | `ResourceReader` | Unchecked header counts (~1 GB allocation from a 206-byte file) and undocumented exceptions on corrupt files | Low | .NET 8, 9, 10 |
| [NUMBER-NEGZERO-1](#number-negzero-1) | `Number.Parsing` | Unsigned `TryParse` accepts `"-0"`/`"-0e5"` but rejects `"-0.0"` | Low | .NET 8, 9, 10 |
| [COMPOSITEFORMAT-2](#compositeformat-2) | `CompositeFormat.Parse` | `"{0:}"` passes `""` where `string.Format` passes `null` | Informational | .NET 8, 9, 10 |
| [METADATA-1](#metadata-13) | `MetadataReader` | `NullReferenceException` from `GetNestedTypes` on malformed metadata | Low–Medium | .NET 8, 9, 10 |
| [METADATA-2](#metadata-13) | `MetadataReader` | `OverflowException` from the constructor (stream headers) | Low–Medium | .NET 8, 9, 10 |
| [METADATA-3](#metadata-13) | `SignatureDecoder`, `CustomAttributeDecoder` | Builders sized by untrusted counts: a 6.6 KB assembly allocates ~2 GB or throws `OutOfMemoryException` | Medium (DoS with untrusted assemblies) | .NET 8, 9, 10 |
| [ASN1-GENTIME-1](#asn1-gentime-1) | `AsnDecoder.ReadGeneralizedTime` | Fractional seconds decoded a tick low (`.043` → `.0429999`), so DER doesn't round-trip | Low–Medium | .NET 8, 9, 10 |
| [URI-HOST-1](#uri-host-1) | `Uri` | Bidi control characters are stripped from the host after validation: `https://‮.com/` has `Host` `".com"` | Low–Medium | .NET 8, 9, 10 |
| [URI-IDN-1](#uri-idn-1) | `Uri.IdnHost` | Throws `UriFormatException` for a host the constructor accepted | Low | .NET 8, 9, 10 |
| [URI-FILE-1](#uri-file-1) | `Uri` (implicit file paths) | U+FFFD and lone surrogates in `"/tmp/…"` paths are turned into literal `%EF%BF%BD` (`LocalPath` changes) | Low | .NET 8, 9, 10 |
| [URI-CANON-1](#uri-canon-1) | `Uri` canonicalization | `AbsoluteUri` doesn't always parse back to the same (or an `Equals`) `Uri` | Low | .NET 8, 9, 10 |

One further finding, in UTF-8 number parsing with custom `NumberFormatInfo` symbols, is not
described here because it may have security impact; it should go through the Microsoft Security
Response Center rather than a public issue. The harness suppresses it as `UTF8CASE-1`.

A second withheld finding, B64URL-AVX2-1 in `Base64Url` UTF-8 decoding, is listed in
[Base64 guard-page campaign](#base64-guard-page-campaign-2026-10-04).
TEXT-24-1 and the wave 2-6 items (18 + 18 + 6, listed by ID with functional descriptions) are in the
[unsafe-code best-practices review](#unsafe-code-best-practices-review-2026-10-04).

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

### UTF8PARSER-FLOAT-1

**`Utf8Parser.TryParse` for `double` and `float` rounds an input that lies exactly halfway between
two values up instead of to even when the text has digits after the decimal point, so the same
number parses differently with and without trailing zeros.**

```csharp
Utf8Parser.TryParse("63732000000000900"u8, out double a, out _);     // 63732000000000896 (to even, like double.Parse)
Utf8Parser.TryParse("63732000000000900.000"u8, out double b, out _); // 63732000000000904
Utf8Parser.TryParse("2001000000.0000000000"u8, out float f, out _);  // 2.0010001E+09; float.Parse: 2.001E+09
```

63732000000000900 is exactly between the doubles …896 and …904, and IEEE round-half-to-even
(what `double.Parse` does) picks …896. `Utf8Parser.Number.cs` copies the digits after the decimal
point, trailing zeros included, into the number buffer, whereas `Number.TryParseNumber` (used by
`double.Parse`) drops trailing zeros. The longer digit string then makes the conversion treat the
tie as being above the midpoint. That's the likely cause, not verified in the conversion code.

### UTF8PARSER-DECIMAL-1

**`Utf8Parser.TryParse` for `decimal` rounds digits beyond decimal's precision half away from zero,
while `decimal.Parse` rounds half to even.**

```csharp
Utf8Parser.TryParse("76228501625444444444444444444.5"u8, out decimal d, out _); // ...445
decimal.Parse("76228501625444444444444444444.5", CultureInfo.InvariantCulture); // ...444
```

Two CoreLib parsers disagree in the last digit for such midpoints. Low severity.

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

### METADATA-1..3

**Malformed assemblies make System.Reflection.Metadata throw exceptions other than
`BadImageFormatException`, or allocate gigabytes.** Each input below is a ~6.6 KB mutation of a
small compiled library. They were reproduced with plain API calls (no harness) on 8.0.31, 9.0.20,
10.0.12 and 11.0 RC1:

| ID | Call | Result |
|---|---|---|
| METADATA-1 | `md.GetTypeDefinition(h).GetNestedTypes()` | `NullReferenceException` in `MetadataReader.InitializeNestedTypesMap` |
| METADATA-2 | `peReader.GetMetadataReader()` | `OverflowException` in `MetadataReader.ReadStreamHeaders` |
| METADATA-3 | `customAttribute.DecodeValue(provider)` | `OutOfMemoryException` in `CustomAttributeDecoder.DecodeArrayArgument` |
| METADATA-3 | `methodDefinition.DecodeSignature(provider, ...)` | allocates 1,984 MB, then `BadImageFormatException` (`SignatureDecoder.DecodeArrayType`) |

The decoders call `ImmutableArray.CreateBuilder<T>(count)` with element counts read from the blob
(up to 2^29) before checking them against the blob's remaining length, which is at most a few
bytes per element. Tools that read untrusted assemblies (analyzers, package scanners,
decompilers, `MetadataLoadContext`) can be made to allocate gigabytes by a tiny file. Bounding the
count by the remaining bytes, and turning the NRE/overflow cases into `BadImageFormatException`,
would fix these. The saved inputs are in `out/metadata/archive/*/*/crashes`, and `./repro.sh
metadata <input>` with `SHARPFUZZ_REPORT_KNOWN_ISSUES=1` shows them.

Also noticed: `AssemblyDefinition.GetAssemblyName()` throws `CultureNotFoundException` under
`InvariantGlobalization` for any assembly with a culture (every satellite assembly), because it
creates a `CultureInfo` for `AssemblyName.CultureName`.

### ASN1-GENTIME-1

**`AsnDecoder.ReadGeneralizedTime` (and `AsnReader`) decode fractional seconds one tick low for
about 6% of millisecond values, so a decoded time written back with `AsnWriter` changes the
DER bytes.**

```csharp
// DER GeneralizedTime "20260927120000.043Z"
AsnDecoder.ReadGeneralizedTime(der, AsnEncodingRules.DER, out _); // 12:00:00.0429999, not .043
// AsnWriter.WriteGeneralizedTime(value) then writes "20260927120000.0429999Z"
```

`AsnDecoder.GeneralizedTime.cs` computes `(long)((double)fraction / fractionScale *
TimeSpan.TicksPerSecond)`; for `.043` the double product is 429999.999… and the cast truncates.
59 of the 999 values `.001`–`.999` are affected on 8.0.31–11.0 RC1. Integer arithmetic
(`fraction * TicksPerSecond / fractionScale`, with the fraction digits capped) would be exact.
Anything that decodes and re-encodes GeneralizedTime with fractions (RFC 3161 `genTime`, CMS
attributes, re-serialized certificates) changes the bytes and breaks signatures over them.

### URI-HOST-1

**`Uri` removes bidi control characters (U+202A–U+202E) from the host after validating it, so
the resulting host can be one `Uri` itself rejects.**

| Input | `Host` | `AbsoluteUri` | Parsing `AbsoluteUri` again |
|---|---|---|---|
| `https://‮.com/` | `".com"` | `https://.com/` | `UriFormatException` |
| `https://‬/?a=b` | `""` | `https:///?a=b` | `UriFormatException` |

`https://.com/` and `https:///` are rejected when written directly. Code that validates a URI by
constructing a `Uri` and then trusts `Host` gets a host that validation would not have allowed.
Low severity on its own; it is listed separately because it concerns the host.

### URI-IDN-1

**`Uri.IdnHost` throws `UriFormatException` for some hosts the constructor accepted**, e.g.
`new Uri("http://xn--bcher-kvaü.example/").IdnHost` ("An invalid Unicode character by IDN
standards was specified in the host"), while `Host` and `DnsSafeHost` work. The exception surfaces
late, e.g. when an HTTP handler resolves the name.

### URI-FILE-1

**Implicit file paths (`new Uri("/tmp/…", UriKind.Absolute)`) turn U+FFFD and lone surrogates into
literal percent sequences:** `new Uri("/tmp/�").LocalPath` is `"/tmp/%EF%BF%BD"` and
`AbsoluteUri` is `file:///tmp/%25EF%25BF%25BD`, while `"/tmp/ü"` round-trips. File names with
U+FFFD exist on Linux (the replacement for undecodable bytes), so such a path points to a different
file after going through `Uri`.

### URI-CANON-1

**`AbsoluteUri` is not always a fixed point of `Uri` parsing.** Minimized by delta debugging:

| Input | `AbsoluteUri` | Parsed again |
|---|---|---|
| `tp:\` (non-special scheme with `\`) | `tp:%5C` | same string, but `Equals` is false |
| `h1:%�x` (stray `%` next to non-ASCII) | `h1:%25%EF%BF%BDx` | same string, `Equals` false |
| `tp:%%2E` | `tp:%25%2E` | `tp:%25.` |
| `/E:` (implicit file path) | `file:///E:` | `UriFormatException` |
| `/.//x` | `file:////x` | `file://x/` |
| `/tmp/a%20b` | `file:///tmp/a%2520b` | same string, `Equals` false |
| `new Uri(new Uri("mailto:0"), "0#[")` | `mailto:0.0.0.0#[` | same string, `Equals` false (direct parsing of the same text is consistent) |

Each is low severity, but together they mean that normalizing a URI by round-tripping it through
`AbsoluteUri` (a common pattern) can change or reject it. 11.0 RC1 also newly accepts
`tp://"@.?` (degenerate host `"."`, `Host` `"%22@."`), which 8–10 reject; hosts other than `.`
parse the same on all versions.

---

## Round 3 (2026-09-28)

Header and stream parsers, System.Data, time zones, `Tensor<T>`, calendars, CBOR, hashing, XML
variants and crypto containers. Round 3 covered areas no other session had fuzzed. Each target ran 30 minutes with three
instances (one with the full ISA, two with AVX-512 / AVX2 disabled; 12 threads for four targets),
after a 45-second shakedown that flushed out harness false positives. Out-of-band packages
(`System.Formats.Cbor`, `System.IO.Hashing`, `System.Security.Cryptography.Pkcs` / `.Cose`) are the
11.0 RC1 NuGet packages, instrumented like `System.Numerics.Tensors` (see `OOB_PACKAGES` in
`setup.sh`).

The last stage looked for memory-safety bugs in code that reads and writes spans through
`Unsafe.ReadUnaligned` / `WriteUnaligned`, pointers and vector loads. With `SHARPFUZZ_GUARD=1` the
harness copies inputs and destinations into buffers that end (or start) right at an inaccessible
page (`Guarded.cs`, mmap + mprotect), so touching one element past a span is a fatal access
violation that AFL records as a crash; results are also compared with the same call over ordinary
arrays. The `unsafetext`, `unsafefmt`, `unsafemem`, `unsafeenc` and `unsaferegex` targets are built
for this, and `tensorprimitives` / `metadata` place their buffers the same way. No out-of-bounds
access (no guard-page fault) was found in the seven 30-minute guarded campaigns; the guarded targets
turned up JSON-COPY-1, B64URL-EXACT-1, UTF8FMT-DT-1, UTF8FMT-NUM-1 and BLOB-DT-1.

### Round 3 campaign statistics

| Target | Assemblies | Wall-clock | Execs | Edges | Result |
|---|---|---|---|---|---|
| `sse` | System.Net.ServerSentEvents | 30 min (3 instances) | 22.2 M | 5.8 k | SSE-TYPE-1/2, MISC-3 |
| `data` | System.Data.Common (expressions, `DbConnectionStringBuilder`) | 30 min (3 instances) | 17.7 M | 19.9 k | DATA-SELECT-1, DATA-OVERFLOW-1, DATA-DOLLAR-1, DATA-ODBC-1, MISC-3 |
| `diag` | System.Diagnostics.DiagnosticSource (propagators, ids) | 30 min (3 instances) | 25.0 M | 6.9 k | DIAG-BAGGAGE-1, DIAG-MISC-1 |
| `mail` | System.Net.Mail (`MailAddress`, `ContentType`, `ContentDisposition`) | 30 min (3 instances) | 33.3 M | 9.6 k | MAIL-CD-1/2, MAIL-ENC-1, MAIL-QUOTE-1, MISC-3 |
| `codepages` | System.Text.Encoding.CodePages | 30 min (3 instances) | 10.9 M | 4.3 k | CP-CONVERT-1 |
| `tensor` | System.Numerics.Tensors (`Tensor<T>`, `TensorSpan<T>`) | 30 min (3 instances) | 19.5 M | 3.8 k | TENSOR-SQUEEZE-1, TENSOR-RESHAPE-1 |
| `sequence` | System.Memory (`SequenceReader`, `ReadOnlySequence`) | 30 min (3 instances) | 13.7 M | 5.4 k | no findings |
| `timezone` | CoreLib `TimeZoneInfo` (TZif, POSIX rules, custom zones) | 30 min (3 instances) | 20.1 M | 8.4 k | TZ-YEAR-1, TZ-RULE-1, TZ-DTO-1, TZ-SER-1 |
| `cookie` | System.Net.Primitives (`CookieContainer`) | 30 min (3 instances) | 12.5 M | 8.5 k | COOKIE-PORT-1 |
| `httputil` | System.Web.HttpUtility | 30 min (3 instances) | 9.3 M | 9.4 k | MISC-3 |
| `calendar` | CoreLib calendars | 30 min (3 instances) | 16.5 M | 4.4 k | CAL-1, MISC-3 |
| `asyncenum` | System.Linq.AsyncEnumerable vs System.Linq | 30 min (3 instances) | 10.4 M | 36.5 k | no findings (harness false positives only) |
| `hashing` | System.IO.Hashing | 30 min (3 instances) | 17.6 M | 2.8 k | HASH-CRC-EVEN-1 |
| `cbor` | System.Formats.Cbor | 30 min (3 instances) | 19.3 M | 7.1 k | CBOR-DUP-1/2, CBOR-DUPW-1, CBOR-SIMPLE-1, CBOR-TRUNC-1, CBOR-FLOAT-1, MISC-3 |
| `binxml` | System.Private.DataContractSerialization (`XmlDictionaryReader` / `Writer`) | 30 min (3 instances) | 21.3 M | 17.5 k | BINXML-DT-1, BINXML-ENC-1, BINXML-ARRAY-1, BINXML-SORT-1, BINXML-LIST-1, BINXML-NUM-1 |
| `xsd` | System.Private.Xml (`XmlSchemaSet`, validating reader, `XmlDocument.Validate`) | 30 min (3 instances) | 19.0 M | 20.1 k | XSD-FACET-1 |
| `pkcs` | System.Security.Cryptography(.Pkcs) (PKCS#12, CMS, RFC 3161, PKCS#8) | 30 min (3 instances) | 52.5 M | 14.7 k | PKCS-DECODE-1 |
| `cose` | System.Security.Cryptography.Cose | 30 min (3 instances) | 52.9 M | 5.8 k | no findings |
| `sortedcoll` | System.Collections (`SortedSet`, `SortedDictionary`, `SortedList`, views) | 30 min (3 instances) | 8.5 M | 5.2 k | no findings |
| `channels` | System.Threading.Channels | 30 min (3 instances) | 29.4 M | 3.7 k | no findings |
| `unsafetext` | CoreLib, System.IO.Hashing (transcoding, hashing, searches, hex, parsers; guarded) | 30 min (2 instances) | 16.1 M | 12.8 k | no findings |
| `unsafefmt` | CoreLib, System.Runtime.Numerics (`TryFormat`, `TryWrite`; guarded) | 30 min (2 instances) | 6.1 M | 10.6 k | UTF8FMT-DT-1, UTF8FMT-NUM-1 |
| `unsafemem` | System.Reflection.Metadata `BlobReader`, `UnmanagedMemoryAccessor` / `Stream`, `SafeBuffer` (guarded) | 30 min (2 instances) | 8.7 M | 4.3 k | BLOB-DT-1 |
| `unsafeenc` | `SearchValues`, `Base64` / `Base64Url`, System.Text.Encodings.Web, System.Text.Json (guarded) | 30 min (2 instances) | 38.7 M | 15.6 k | JSON-COPY-1, B64URL-EXACT-1, MISC-3 (JSON-SURR-1) |
| `unsaferegex` | System.Text.RegularExpressions span APIs (guarded) | 30 min (3 instances) | 7.9 M | 23.0 k | no findings |
| `tensorprimitives` | System.Numerics.Tensors 11.0 RC1 (guarded buffers) | 30 min (2 instances, resuming the earlier corpus) | ~21.7 M | 15.9 k | no new findings |
| `metadata` | System.Reflection.Metadata (`PEReader` / `MetadataReader` over guarded memory) | 30 min (2 instances, resuming the earlier corpus) | ~19.0 M | 14.7 k | no new findings |

`sse`, `data`, `diag` and `mail` ran 13 minutes, then were resumed for 17 more. Crash counts are
AFL's saved crashes, almost all duplicates of the findings above or of harness false positives fixed
during triage; with the final harness every saved crash replays clean (known issues suppressed).

### Round 3 summary

| ID | Component | Kind | Severity (my assessment) | Versions |
|----|-----------|------|--------------------------|----------|
| [TZ-YEAR-1](#tz-year-1) | `TimeZoneInfo` (new transition cache) | Wrong UTC offsets around the new year and in the first year of a zone's POSIX rule; real zones (Sydney, Auckland, Santiago, ...) are off by an hour for hours to months | **High** | **.NET 11 regression** (8, 9, 10 correct) |
| [HASH-CRC-EVEN-1](#hash-crc-even-1) | `Crc64ParameterSet.Create` (new in 11) | Reflected parameter sets with an even polynomial give wrong CRCs for inputs of 16+ bytes (vectorized path), right ones for shorter inputs | Medium | new .NET 11 API |
| [CBOR-DUP-1/2](#cbor-dup-12) | `CborReader` (Strict) | A duplicate map key is not detected when the value before it is an indefinite-length string, or when the two keys encode the same integer differently (`01` / `18 01`) | Medium | Cbor 8.0.0, 9.0.20, 10.0.0, 11.0 RC1 packages |
| [TENSOR-SQUEEZE-1](#tensor-squeeze-1) | `Tensor.Squeeze` | Squeezing a tensor whose lengths are all 1 returns an empty tensor: the element is lost | Medium | Tensors 10.0.12 and 11.0 RC1 packages |
| [DIAG-BAGGAGE-1](#diag-baggage-1) | `W3CPropagator` (the default since .NET 10) | Baggage percent-decoding accepts malformed UTF-8: `%E2%41%41` → U+2041, `%ED%20%80` → lone U+D800 | Low–Medium | .NET 10, 11 |
| [BINXML-DT-1](#binxml-dt-1) | `XmlDictionaryWriter` (binary) | Copying binary XML with `WriteNode` turns UTC / local `DateTime` values into unspecified ones | Low–Medium | .NET 8, 9, 10, 11 |
| [SSE-TYPE-1/2](#sse-type-12) | `SseParser` | `event:` with an empty value gives type `""` instead of `"message"`; an event type followed by a blank line without data leaks into the next event | Low–Medium | .NET 10, 11 |
| [CP-CONVERT-1](#cp-convert-1) | `System.Text.Encoding.CodePages` | `Encoder.Convert` writes one replacement for an unencodable surrogate pair where `GetBytes` writes two (SBCS), or throws `ArgumentException` (DBCS), when the output fills up | Low–Medium | .NET 8, 9, 10, 11 |
| [MAIL-CD-1/2](#mail-cd-12) | `ContentDisposition` | `"attachment; x"` throws `IndexOutOfRangeException`; a date with an offset beyond ±14 h throws `ArgumentOutOfRangeException` when read | Low–Medium | .NET 8, 9, 10, 11 |
| [BINXML-ENC-1](#binxml-enc-1) | `XmlDictionaryReader.CreateTextReader` | An unterminated `encoding='...` in the XML declaration, or a UTF-8 BOM followed by one byte, throws `IndexOutOfRangeException` | Low–Medium | .NET 8, 9, 10, 11 |
| [CBOR-DUPW-1](#cbor-dupw-1) | `CborWriter` (Strict, Canonical) | A duplicate key written after more than ~500 bytes of output throws `ArgumentOutOfRangeException` instead of `InvalidOperationException` and stays written; a caller that catches it and goes on encodes a map with duplicate keys | Low–Medium | Cbor 8.0.0, 9.0.20, 10.0.0, 11.0 RC1 packages |
| [MAIL-ENC-1](#mail-enc-1) | `ContentType`, `ContentDisposition` | A quoted parameter value shaped like an encoded-word with an unknown charset (`"=?x?B?QQ==?="`) parses, then `ToString()` throws `ArgumentException` | Low–Medium | .NET 8, 9, 10, 11 |
| [UTF8FMT-DT-1](#utf8fmt-dt-1) | UTF-8 `TryFormat` of `DateTime`, `DateTimeOffset`, `TimeSpan`, `TimeOnly` | An escaped non-ASCII literal in a custom format (`yyyy\年`) is written as the low byte of the char: wrong text, invalid UTF-8 | Low–Medium | .NET 8, 9, 10, 11 |
| [UTF8FMT-NUM-1](#utf8fmt-num-1) | UTF-8 `TryFormat` of every number type | A custom format with a character outside the BMP (`0😀`) throws `ArgumentOutOfRangeException`; `ToString` works | Low–Medium | .NET 8, 9, 10, 11 |
| [B64URL-EXACT-1](#b64url-exact-1) | `Base64Url` decoding | A final block with partial padding (`GQ=`) decodes into a larger destination, but an exactly sized one gives `InvalidData` (`TryDecodeFrom*` throw `FormatException`) | Low–Medium | .NET 9, 10, 11 |
| [COOKIE-PORT-1](#cookie-port-1) | `CookieContainer` | The `Port` attribute is validated leniently (CR/LF allowed around the numbers) and echoed into the `Cookie` request header | Low | .NET 8, 9, 10, 11 |
| [TZ-RULE-1](#tz-rule-1) | `TimeZoneInfo.FindRuleForYear` | `ArgumentOutOfRangeException` for a rule ending 0001-01-01 under a negative offset | Low | .NET 11 regression |
| [TENSOR-RESHAPE-1](#tensor-reshape-1) | `Tensor.Reshape` | `DivideByZeroException` / `IndexOutOfRangeException` instead of `ArgumentException` | Low | Tensors 10.0.12 and 11.0 RC1 packages |
| [CBOR-SIMPLE-1, CBOR-TRUNC-1](#cbor-simple-1-cbor-trunc-1) | `CborReader` | Reserved simple values: `PeekState` says `SimpleValue`, `ReadSimpleValue` throws `InvalidOperationException`; with multiple root values a trailing tag without content is accepted | Low | 11.0 RC1 package |
| [DATA-SELECT-1](#data-select-1) | `DataTable.Select` | `Select("id > 1", "id, id")` throws `IndexOutOfRangeException` | Low | .NET 8, 9, 10, 11 |
| [DATA-OVERFLOW-1](#data-overflow-1) | `DataTable` expressions | An overflow inside an `AND`/`OR` operand makes `ExprException.Overflow` throw `NullReferenceException` | Low | .NET 8, 9, 10, 11 |
| [DATA-DOLLAR-1](#data-dollar-1) | `DbConnectionStringBuilder` | Regexes end in `$`: keys ending in `\n` pass validation, values ending in `\n` aren't quoted, the newline is lost | Low | .NET 8, 9, 10, 11 |
| [DATA-ODBC-1](#data-odbc-1) | `DbConnectionStringBuilder` (ODBC rules) | Keys with `=` / `;` aren't escaped; values with control characters are written unquoted and don't parse | Low | .NET 8, 9, 10, 11 |
| [MAIL-QUOTE-1](#mail-quote-1) | `MailAddress` | Display names with `\` or `"` don't round-trip through `ToString()` | Low | .NET 8–11 |
| [TZ-DTO-1, TZ-SER-1](#tz-dto-1-tz-ser-1) | `TimeZoneInfo` | Custom zones with offsets past ±14 h are accepted, then `ConvertTime(DateTimeOffset)` throws; a truncated serialized rule throws `IndexOutOfRangeException` | Low | .NET 8, 9, 10, 11 |
| [CAL-1](#cal-1) | `System.Globalization` calendars | `JulianCalendar.AddMonths` clamps to Feb 28 in Julian leap century years; `KoreanLunisolarCalendar` puts 952-12-25 in month 13 of a 12-month year; `HijriCalendar.GetYear` and `Calendar.GetWeekOfYear` throw for supported dates near the range ends | Low | .NET 8, 9, 10, 11 |
| [DIAG-MISC-1](#diag-misc-1) | `ActivityTraceId`, `ActivityContext`, `Activity` | `CreateFromUtf8String` accepts invalid ids; `ActivityContext.TryParse` doesn't check the `-` separators; `SetParentId` accepts CR/LF, which the legacy propagator writes into `Request-Id` | Low | .NET 8, 9, 10, 11 |
| [XSD-FACET-1](#xsd-facet-1) | `XmlSchemaSet.Compile` | A `length` / `minLength` / `maxLength` / `totalDigits` / `fractionDigits` value above `int.MaxValue` throws `OverflowException` instead of `XmlSchemaException` | Low | .NET 8, 9, 10, 11 |
| [BINXML-ARRAY-1](#binxml-array-1) | `XmlDictionaryWriter.WriteNode` | Copying binary XML drops the comments that follow an array record | Low | .NET 8, 9, 10, 11 |
| [BINXML-SORT-1, BINXML-LIST-1](#binxml-sort-1-binxml-list-1) | `XmlDictionaryReader.CreateBinaryReader` | An attribute name that isn't valid UTF-8 makes the duplicate-attribute check throw `InvalidOperationException` ("Failed to compare two elements"); `Value` of a list record with an item it can't convert throws `InvalidOperationException` | Low | .NET 8, 9, 10, 11 |
| [PKCS-DECODE-1](#pkcs-decode-1) | `Pkcs12Info.Decode` | `30 80` (indefinite length, no content) throws `AsnContentException` instead of `CryptographicException` | Low | Pkcs 8.0.1, 9.0.20, 10.0.12, 11.0 RC1 packages |
| [JSON-COPY-1](#json-copy-1) | `Utf8JsonReader.CopyString(Span<byte>)` | Throws "destination is too short" for an exactly sized destination when unescaped text follows the last escape (`"\u0041b"` into 2 bytes) | Low | .NET 8, 9, 10, 11 |
| [BLOB-DT-1](#blob-dt-1) | `BlobReader.ReadDateTime` | Ticks outside `DateTime`'s range throw `ArgumentOutOfRangeException` instead of `BadImageFormatException` | Low | .NET 8, 9, 10, 11 |
| [MISC-3](#misc-3) | various | See the list at the end of this section | Informational | |

### TZ-YEAR-1

**.NET 11 computes wrong UTC offsets around the new year for zones whose daylight time spans it,
and in the first calendar year governed by a zone's POSIX TZ rule.** 8.0.31, 9.0.20 and 10.0.12
are correct in every case below; 11.0 RC1 is not. The fuzzer found it on custom zones (the local
time of an instant on Dec 31 converted back to a different instant); a scan of all 419 system
zones confirmed it on real data.

Offset changes of `TimeZoneInfo.FindSystemTimeZoneById(id).GetUtcOffset(utc)` scanned 1970–2045,
.NET 11 vs .NET 10, with the stock Ubuntu 22.04 tzdata ("fat" TZif, explicit transitions until 2037):

| Zone | .NET 10 | .NET 11 RC1 |
|---|---|---|
| Pacific/Auckland (also Antarctica/McMurdo) | +13 through 2037-12-31 / 2038-01-01 | +12 from 2037-12-31 11:00Z to 2038-01-01 00:00Z |
| Australia/Sydney (also Melbourne, Hobart, Adelaide, Broken_Hill, Antarctica/Macquarie) | daylight time | standard time for the 10–13 hours before 2038-01-01 00:00Z |
| America/Santiago, Pacific/Easter | transitions 2038-04-03 and 2038-09-04 | no 2038 transitions: wrong from April to September 2038 |
| Australia/Lord_Howe, Pacific/Chatham, Pacific/Norfolk | 2038 transitions in April / October | moved to 2038-12-31 / 2039-01-01 |
| Africa/Cairo | DST ends 2037-10-29 21:00Z (last Thursday 24:00) | a day early |

The same zones compiled as "slim" TZif (`zic -b slim`, the zic default since 2020b), where the
explicit transitions stop as soon as the POSIX rule describes the zone:

| Zone | .NET 11 RC1 error |
|---|---|
| Australia/Sydney, Melbourne, Adelaide, Broken_Hill, Lord_Howe | 2008 transitions (Apr 5, Oct 4) missing: daylight time from April to October 2008 |
| America/Santiago, Pacific/Easter | 2023 transitions (Apr 2, Sep 2) missing: five months wrong |
| Pacific/Norfolk | DST starts 2020-01-01 instead of 2019-10-05 |
| Pacific/Auckland, Chatham, Antarctica/McMurdo, Australia/Hobart, Antarctica/Macquarie | standard time for New Year's Eve 2007 (2011 for Macquarie) |

So with slim TZif data, the first POSIX-rule year of a zone whose daylight time spans the new year
is converted wrongly, and that year moves forward whenever the zone's rules change (as Chile's did
in 2022/2023). Custom zones show the mechanism directly:

- for an instant on Dec 31 whose local time is in the next year, the wrong year's rule is used:
  a zone with base offset +13:11 and a 2001–2012 rule with `BaseUtcOffsetDelta` −1:30 gives
  `GetUtcOffset(2001-12-31T20:52Z)` = 13:11 (8–10: 11:41);
- a zone whose daylight time runs from April to the first Monday of January reports standard time
  on `2045-12-31T20:36Z` (8–10: daylight time);
- for a local time in a rule's first year but before its `DateStart`, the rule is applied anyway
  (`GetUtcOffset(2021-01-01T10:03)` is 12:41 instead of 13:11 for a rule starting 2021-02-01).

The per-year transition cache in `TimeZoneInfo.Cache.cs` came with dotnet/runtime#119662 ("TimeZones
improvement", merged 2025-10-05, after .NET 10 branched), which replaced the adjustment-rule lookup
in `TimeZoneInfo.cs`; TZ-RULE-1 is in the same file.

```csharp
var tz = TimeZoneInfo.FindSystemTimeZoneById("Pacific/Auckland");
tz.GetUtcOffset(new DateTime(2037, 12, 31, 12, 0, 0, DateTimeKind.Utc)); // .NET 10: 13:00, .NET 11 RC1: 12:00
```

### HASH-CRC-EVEN-1

**`Crc64ParameterSet.Create` (new in .NET 11) with `reflectValues: true` and an even polynomial
computes wrong CRCs for inputs of 16 bytes or more.** Against a bit-at-a-time Rocksoft-model CRC, 50
random even polynomials: 0/50 differ for 5-byte inputs, 50/50 for 16, 64 and 300 bytes; odd
polynomials, non-reflected parameter sets and every `Crc32ParameterSet` are always right. So the
same parameter set gives results that depend on the input length (and on how it is split across
`Append` calls). Real CRC polynomials have the x⁰ term, so either `Create` should reject even
polynomials or the vectorized (carry-less multiply) path needs to handle them like the table path.
Related (HASH-CRC-INIT-1, documentation): for reflected parameter sets the initial value is loaded
into the reflected register as is, where the Rocksoft model and the CRC catalogue reflect it; the
two agree only for bit-palindromic values (all catalogue CRC-32/64 entries use 0 or all ones).

### CBOR-DUP-1/2

**`CborReader` in `Strict` mode misses duplicate map keys** in two cases (8.0.0, 9.0.20, 10.0.0
and 11.0 RC1 packages):

- CBOR-DUP-1: the value before the duplicate is an indefinite-length string.
  `A2 03 7F FF 03 61 6E` (`{3: "" (indefinite), 3: "n"}`) and `A2 03 5F FF 03 60` are accepted;
  `A2 03 60 03 61 6E` is rejected as expected.
- CBOR-DUP-2: the keys are equal but encoded differently, which Strict (unlike the canonical
  modes) allows: `A2 01 00 18 01 00` (`{1: 0, 1: 0}` with the second `1` as `18 01`) and
  `A2 20 00 38 00 00` (`-1` twice) are accepted. The check compares key encodings byte by byte,
  but RFC 8949 §5.6 defines duplicates on the decoded values.

Duplicate-key rejection is what Strict mode is for, and a reader that lets one through can be made
to disagree with other parsers about a map's contents. Canonical modes reject indefinite-length
items and non-shortest integers, so they aren't affected. (CborWriter in Strict mode then refuses to
write the map back, see also [CBOR-DUPW-1](#cbor-dupw-1).)

### CBOR-DUPW-1

**`CborWriter`'s rollback after a duplicate key uses an end offset as a length.** In
`HandleMapKeyWritten` (`CborWriter.Map.cs`), a key that repeats one already in the map (Strict,
Canonical and Ctap2Canonical) should clear the key's bytes, rewind `_offset` to before the key and
throw `InvalidOperationException`. It clears `_buffer.AsSpan(currentKey.Offset, _offset)`, passing
the end offset `_offset` where the length `_offset - currentKey.Offset` belongs. Once
`currentKey.Offset + _offset` is past the buffer's size, which happens after about 500 bytes of
output, `AsSpan` throws `ArgumentOutOfRangeException` before the rewind. The duplicate key then stays
in the buffer: a caller that catches the exception and goes on (as it can after the documented
`InvalidOperationException`) gets output that the Strict reader rejects.

```csharp
var w = new CborWriter(CborConformanceMode.Strict);
w.WriteStartMap(2);
w.WriteInt32(0);
w.WriteByteString(new byte[600]);
try { w.WriteInt32(0); } catch (Exception e) { Console.WriteLine(e.GetType()); } // ArgumentOutOfRangeException (200 bytes: InvalidOperationException)
w.WriteInt32(1); w.WriteInt32(2); w.WriteEndMap();
new CborReader(w.Encode(), CborConformanceMode.Strict).SkipValue(); // CborContentException: duplicate keys
```

Same in the 8.0.0, 9.0.20, 10.0.0 and 11.0 RC1 packages. The fuzzer reached it by replaying
CBOR-DUP-1 maps into a writer after a long run of root values.

### TENSOR-SQUEEZE-1

**`Tensor.Squeeze` of a tensor whose lengths are all 1 loses the element.**
`Tensor.Squeeze(Tensor.Create(new[] { 7 }, [1]))` returns a rank-1 tensor with `FlattenedLength`
0 (enumerating it yields nothing), and so does `Squeeze` of a `[1, 1]` `TensorSpan`. Removing every
dimension should leave a single element (NumPy returns a 0-d array with the value), or keep one
dimension of length 1; returning an empty tensor silently drops data.

### TENSOR-RESHAPE-1

**`Tensor.Reshape` throws `DivideByZeroException` or `IndexOutOfRangeException`** instead of
`ArgumentException`: `Reshape(new TensorSpan<int>(a, [4]), [-1, 0])` divides the element count by
the product of the other lengths (0) to infer the `-1`; `Reshape` of an empty `[0, 0, 7]` span to
`[0, 1, 0, 1]` indexes out of range.

### DIAG-BAGGAGE-1

**The W3C propagator (the default `DistributedContextPropagator` since .NET 10) decodes malformed
UTF-8 in baggage values into other characters.** `TryDecodeBaggageValue` (`W3CPropagator.cs`)
checks continuation bytes for 2- and 4-byte sequences but not for 3-byte ones, so
`baggage: k=%E2%41%41` is extracted as `k` = `"⁁"` (U+2041) instead of U+FFFD + `"AA"`, and
`%ED%20%80` becomes a lone surrogate U+D800 (the check that rejects encoded surrogates only looks at
the second byte's range). Baggage comes from incoming request headers, so any server that
propagates context gets code points that aren't in the header. 8/9's legacy propagator decodes these
to U+FFFD.

### BINXML-DT-1

**Copying binary XML through `XmlDictionaryWriter.CreateBinaryWriter(...).WriteNode(reader, ...)`
drops the `Kind` of typed `DateTime` values.** A `DateTime` record written from
`new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc)` reads back as `...Z` (Utc) from the original
but as unspecified after a binary-to-binary copy (a copy to text keeps the `Z`). Local times lose
their offset the same way. Copying messages this way is what WCF-style message buffering does.

### SSE-TYPE-1/2

**`SseParser` deviates from the WHATWG event stream algorithm in two ways.** An `event:` line with
an empty value sets the type to `""`; the spec only changes the type when the buffer is non-empty,
so the event is a `"message"`. And the event type buffer is only reset when an event is
dispatched: `event: ping\n\n` (no data, so nothing is dispatched) followed by `data: x\n\n` gives
an item of type `"ping"`, where browsers deliver a `"message"`. A stream that sends typed
keep-alives without data reroutes the next event.

### CP-CONVERT-1

**The code page encoders' `Encoder.Convert` loses or rejects the fallback for a surrogate pair
when the output buffer fills up.** For `"abcdefg😀"` and code page 37, 437 or 1252, `GetBytes`
writes nine bytes (two `?` for the pair) but `Convert` into an 8-byte buffer (looping until
`completed`) writes eight; code page 932 throws `ArgumentException` with a 1- or 2-byte buffer.
CoreLib's own ASCII and Latin-1 encoders are consistent, so this is in
`System.Text.Encoding.CodePages`' encoder / fallback-buffer handling.

### MAIL-CD-1/2

`new ContentDisposition("attachment; x")` (a trailing parameter without `=value`) throws
`IndexOutOfRangeException` from `ContentDisposition.ParseValue`. A date parameter with an
out-of-range zone offset (`creation-date="Tue, 15 Nov 1994 08:12:31 +9900"`) parses, but reading
`CreationDate` / `ModificationDate` / `ReadDate` throws `ArgumentOutOfRangeException` from
`SmtpDateTime.Date`; so does a valid offset that moves the UTC time out of range
(`"Fri, 31 Dec 9999 20:00:00 -0800"`). Code that parses `Content-Disposition` headers of uploads with
this class and catches `FormatException` fails on both.

### MAIL-ENC-1

**`ContentType` / `ContentDisposition` accept a parameter value that looks like an RFC 2047
encoded-word with an unknown charset, then `ToString()` throws.**
`new ContentType("text/plain; x=\"=?x?B?QQ==?=\"")` (or `"=??B?QQ==?="`, or
`"=?bogus-charset?Q?a?="`) parses and keeps the value as is, but `ToString()` passes the value to
`MimeBasePart.DecodeEncoding`, whose `Encoding.GetEncoding("x")` throws `ArgumentException`
("'x' is not a supported encoding name"). A known charset (`=?utf-8?B?QQ==?=`, even with an invalid
encoding letter) is written back unchanged. Any code that parses a received header and serializes it
again (forwarding, `Attachment.ContentType`, logging) throws on attacker-chosen input. Same on 8.0.31,
9.0.20, 10.0.12 and 11.0 RC1.

### BINXML-ENC-1

`XmlDictionaryReader.CreateTextReader` (the DataContract / WCF text reader) throws
`IndexOutOfRangeException` from `EncodingStreamWrapper.CheckUTF8DeclarationEncoding` when the XML
declaration's encoding value is unterminated: `<?xml version='1.0' encoding='utf-8` (a truncated
message) or `<?xml version="1.0" encoding="x`, and when the input is a UTF-8 BOM followed by a
single byte (`EF BB BF 71`). `XmlException` is the documented failure.

### COOKIE-PORT-1

`CookieContainer.SetCookies` accepts an RFC 2965 `Port` attribute with whitespace (including CR and
LF) around the port numbers, `Port="8\r,443"`, and `GetCookieHeader` echoes it verbatim as
`$Port="8\r,443"`, so the `Cookie` header it produces contains a line break. `HttpClient` rejects
such a header value when sending, but code that builds requests by hand gets a split header.
(The container also stores cookies whose names contain control characters or spaces, and values
with unbalanced quotes.)

### TZ-RULE-1

**`GetUtcOffset` / `ConvertTimeFromUtc` throw `ArgumentOutOfRangeException` for a zone with a rule
ending on 0001-01-01 and a negative offset** (.NET 11 regression). `FindRuleForYear`
(`TimeZoneInfo.Cache.cs`) evaluates `previousRule.DateEnd + (baseUtcOffset + BaseUtcOffsetDelta +
DaylightDelta)`, which underflows `DateTime`. Real TZif data starts its first rule at 0001-01-01 but
ends it on 0001-12-31, so this needs a custom or deserialized zone:
`TimeZoneInfo.FromSerializedString("Z1;-360;Z1;Z1;Z1D;[01:01:0001;01:01:0001;60;[0;00:00:00;1;1;0;];[0;00:30:00;1;5;3;];][05:01:0001;08:23:0007;0;[0;12:30:00;9;3;2;];[0;00:30:00;1;5;3;];];")`
then `ConvertTimeFromUtc(new DateTime(6, 10, 30, 17, 0, 0, DateTimeKind.Utc), zone)`. 8–10 return
`0006-10-30T11:00`.

### CBOR-SIMPLE-1, CBOR-TRUNC-1

- For `FE` (major type 7 with the reserved additional information 28–30) `PeekState()` returns
  `SimpleValue`, and `ReadSimpleValue()` / `SkipValue()` then throw `InvalidOperationException`
  rather than `CborContentException`, in every conformance mode. Code that dispatches on
  `PeekState` and catches `CborContentException` fails on it.
- With `allowMultipleRootLevelValues: true`, `01 C7` (a root value, then a tag with no data item
  after it) reads as `UnsignedInteger`, `Tag`, then `Finished`: the truncated input is accepted.
  A single `C7` correctly throws `CborContentException` after `ReadTag`.

### DATA-SELECT-1

`DataTable.Select(filter, sort)` throws `IndexOutOfRangeException` from `Select.CreateIndex` when
the sort names a column twice and the filter is not empty: `table.Select("id > 1", "id, id")`.
Without a filter it works.

### DATA-OVERFLOW-1

`BinaryNode.EvalBinaryOp` evaluates the operands of `AND` / `OR` inside the `try` that turns an
`OverflowException` into `ExprException.Overflow(DataStorage.GetTypeStorage(resultType))`; when the
overflow comes from an operand, `resultType` is still `Empty`, `GetTypeStorage` returns null and
`Overflow` throws `NullReferenceException`: `table.Select("(SUBSTRING(s, 9999999999, 2) = 'a') AND true")`.

### DATA-DOLLAR-1

`DbConnectionOptions`' key validation (`^(?![;\s])[^\p{Cc}]+(?<!\s)$`) and value quoting
(`^[^"'=;\s\p{Cc}]*$`) regexes end in `$`, which also matches before a final `\n`. So
`builder["k\n"] = "v"` is accepted, and `builder["k"] = "v\n"` is written unquoted as `k=v\n`;
parsing the connection string back gives `k` = `"v"` in both cases. `\z` would fix both.

### DATA-ODBC-1

With `useOdbcRules: true`, keys are written without escaping: `builder["a=b"] = "c"` gives `a=b=c`,
which parses as `a` = `b=c`, and a key containing `;` splits into two entries. Values with control
characters are written without braces and the ODBC parser then rejects the whole string
(`b=x\u0007`), and so are values where whitespace precedes a `{` (`builder["d"] = " {o"` gives
`d= {o`, which the parser reads as an unterminated braced value); both `ConnectionString` and
`AppendKeyValuePair` do this.

### MAIL-QUOTE-1

`MailAddress.ToString()` quotes the display name and, in 11 RC1, escapes `\` and `"` in it; the
parser keeps quoted-pairs escaped. `new MailAddress("u@h.com", "a\"b\\c")` → `"a\"b\\c" <u@h.com>`
→ reparsed display name `a\"b\\c` → next round trip `a\\\"b\\\\c`. On 8–10 the second parse throws
`FormatException` instead.

### TZ-DTO-1, TZ-SER-1

- `CreateCustomTimeZone` validates the base offset and each rule's daylight delta against ±14 h but
  not base + `BaseUtcOffsetDelta`: base −13:30 with a rule delta of −1:00 is accepted, `GetUtcOffset`
  returns −14:30, `ConvertTimeFromUtc` works, and `ConvertTime(DateTimeOffset, zone)` throws
  `ArgumentOutOfRangeException`.
- `TimeZoneInfo.FromSerializedString("X;-480;X;X;X;[01:01:0001;12:31:2006;60;[0;02:00:00;4;1;0;];[0;02:00:00;10;5;0;];00;")`
  throws `IndexOutOfRangeException` from `StringSerializer.GetNextAdjustmentRuleValue` (without the
  trailing `00;` it gives the documented `SerializationException`).

### CAL-1

- `JulianCalendar.AddMonths` clamps the day with the wrong leap rule in century years:
  `AddMonths(1399-08-31 (Julian), 6)` gives Feb 28, 1400, although `GetDaysInMonth(1400, 2)` is 29 in
  the Julian calendar (also 700, 9100).
- `KoreanLunisolarCalendar` returns year 952, month 13 for 952-12-25 … (Gregorian), while
  `GetMonthsInYear(952)` is 12 and `GetLeapMonth(952)` is 0 (`GetMonthsInYear(953)` is 13): the
  table data for that year is inconsistent.
- `HijriCalendar` with a non-zero `HijriAdjustment` misreports dates near the ends of its range:
  with `HijriAdjustment = -2`, `GetYear(MinSupportedDateTime)` is 0 (not a valid Hijri year), and
  `GetYear` throws `ArgumentOutOfRangeException` for other supported dates there. `Calendar.GetWeekOfYear` throws for
  supported dates near `MinSupportedDateTime` / `DateTime.MinValue` of several calendars (it looks at
  days before them).

### DIAG-MISC-1

- `ActivityTraceId.CreateFromUtf8String` / `ActivitySpanId.CreateFromUtf8String` parse each 16-hex
  half with `Utf8Parser.TryParse(..., 'x')` and ignore how many bytes it consumed, so
  `"00-0af7651916cd43dd8448eb211c803"` becomes `00000000000000003dd8448eb211c803`; upper case and
  all-zero ids are accepted too. `CreateFromString` rejects all of these.
- `ActivityContext.TryParse` accepts a traceparent whose separators aren't `-`
  (`00x0af7…319cxb7ad…3331x01`); the W3C propagator rejects it.
- `Activity.SetParentId` accepts any string as a hierarchical id, including CR/LF, and the legacy
  propagator writes the resulting `Activity.Id` into `Request-Id` unchanged.

### XSD-FACET-1

**`XmlSchemaSet.Compile` throws `OverflowException` for integer facets above `int.MaxValue`.**
`FacetsChecker.FacetsCompiler` parses `length`, `minLength`, `maxLength`, `totalDigits` and
`fractionDigits` as `xs:nonNegativeInteger` (unbounded; values past `decimal` are rejected with
`XmlSchemaException`), then converts them with `XmlBaseConverter.DecimalToInt32`, which throws
`OverflowException` for `2147483648` up to about 7.9e28. `<xs:maxLength value='2147483648'/>` is a
valid facet (it could be clamped to `int.MaxValue`) or at least a schema error; instead the
exception escapes `Compile` and inline-schema validation. Same on 8.0.31, 9.0.20, 10.0.12 and
11.0 RC1.

### BINXML-ARRAY-1

**`XmlDictionaryWriter.WriteNode` drops comments that directly follow a binary array record.** A
document written with `WriteArray(null, "arr", null, new[] { 1, 2 }, 0, 2)` followed by
`WriteComment("c1")`, `WriteComment("c2")` and an element reads back as
`<r><arr>1</arr><arr>2</arr><!--c1--><!--c2--><m></m></r>`; copying it with
`WriteNode(XmlDictionaryReader.CreateBinaryReader(...), true)` into a binary or a text writer gives
`<r><arr>1</arr><arr>2</arr><m></m></r>`. Text or elements in the same place are copied. The array
fast path apparently moves the reader past the following comments. Same on 8.0.31, 9.0.20, 10.0.12
and 11.0 RC1.

### BINXML-SORT-1, BINXML-LIST-1

`XmlDictionaryReader.CreateBinaryReader` throws `InvalidOperationException` where malformed input
should give `XmlException` (8.0.31, 9.0.20, 10.0.12 and 11.0 RC1):

- BINXML-SORT-1: when an element has enough attributes that `CheckAttributes` looks for duplicates by
  sorting them (`XmlBaseReader.AttributeSorter` via `Array.Sort`), a prefix or name that isn't valid
  UTF-8 throws `XmlException` inside the comparer, and `Array.Sort` wraps it in
  `InvalidOperationException` ("Failed to compare two elements in the array"). This was the most
  common crash in the binary XML campaign.
- BINXML-LIST-1: `Value` of a list-valued text record whose items `ValueHandle.ToObject` can't
  convert throws a bare `InvalidOperationException`.

### PKCS-DECODE-1

`Pkcs12Info.Decode(new byte[] { 0x30, 0x80 }, ...)` throws `System.Formats.Asn1.AsnContentException`
from `PkcsHelpers.FirstBerValueLength` (an indefinite length with no content), where every other
truncated or malformed input (`30`, `30 81`, `30 84 FF FF FF FF`) throws the documented
`CryptographicException`. Same in the 8.0.1 (8.0.10), 9.0.20, 10.0.12 and 11.0 RC1 packages.

### UTF8FMT-DT-1

**UTF-8 formatting of dates and times writes an escaped non-ASCII literal as one byte.** In a custom
format, `\x` makes `x` a literal. `ToString` / UTF-16 `TryFormat` copy it; the UTF-8 path
(`IUtf8SpanFormattable.TryFormat`) writes `(byte)x`:

```csharp
var dt = new DateTime(2020, 1, 2);
dt.ToString("yyyy\\年");                                   // "2020年"
dt.TryFormat(utf8, out int n, "yyyy\\年", null);           // 32 30 32 30 74 ("2020t": 0x74 is the low byte of U+5E74)
dt.TryFormat(utf8, out n, "\\é", null);                    // E9: not UTF-8 at all
dt.TryFormat(utf8, out n, "\\😀", null);                   // ArgumentOutOfRangeException
```

The same happens for `DateTimeOffset`, `TimeSpan` and `TimeOnly`, on 8.0.31, 9.0.20,
10.0.12 and 11.0 RC1. Quoted literals (`'年'`), unescaped literals (`yyyy年MM月dd日`) and culture
data (month names) come out right, so only the backslash escape is affected. The output is silently
wrong, and can be invalid UTF-8 that a later reader rejects or replaces.

### UTF8FMT-NUM-1

**UTF-8 number formatting throws for custom formats containing a surrogate pair.**
`Number.AppendUnknownChar` (UTF-8 instantiation) converts each literal char with `new Rune(char)`,
which throws for either half of a surrogate pair. `1.5.ToString("0😀")` is `"2😀"`, but
`1.5.TryFormat(utf8, out _, "0😀", null)` throws `ArgumentOutOfRangeException` (parameter `ch`), for
`int`, `double`, `decimal`, `Half` and the other number types, quoted (`'😀'`) or not. BMP literals
(`0é`) work. Same on 8.0.31, 9.0.20, 10.0.12 and 11.0 RC1.

### B64URL-EXACT-1

**`Base64Url` rejects partially padded input when the destination is exactly the decoded size.**
`Base64Url` accepts a final block with no, partial or full padding (`GQ`, `GQ=`, `GQ==`, also `%`).
Decoding `GQ=` (or `SGVsbA=`) into a destination with room to spare returns `Done` (1 or 4 bytes),
but into a destination of exactly 1 (or 4) bytes it returns `InvalidData` after 0 (or 3) bytes, and
`TryDecodeFromUtf8` / `TryDecodeFromChars` throw `FormatException` for input they accept otherwise.
`GQ` and `GQ==` decode fine at the exact size. Same on 9.0.20, 10.0.12 and 11.0 RC1 (8.0 has no
`Base64Url`). Found by the guard-page `unsafeenc` target, which decodes into exactly sized buffers.

### JSON-COPY-1

**`Utf8JsonReader.CopyString(Span<byte>)` rejects a destination that is exactly the size of the
unescaped value** when the value contains an escape followed by unescaped text: `"\u0041b"` (`Ab`,
2 bytes), `"a\\b"` (`a\b`, 3 bytes), `"x\ny\nz"` (5 bytes) and `"a\/b"` throw
`ArgumentException` ("Destination is too short") with a 2-, 3- or 5-byte destination and succeed with
one byte more. Values that end in an escape (`"x\ny\n"`, `"\"quoted\""`) are copied fine, and so
is every value by the `Span<char>` overload. Single- and multi-segment readers behave the same, on
8.0.31, 9.0.20, 10.0.12 and 11.0 RC1. In `JsonReaderHelper.TryUnescape`, the check before copying
the unescaped run after an escape is `(uint)(written + nextUnescapedSegmentLength) >= (uint)destination.Length`;
it should be `>` (a following escape is already caught by the loop's `written == destination.Length`
check). Code that sizes the
buffer from `ValueSpan.Length`, as the docs suggest, always has a spare byte, so this bites callers
that size it exactly (for example from a known field length). The guard-page `unsafeenc` target
found it on its first seed; no memory is touched out of bounds.

### BLOB-DT-1

`BlobReader.ReadDateTime()` passes the 64-bit value to the `DateTime(long)` constructor unchecked,
so ticks outside `DateTime`'s range (`long.MaxValue`, `-1`) throw `ArgumentOutOfRangeException`.
Metadata readers otherwise report malformed data with `BadImageFormatException`. Found by the
guard-page `unsafemem` target; 8.0.31 to 11.0 RC1.

### MISC-3

- `SseParser` parses `retry` with `long.TryParse`, which ignores trailing U+0000: `retry: 5\0` sets
  5 ms although the field isn't all digits. `SseItem.EventId` rejects line breaks but accepts
  U+0000; `SseFormatter` writes it and the parser then ignores the whole `id` field.
- `ContentType.ToString()` writes parameter values with non-ASCII or control characters as RFC 2047
  encoded-words that `new ContentType(...)` doesn't decode.
- `HttpUtility.ParseQueryString("=x&y").ToString()` is `"x&y"`: the empty name loses its `=`.
  `HttpUtility.UrlPathEncode` leaves DEL (U+007F) unencoded while encoding the other control
  characters (`UrlPathEncodeImpl` uses the range `0x21..0x7F`).
- `DataTable` expressions: `SUBSTRING(s, 0, 2)` throws `ArgumentOutOfRangeException` and
  `SUBSTRING(s, '.', 2)` `InvalidCastException` instead of `EvaluateException`; some malformed
  `Convert(x, 'type')` names throw `FileLoadException`.
- `CborWriter` writes every NaN as the canonical `F9 7E00`, dropping sign and payload, in all
  conformance modes.
- CBOR-FLOAT-1: the Canonical and Ctap2Canonical readers accept floats that have a shorter exact
  encoding (`FA 7F800000` for +Infinity, `FB 3FF0000000000000` for 1.0), while `CborWriter` in
  those modes always writes the shortest (`F9 7C00`), so such input doesn't round-trip and a
  shortened map key can change the canonical key order. RFC 7049's canonical rules leave float width
  open, so this is informational.
- BINXML-NUM-1: copying binary XML through `XmlDictionaryWriter.CreateBinaryWriter` (`WriteNode`)
  turns a `-0` numeric record into `0`, and decimals with an out-of-range scale are formatted
  differently.
- JSON-SURR-1: `JsonDocument.Parse` accepts a string with an escaped lone surrogate (`["\ud83d"]`),
  and `GetRawText()` returns it, but `JsonDocument.WriteTo` / `JsonElement.WriteTo` throw
  `InvalidOperationException` ("incomplete UTF-16"), like `GetString()`, so a parsed document can't
  always be written back (8.0 to 11.0).
- In invariant globalization mode `new JapaneseCalendar()`, `new KoreanCalendar()` and
  `new TaiwanCalendar()` throw `TypeInitializationException` (they look up `ja-JP` / `ko-KR` /
  `zh-TW`), while the lunisolar and Thai calendars work.

## Round 4 (2026-09-28 evening): more code built on Unsafe / pointers

Areas with `Unsafe` / pointer / native-interop code that earlier rounds didn't reach, fuzzed with
guard-page buffers (`SHARPFUZZ_GUARD=1`) against differential and round-trip checks, 30 minutes per
area on at most 12 threads: the new span compression encoders, System.Net parsers, the vector APIs'
software fallbacks, JSON (serializer, nodes, multi-segment and async readers), interop marshalling,
text I/O, archives, the managed WebSocket, PEM / ASN.1 / X.509 parsing, metadata writing, HTTP
headers, the DataContract JSON stack and pipelines. Several targets also compare reading the same
bytes whole and in small pieces, which is how SR-BOM-1 and DCJSON-ENC-1 turned up. As in round 3, no
guard-page fault (out-of-bounds read or write) occurred; every saved crash replays clean against the
final harness with the known issues below suppressed.

### Round 4 campaign statistics

| Target | Assemblies | Wall-clock | Execs | Edges | Result |
|---|---|---|---|---|---|
| `unsafecomp` | System.IO.Compression (`DeflateEncoder` / `ZLibEncoder` / `GZipEncoder` and decoders, new in 11), System.IO.Compression.Brotli; guarded | 30 min (3 instances) | 8.5 M | 2.7 k | COMP-EXACT-1, COMP-EMPTY-1 |
| `unsafenet` | `IPAddress`, `IPNetwork`, `IPEndPoint`, `PhysicalAddress`, span `Uri.TryEscapeDataString` / `TryUnescapeDataString`; guarded | 30 min (3 instances) | 26.3 M | 5.1 k | no findings |
| `vectorops` | `Vector128` / `256` / `512`, `Vector<T>` against a scalar model, all element types, three ISA levels; guarded loads / stores | 30 min (3 instances) | 49.1 M | 2.3 k | no findings |
| `unsafejson` | `JsonSerializer`, `JsonNode` over guarded memory, exactly sized `IBufferWriter` | 30 min (3 instances) | 20.0 M | 20.0 k | JSON-DEEPEQ-1, ROUND4-MISC |
| `unsafemarshal` | `Marshal.PtrToStructure` / `StructureToPtr`, `PtrToString*`, string marshallers; guarded native memory | 30 min (3 instances) | 30.6 M | 7.5 k | MARSHAL-TSTR-1 |
| `textio` | `StreamReader`, `BinaryReader`, `StringBuilder` with chunked streams | 30 min (3 instances) | 39.8 M | 5.4 k | SR-BOM-1, BR-CHARS-1, ROUND4-MISC |
| `archive` | `ZipArchive` (sync and async), `TarReader` (sync and async) | 30 min (3 instances) | 41.8 M | 7.9 k | ZIP-ENC-1 |
| `arrays` | `BitArray`, `Array.Copy` widening, `Buffer.BlockCopy`, range operations, `BitOperations` (sentinels) | 30 min (3 instances) | 35.4 M | 2.9 k | no findings |
| `websocket` | Managed `WebSocket` receive against a frame model; guarded receive buffers | 30 min (3 instances) | 52.0 M | 8.5 k | WS-UTF8-1 |
| `unsafeder` | `PemEncoding`, `AsnDecoder.TryRead*` into exactly sized guarded spans | 30 min (3 instances) | 44.0 M | 8.6 k | no findings |
| `unsafex509` | `X509CertificateLoader`, `CertificateRequest.LoadSigningRequest`, `X500DistinguishedName` from guarded memory | 30 min (3 instances) | 51.1 M | 8.8 k | no findings |
| `blobwriter` | `BlobBuilder` / `BlobWriter` (System.Reflection.Metadata) read back from guarded memory | 30 min (3 instances) | 35.9 M | 3.6 k | no findings |
| `chunked` | `Utf8JsonReader` multi-segment, `DeserializeAsync` / `ParseAsync`, decompression streams, `XmlReader`: chunked vs whole | 30 min (3 instances) | 37.8 M | 21.9 k | ZLIB-DICT-1, ROUND4-MISC (BROTLI-EXC-1) |
| `httpheaders` | System.Net.Http header values (`TryParse` round trips, `HttpHeaders` views) | 30 min (3 instances) | 65.7 M | 10.7 k | ROUND4-MISC (HTTP-QVALUE-1) |
| `dcjson` | DataContract JSON reader / writer against System.Text.Json | 30 min (3 instances) | 39.8 M | 8.3 k | DCJSON-ENC-1, DCJSON-SCOPE-1, ROUND4-MISC (DCJSON-LENIENT-1, DCJSON-CTRL-1) |
| `pipelines` | System.IO.Pipelines against a byte-queue model | 30 min (3 instances) | 38.7 M | 2.3 k | no findings |

### Round 4 summary

| ID | Component | Kind | Severity (my assessment) | Versions |
|----|-----------|------|--------------------------|----------|
| [DCJSON-ENC-1](#dcjson-enc-1) | `JsonReaderWriterFactory.CreateJsonReader(Stream)`, `DataContractJsonSerializer.ReadObject(Stream)` | Encoding detection now looks only at the first `Read`: UTF-16 JSON without a BOM fails when the stream returns 1 byte first (8–10 read it), and the new BOM support fails on short first reads | **Medium** | **.NET 11 regression** |
| [WS-UTF8-1](#ws-utf8-1) | Managed `WebSocket` (client and server, used by ASP.NET Core) | A fragmented text message whose last fragment is empty is delivered as complete without the end-of-message UTF-8 check: truncated sequences and bytes like `C0` get through | **Medium** | .NET 8, 9, 10, 11 |
| [SR-BOM-1](#sr-bom-1) | `StreamReader` (BOM detection, the default) | When the first read returns 1–2 bytes, BOM detection runs again on later buffers: BOM-like bytes mid-stream are dropped or switch the decoding to UTF-16 / UTF-32; a BOM split across reads is missed | **Medium** | .NET 8, 9, 10, 11 |
| [COMP-EXACT-1](#comp-exact-1) | `DeflateEncoder.TryCompress` (new in 11) | Fails for a destination of exactly the compressed size; one byte more works | Low–Medium | new .NET 11 API |
| [MARSHAL-TSTR-1](#marshal-tstr-1) | `Marshal.StructureToPtr` (ANSI `ByValTStr`, ANSI by-value `char[]`) | A non-ASCII string is cut inside a UTF-8 sequence, or throws when its UTF-8 is longer than `SizeConst`; any non-ASCII char in a by-value `char[]` throws; ASCII strings are truncated | Low–Medium | .NET 8, 9, 10, 11 (exception type changed in 11) |
| [BR-CHARS-1](#br-chars-1) | `BinaryReader.ReadChars` | Throws `ArgumentException` ("output char buffer is too small") for invalid UTF-8, or a character outside the BMP, at the end of the requested count | Low–Medium | .NET 8, 9, 10, 11 |
| [JSON-DEEPEQ-1](#json-deepeq-1) | `JsonElement.DeepEquals`, `JsonNode.DeepEquals` | Throw `ArgumentOutOfRangeException` for any number whose exponent doesn't fit in an `int`, even when comparing a document with itself | Low–Medium | .NET 9, 10, 11 |
| [DCJSON-SCOPE-1](#dcjson-scope-1) | DataContract JSON reader / `DataContractJsonSerializer` | A stray closing bracket after the root value is ignored (`9]`, `[1]}`, `[9]]`); a second one (`9]]`) throws `IndexOutOfRangeException`, which `ReadObject` doesn't wrap | Low–Medium | .NET 8, 9, 10, 11 |
| [ZLIB-DICT-1](#zlib-dict-1) | `ZLibStream` | A zlib header asking for a preset dictionary throws `ZLibException` (an `IOException`) rather than `InvalidDataException`; in 11 the message shows a raw `'{0}'` | Low | .NET 8, 9, 10, 11 (message: 11 regression) |
| [ZIP-ENC-1](#zip-enc-1) | `ZipArchiveEntry.Open` / `OpenAsync` (encryption support new in 11) | For an encrypted entry with an unknown encryption method, `Open` throws `InvalidDataException` and `OpenAsync` `NotSupportedException`; the two also check header, method and password in different orders | Low | new .NET 11 API |
| [COMP-EMPTY-1](#comp-empty-1) | `DeflateDecoder` / `ZLibDecoder` / `GZipDecoder.TryDecompress` (new in 11) | Decompressing an empty payload into an empty destination returns `false` | Low | new .NET 11 API |
| [ROUND4-MISC](#round4-misc) | various | See the list at the end of this section | Informational | |

### WS-UTF8-1

**The managed WebSocket accepts invalid UTF-8 in text messages that end with an empty fragment.**
RFC 6455 (§5.6, §8.1) requires an endpoint to fail the connection when a text message isn't valid
UTF-8. `WebSocket.CreateFromStream` (the implementation behind `ClientWebSocket` and ASP.NET Core's
server WebSockets) validates text payloads as they arrive, leaving an incomplete sequence at the end
of a fragment for the next one, and checks that nothing is left over when the message ends. When the
final fragment (FIN, opcode 0) has no payload, that last check is skipped:

| Frames (unmasked, as received by a client) | Result on 8.0.31, 9.0.20, 10.0.12, 11.0 RC1 |
|---|---|
| `01 01 F0`, `00 01 80`, `80 00` (text `F0`, continuation `80`, empty final continuation) | delivered as a complete text message `F0 80` |
| `01 02 61 C3`, `80 00` | delivered: `61 C3` |
| `01 01 C0`, `80 00` | delivered: `C0` (a byte that never appears in UTF-8) |
| `01 01 F0`, `80 01 80` (the same bytes, non-empty final fragment) | rejected (`WebSocketException`) |
| `81 02 61 C3` (unfragmented) | rejected |

The receive buffer size doesn't matter. A peer can therefore hand an application "text" that isn't
UTF-8, which the application reasonably assumes the framework validated (a server echoing messages
to other clients forwards them, a strict decoder throws). The `C0` case shows the per-fragment check
also keeps a byte that can never start a sequence as "incomplete" at the end of a fragment, so the fix
needs both: reject such bytes immediately, and validate the remainder when the message ends, whatever
the length of the last fragment. Found by the `websocket` target (a frame decoder as the model).

### SR-BOM-1

**`StreamReader` decodes the same bytes differently depending on how the stream hands them out.**
With `detectEncodingFromByteOrderMarks: true` (what `new StreamReader(stream)` and
`new StreamReader(stream, encoding)` use), the reader looks for a byte order mark in its first
buffer. If the first `Read` returns fewer bytes than it needs to decide (1 or 2), detection stays
pending and is applied to the start of a later buffer instead, in the middle of the text. A stream
that returns data in small pieces (a pipe, a socket, a decompression or custom stream) gives, on
8.0.31, 9.0.20, 10.0.12 and 11.0 RC1 alike:

| Bytes | Reads | `ReadToEnd()` | With a single read |
|---|---|---|---|
| `ab` `EF BB BF` `cd` (UTF-8) | 2, 3, 2 | `abcd` | `ab\uFEFFcd` |
| `ab` `FF FE` `cd` (UTF-8) | 2, 2, 2 | `ab\u6463` (switched to UTF-16) | `ab\uFFFD\uFFFDcd` |
| `ab` `FE FF` `cd` (Latin-1) | 2, 2, 2 | `ab\u6364` (switched to UTF-16BE) | `abþÿcd` |
| `a` `U+FEFF` `b` (UTF-16LE) | 2, 2, 2 | `ab` | `a\uFEFFb` |
| `a` `FF FE 00 00` `bc` (UTF-16LE) | 2, 4, 4 | `a\uFFFD` (switched to UTF-32) | `a\uFEFF\u0000bc` |
| `EF BB BF` `hi` (Latin-1 given) | 1, 1, 1, 2 | `ï»¿hi` (BOM missed) | `hi` (UTF-8) |
| `FF FE 00 00` `hi` (UTF-32LE) | 2, 2, 8 | `\u0000h\u0000i\u0000` (UTF-16) | `hi` |

So text read from the same byte stream depends on how the operating system or the sender splits
it: a peer that controls the chunking (sends two bytes, then the rest) can make a reader drop
characters or switch the rest of the stream to another encoding, and ordinary data containing
`U+FEFF` or the bytes `FF FE` / `FE FF` (Latin-1 `ÿþ`) is corrupted when an early read happens to
be short. Detection should either wait until it has enough bytes or give up after the first
buffer; it should never apply past the start of the stream. Found by the `textio` target (a
stream returning a few bytes per `Read`).

### BR-CHARS-1

**`BinaryReader.ReadChars(count)` throws `ArgumentException` for some UTF-8 input.** It reads bytes
and decodes them into the space left for `count` chars. When the decoder produces two chars at once
into one remaining slot, `Decoder.GetChars` throws "The output char buffer is too small to contain
the decoded characters": an invalid lead byte followed by an ASCII byte (`C3 61` with
`ReadChars(1)`: the replacement character and `a` arrive together), a truncated sequence
(`61 E4 B8 62` with `ReadChars(2)`), or a character outside the BMP (`F0 9F 98 80`, a surrogate pair,
with `ReadChars(1)`). `Encoding.UTF8.GetString` decodes all of these. `BinaryReader.ReadChar` is
documented to throw for surrogates; `ReadChars` isn't, and invalid input shouldn't depend on the
count asked for. Same on 8.0.31, 9.0.20, 10.0.12 and 11.0 RC1.

### DCJSON-ENC-1

**.NET 11 regression: the DataContract JSON stream reader decides the encoding from the first `Read`
alone.** `JsonReaderWriterFactory.CreateJsonReader(Stream, encoding: null, ...)`, which
`DataContractJsonSerializer.ReadObject(Stream)` uses, detects UTF-8 / UTF-16 / UTF-32 from the first
bytes. In 11.0 RC1 it also learned to skip byte order marks, but it now looks only at what the first
`Read` of the stream returned:

| `{"a":"hi","b":[1,2]}` encoded as | 8.0.31 / 9.0.20 / 10.0.12, first read 1 byte | 11.0 RC1, first read 1 byte | 11.0 RC1, `MemoryStream` / `byte[]` |
|---|---|---|---|
| UTF-16LE, no BOM | read | `XmlException`: "The token '"' was expected but found ' '" | read |
| UTF-16BE, no BOM | read | same `XmlException` | read |
| UTF-16LE with BOM | rejected (no BOM support) | rejected | read (new) |
| UTF-8 with BOM | rejected (no BOM support) | rejected (also with a 2-byte first read) | read (new) |

`DataContractJsonSerializer.ReadObject` over such a stream throws `SerializationException` (inner
`XmlException`) on 11.0 RC1 and returns the object on 8–10. Network, pipe and decompression streams
routinely return a byte or two on the first read, so UTF-16 JSON that worked before breaks depending on
timing. Found by the `dcjson` target (a stream returning a few bytes per read against `byte[]`).

### DCJSON-SCOPE-1

**The DataContract JSON reader mishandles stray closing brackets after the root value.** One is ignored:
`9]`, `1}`, `"s"]`, `[1]]`, `{}}` and even the mismatched `[1]}` read as if the bracket weren't there
(`ReadObject<int[]>("[9]]")` is `[9]`), while `null]` is rejected. Two throw
`IndexOutOfRangeException` from `XmlJsonReader.ExitJsonScope`, from `CreateJsonReader` and from
`DataContractJsonSerializer.ReadObject` alike (`9]]`), which doesn't wrap it in its documented
`SerializationException`, so a service deserializing request bodies with it sees an unexpected
exception type for a four-byte input. Same on 8.0.31, 9.0.20, 10.0.12 and 11.0 RC1.

### ZLIB-DICT-1

**`ZLibStream` doesn't handle a zlib header that asks for a preset dictionary.** A valid zlib header
with the FDICT flag (`78 20`, `78 BB`) makes zlib return `Z_NEED_DICT`, which `Inflater` treats as an
unexpected error: `ZLibStream.Read` throws `System.IO.Compression.ZLibException` (derived from
`IOException`) instead of the `InvalidDataException` used for every other kind of bad data, so callers
that catch `InvalidDataException` around decompression of untrusted data let it through. In 11.0 RC1 the
message also lost its formatting: "The underlying compression routine returned an unexpected error
code: '{0}'" (8–10: "...an unexpected error code."). The new `ZLibDecoder.TryDecompress` returns `false`
for such input. Found by the `chunked` target.

### COMP-EXACT-1

**`DeflateEncoder.TryCompress` needs one byte more than the compressed size.** .NET 11 adds
span-based `DeflateEncoder`, `ZLibEncoder` and `GZipEncoder` next to `BrotliEncoder`. For every
input tried, `DeflateEncoder.TryCompress(source, destination, out written)` returns `false` when
`destination` is exactly as long as the compressed output, and succeeds, writing that many bytes,
with one byte more: an empty input compresses to 2 bytes but fails into 2, 840 bytes of text
compress to 35 bytes but fail into 35, and so on. `ZLibEncoder`, `GZipEncoder` and `BrotliEncoder`
succeed at the exact size. `false` is documented to mean "destination too small", so callers that
size the buffer from a previous compression of the same data (or retry with the reported size) get
a failure for a buffer that is big enough (I haven't traced the cause in the source). 11.0 RC1 only
(new API). Found by the guard-page `unsafecomp` target.

### MARSHAL-TSTR-1

**Marshalling an ANSI by-value string (`[MarshalAs(UnmanagedType.ByValTStr, SizeConst = n)]` with
`CharSet.Ansi`, which is UTF-8 on Unix) handles non-ASCII text inconsistently.** For
`SizeConst = 4`, `Marshal.StructureToPtr` writes:

| Managed string | UTF-8 | Native bytes | Read back |
|---|---|---|---|
| `abcdef` | 6 bytes | `61 62 63 00` | `abc` (truncated, as documented) |
| `éé` | 4 bytes | `C3 A9 C3 00` | `é\uFFFD`: the terminator overwrote half of the second `é` |
| `😀` | 4 bytes | `F0 9F 98 00` | `\uFFFD` |
| `中文` | 6 bytes | — | `ArgumentException`: "The output byte buffer is too small to contain the encoded data" |

So the string is encoded into `SizeConst` bytes (throwing when it doesn't fit) and the last byte is
then forced to 0, instead of truncating at a character boundary that leaves room for the terminator.
Structs read with `PtrToStructure` can't always be written back: the fuzzer got there by reading
arbitrary bytes into such a struct (invalid UTF-8 becomes U+FFFD, three bytes each) and marshalling
it again. Same on 8.0.31, 9.0.20, 10.0.12 and 11.0 RC1 (`CSTRMarshaler.ConvertFixedToNative`).

By-value `char` arrays in an ANSI struct (`[MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] char[]`)
are worse: each char becomes UTF-8 into a `SizeConst`-byte field, so any non-ASCII char (`a`, `é`, `z`
needs 4 bytes for 3) makes `StructureToPtr` fail. 8.0.31, 9.0.20 and 10.0.12 throw `COMException`
(0x8007007A, "The data area passed to a system call is too small"); 11.0 RC1, where struct marshalling
moved to managed code (`StructureMarshaler<T>`, `AnsiCharArrayMarshaler`), throws `ArgumentException`
instead, a behavior change for code that catches the former. Found by the guard-page `unsafemarshal`
target.

### JSON-DEEPEQ-1

**`JsonElement.DeepEquals` (new in .NET 9) throws for valid numbers with large exponents.** It
compares numbers semantically (`1.0` equals `1`), parsing each into sign, digits and an `int`
exponent (`JsonHelpers.AreEqualJsonNumbers`). An exponent outside the `int` range throws
`ArgumentOutOfRangeException` ("The exponent value in the specified JSON number is too large"), so
`DeepEquals` of `1e2147483648`, `-1E-99999999999` or `0.000e99999999999999` with an identical
document throws instead of returning `true`, and so does `JsonNode.DeepEquals` on nodes containing
such a number. `JsonDocument.Parse` accepts these numbers (the JSON grammar has no limit), so any
code comparing untrusted JSON with `DeepEquals` gets an unexpected exception type. Same on 9.0.20,
10.0.12 and 11.0 RC1. Found by the `unsafejson` target.

### ZIP-ENC-1

**`ZipArchiveEntry.Open` and `OpenAsync` fail differently on the same encrypted entry.** .NET 11 adds
zip encryption (`Open(ReadOnlySpan<char> password)`, `OpenAsync(password, ...)`, `IsEncrypted`,
`EncryptionMethod`). For an entry whose central directory marks it as encrypted with a method the
reader doesn't know (`EncryptionMethod == Unknown`), `Open()` and `Open(password)` throw
`InvalidDataException` ("The archive entry was compressed using an unsupported compression method"),
while `OpenAsync()` throws `NotSupportedException` ("The entry's encryption method is not supported").
With the AES marker method (99), `Open()` reports an unsupported compression method and `OpenAsync()`
that a password is required; with a corrupt local header, `Open()` reports the header and
`OpenAsync()` the password. Code that catches `InvalidDataException` around the async API (the only
exception the rest of `System.IO.Compression` uses for bad archives) sees `NotSupportedException`
escape. 11.0 RC1 only (new API). Found by the `archive` target (synchronous against asynchronous
reading).

### COMP-EMPTY-1

**The zlib-based decoders can't decompress an empty payload into an empty destination.**
`DeflateDecoder.TryDecompress(compressedEmpty, Span<byte>.Empty, out written)` returns `false` (the
same for `ZLibDecoder` and `GZipDecoder`), although the data decompresses to 0 bytes; with a
one-byte destination it returns `true` with 0 bytes written. `BrotliDecoder` returns `true`. Callers
that know the uncompressed length (a length-prefixed format) and allocate exactly that fail on empty
payloads. 11.0 RC1 only (new API).

### ROUND4-MISC

- JSON-FLOAT-1: `Utf8JsonReader.TryGetSingle` / `TryGetDouble` return `true` with ±Infinity for numbers
  beyond the type's range (`3.5e38` as `float`, `1e309` as `double`), so `JsonSerializer.Deserialize<float>("1e80")`
  gives `Infinity`, which `JsonSerializer.Serialize` then rejects with `ArgumentException` unless
  `AllowNamedFloatingPointLiterals` is set: the serializer can't write back what it read (8.0 to 11.0).
- JSON-UTF8-1: a `JsonElement` (for example a `Dictionary<string, JsonElement>` value) keeps invalid
  UTF-8 in property names as is (`{"Map":{"<B0>":1,"<8C>":2}}` deserializes, even with
  `AllowDuplicateProperties = false`, since the names are different bytes), and writing it replaces
  each invalid byte with U+FFFD, so the output has two `"�"` properties that the same options
  then reject as duplicates. (A `Dictionary<string, double>` rejects such names up front.)
- DCJSON-CTRL-1: `JsonReaderWriterFactory.CreateJsonReader` throws `FormatException` ("Encountered invalid
  character") for a raw control character inside a JSON string, where other malformed JSON throws
  `XmlException`; `DataContractJsonSerializer.ReadObject` wraps both in `SerializationException`
  (8.0 to 11.0).
- DCJSON-LENIENT-1: the DataContract JSON reader (`JsonReaderWriterFactory.CreateJsonReader`) accepts a
  lot of invalid JSON at the `XmlDictionaryReader` level: any run of non-delimiter characters as a number
  (`1x2`, `1"2`, `--1`, `0x10`, `Infinity`, control characters), values without commas inside one element
  (`[1 2]` is one number element with the texts `1` and `2`, `[true false]` one boolean), and NUL bytes as
  whitespace between tokens. `DataContractJsonSerializer` rejects most of it when converting (it accepts
  `[1.]` and `Infinity`), but a reader-to-writer copy turns it into different JSON (`[true false]`
  becomes `[truefalse]`), and the `byte[]` and `Stream` overloads disagree once such junk crosses a buffer boundary
  (8.0 to 11.0).
- BROTLI-EXC-1: `BrotliStream` reports corrupt data with `InvalidOperationException` ("Decoder ran into
  invalid data"), where `DeflateStream`, `ZLibStream` and `GZipStream` throw `InvalidDataException`
  (8.0 to 11.0).
- HTTP-QVALUE-1: `StringWithQualityHeaderValue` parses
  q-values with more than three decimals or leading zeros (`q=0000.6001`), which RFC 9110 doesn't allow,
  and `ToString()` rounds them to three decimals, so the value read back isn't `Equal`.
- `BinaryReader.ReadChars` never flushes its decoder: an incomplete UTF-8 / UTF-16 sequence at the end
  of the stream is dropped, where `Encoding.GetString` and `StreamReader` produce U+FFFD.
- `JsonNode.ToJsonString` of a node parsed from a string with an escaped lone surrogate throws
  `InvalidOperationException`, the same as JSON-SURR-1 (round 3) through the node API.

---

## Base64 guard-page campaign (2026-10-04)

A targeted follow-up on Base64 / Base64Url decoding. The new `base64guard` target
(`Base64GuardTarget.cs`) calls every decoding entry point: UTF-8 and UTF-16, one-shot, streaming
(`isFinalBlock: false`), in-place, `Try*`, the allocating overloads, `IsValid` and
`Convert.TryFromBase64Chars`. Sources and destinations are exactly sized against guard pages, the
destination size comes from the fuzzer (exact, short, scaled or oversized), and every result has to
match the same call on plain arrays and the reference decoder from `Base64Target`. In the payload,
each byte below 0xF0 maps onto the alphabet, so long valid inputs that reach the vector paths are
easy to generate.

Before fuzzing, the decode paths of the RC1 CoreLib were checked against a local build of `main`
(2026-09-18): every `Base64Helper` decode method has the same IL size, so RC1 results apply to the
code that is about to ship.

| Target | Assemblies | Wall-clock | Execs | Edges | Crashes | Result |
|---|---|---|---|---|---|---|
| `base64guard` | CoreLib (guarded, `SHARPFUZZ_GUARD=1`) | 30 min (8 instances) | 38.9 M | 4.5 k | 156 | B64URL-AVX2-1 (all 156) |
| `base64` | CoreLib | 30 min (4 instances) | 44.6 M | 5.5 k | 0 | no new findings |

### B64URL-AVX2-1

**Withheld: this may have security impact, so it should go to the Microsoft Security Response
Center rather than a public issue.**

All 156 crashes are `AccessViolationException`s from a guard page, with the same top frames:
`Base64Helper.Avx2Decode<Base64UrlDecoderByte, byte>` called from `Base64Url.DecodeFromUtf8(source,
destination, out, out, isFinalBlock)`. That call is reached directly, through `TryDecodeFromUtf8`,
through the streaming loop, and through the whitespace fallback.

- It happens only when the AVX2 path is enabled, with AVX-512 on or off (61 with the full ISA, 90 with
  `DOTNET_EnableAVX512=0`), and never with `DOTNET_EnableAVX2=0`.
- In every direct call it happens with `isFinalBlock: true` and a destination that ends at a guard
  page and is smaller than the decoded output.
- `Base64` (not Url), the UTF-16 overloads, in-place decoding and `IsValid` never crashed.

**Not yet confirmed outside the fuzzer.** A plain repro was clean on stock 9.0.20, 10.0.12 and 11 RC1,
with every ISA setting. It decodes valid Base64Url text into every too-short destination carved out
of a larger array and checks the bytes after the slice. So the triggering inputs need more than
that, or the instrumented CoreLib is involved. Triage was stopped at this point. The next step is
to replay the saved inputs (WSL: `/root/sharpfuzz/out-b64g/base64guard/*/crashes`, stacks bucketed
in `/root/sharpfuzz/triage-b64g/stacks.txt`) with guard pages on the stock RC1 runtime, and then
report through MSRC. The harness does not suppress this finding: it is a process crash.

## Unsafe-code best-practices review (2026-10-04)

A source review, not a fuzzing campaign. It checks the areas covered by the guard-page targets
against all 26 sections of Microsoft's
[unsafe code best practices](https://learn.microsoft.com/en-us/dotnet/standard/unsafe-code/best-practices)
on `main` (the same code as 11.0 RC1 for these files). Seven areas: Base64 / Base64Url encoding and
hex; text transcoding and ASCII / Latin-1; number formatting and parsing; span search and
`SearchValues`; System.IO.Compression and Brotli; System.Text.Json and System.Text.Encodings.Web;
the IP / `Uri` parsers and the managed WebSocket. Base64 decoding is covered by B64URL-AVX2-1 above, and
the UTF-8 ignore-case helpers are excluded (UTF8CASE-1).

Each finding below was checked at two levels. First, the pattern exists at the cited lines; the
key lines of every finding were re-read. Second, every caller in the repo was traced to decide
whether the assumption the code depends on can actually break. Nothing was built or run for this
review. Unless a finding says otherwise, **the assumption holds for every caller today**. These are
hardening gaps: the only guard is a `Debug.Assert`, a comment, caller arithmetic, or a runtime
implementation detail. They are not reachable memory-safety bugs.

### Summary

| Areas reviewed | Findings | DON'T rules broken | Hardening gaps (assumption holds) | Reachable by a caller | Withheld |
|---|---|---|---|---|---|
| 7 (about 120 files) | 35 | 4 (NUM-5/11-1, TEXT-11-1, WS-2/22-1, STJ-1-1) | 30 | TEXT-11-1 (process crash), STJ-5-1, STJ-16-2, STJ-20-1 (wrong output, no memory corruption) | TEXT-24-1 |

The most common gap, in most areas, is rule 9 / 24. Vector loads and stores, and table lookups
with `Unsafe.Add`, are bounded only by caller arithmetic, and the `Debug.Assert`s that back them up
are missing or check a smaller width than the access. The second is pointers stored inside `fixed`
(rules 1 / 2), which stay in native or struct state after the pin ends.

### Findings that a caller can trigger

- **TEXT-11-1** (`Text/Latin1Utility.cs:997-1021`, `WidenLatin1ToUtf16_Sse2`; rules 11, 24; DON'T
  rule broken).
  - The alignment offset is computed as if the UTF-16 destination were at an even address, and the
    stores use `Sse2.StoreAligned`.
  - A `char` destination at an odd address, which is possible through `Latin1Encoding.GetChars(byte*,
    int, char*, int)` or a span reinterpreted with `MemoryMarshal.Cast`, makes the aligned store
    fault. The result is a process crash, not an exception.
  - Destinations backed by a `string` or `char[]` are always aligned.
  - The ASCII equivalent (`Ascii.Utility.cs:2211-2222`) handles odd destinations and uses `Store`.
  - Fix: use `Store`, or skip the alignment step for odd pointers.
- **STJ-5-1** (`Writer/Utf8JsonWriter.cs:140-175`, `Utf8JsonWriter.WriteValues.StringSegment.cs:35-39`;
  rules 5, 11, 21).
  - All three segment kinds (UTF-8, UTF-16, Base64) share one 3-byte leftover buffer, and the
    UTF-16 view reinterprets it with `MemoryMarshal.Cast<byte, char>`.
  - With `SkipValidation = true`, switching segment encoding mid-string doesn't clear the leftover,
    so 1-3 leftover bytes are read back as a different encoding and written out.
  - Memory-safe, but the output is wrong. Fix: clear the leftover when the container kind changes.
- **STJ-16-2** (`Utf8JsonWriter.WriteValues.String.cs:181-205`, `WriteProperties.Helpers.cs:220-225`,
  `JsonWriterHelper.Escaping.cs:130-143, 254-262`; rule 16).
  - The writer reserves 6 bytes per input char and checks the transcoding status only in Debug.
  - A custom `JavaScriptEncoder` that emits non-ASCII escapes, or lone surrogates, gets its string
    silently truncated in Release.
  - The writes are bounds-checked.
- **STJ-20-1** (`Document/JsonDocument.cs:61-89`, `JsonMarshal.cs:25-47`,
  `JsonSerializer.Read.Element.cs`; rules 20, 23).
  - `Dispose` returns the document's pooled buffers while spans obtained after `CheckNotDisposed`,
    such as `JsonMarshal.GetRawUtf8Value` or `Deserialize(JsonElement)`, may still be read.
  - This happens only when a caller misuses the documented not-thread-safe contract: disposing on
    another thread, or from a converter. The reader then sees cleared or reused data. Nothing is
    written.

### TEXT-24-1 (withheld, needs confirmation)

This may have security impact, so it should go to MSRC rather than a public issue.

- **Where:** `Ascii.Utility.cs`, `GetIndexOfFirstNonAsciiChar_Vector` (used on AVX2 / AVX-512
  machines), and `Latin1Utility.cs`, `GetIndexOfFirstNonLatin1Char_Default` (non-SSE2 machines,
  such as Arm64).
- **What the review reports:** when the `char` input starts at an odd address, the alignment step
  mixes byte and char counts. That can return a wrong index, which makes `GetByteCount` undercount,
  and may read one byte past the end of the input.
- **Status:** not reproduced. Downstream writers check destination lengths, so the review found no
  write past a destination.

### Hardening gaps (the assumption holds for every caller)

| ID | Where | Rules | What |
|---|---|---|---|
| B64ENC-24-1 | `Base64UrlEncoder.cs:246-248` → `Base64EncoderHelper.cs:37-42` | 9, 16, 24 | The Base64Url source limit isn't capped at the source length. For a 1,610,612,734-byte source with an `int.MaxValue` destination, the limit is one past the end. Loop strides keep the reads in bounds, but the call returns `DestinationTooSmall` instead of encoding the last byte (a functional bug). Plain Base64 caps it. |
| B64ENC-24-2 | `Base64EncoderHelper.cs:164, 408, 803, 887` | 9, 24 | `AssertRead`/`AssertWrite` check a smaller width than the SIMD access (32 of 64, 16 of 48, 16 of 64 bytes; 16 of 64 chars). |
| B64URL-1/26-1 | `Base64UrlEncoder.cs:162-172`; `Directory.Build.props:307` | 1, 26 | `EncodeToString` passes `&source` (a span) to `string.Create` as an `IntPtr`. CS8500 is suppressed repo-wide. `Base64.EncodeToString` passes the span directly. |
| HEX-24-1 / HEX-24-2 | `Common/src/System/HexConverter.cs:120-184, 304-453` | 9, 16, 24 | The vectorized hex encode and decode store without checks. The destination sizes are `Debug.Assert` only (lines 189, 206, 307-308). |
| NUM-5/11-1 | `Number.Formatting.cs:1777-1798, 2287-2320` | 5, 11 | `MemoryMarshal.Cast<char, DigitPair(uint)>` followed by plain `uint` stores. For odd-length strings the stores are only 2-byte aligned. Fine on x64 / Arm64; `WriteTwoDigits` uses `MemoryMarshal.Write`. |
| NUM-9/5/3-1 | `Number.BigInteger.cs:849-855` | 3, 5, 9 | `Unsafe.As<byte, BigInteger>` over a static table. The full extent is `Debug.Assert` only, and on 64-bit the table has no slack (121 of 121 elements). |
| NUM-9-2 | `Number.BigInteger.cs`, `ShiftLeft` | 9, 16 | The overflow guard checks the input length, not the shifted length, so the `SetZero` fallback never runs. Bounds-checked inline-array accesses would throw. The margin is thin (about 3,682 of 3,690 bits). |
| NUM-19-1 | `Number.BigInteger.cs`, `SkipInit` sites; `GetBlock`/`GetBits64`/`HasZeroTail` | 19 | Blocks past `_length` are uninitialized, and indices are checked against `_length` in Debug only. |
| NUM-9-3 | `FormattingHelpers.CountDigits.cs:54-55` | 9 | Unchecked `Unsafe.Add` table read (maximum index 20 of 21). |
| NUM-17-1 | `Number.Formatting.cs:288-293` | 17 | `GetFreshStringSpan` returns a writable span over any string. Only a comment says the string must be fresh; every caller passes `FastAllocateString`. |
| TEXT-19-1 | `Utf8Utility.Transcoding.cs:886-891, 948-959` | 19 | `Unsafe.SkipInit` of a vector mask, safe only while two copies of the same ISA condition stay identical. |
| SV-1-1 | `SearchValues/ProbabilisticMapState.cs:31`; `ProbabilisticMap.cs:376-395` | 1, 8, 16 | An ordinary struct stores a `ReadOnlySpan<char>*` to the caller's stack-local span. The lifetime rule is a comment. |
| SV-15-1 | `SearchValues/ProbabilisticMap.cs:27-103` | 3, 4, 15, 16 | Eight `uint` fields are addressed as an array via `Unsafe.Add(ref _e0, …)`. `[InlineArray(8)]` would express this. |
| SV-5-1 | `SearchValues/Strings/AsciiStringSearchValuesTeddyBase.cs:113-141, 565-660` | 5 | Unchecked `Unsafe.As<string[]>`/`Unsafe.As<string>` on object buckets, chosen by a generic constant. |
| SPAN-9-1 | `SpanHelpers.Byte.cs:298-450`, `SpanHelpers.Char.cs:313-465` | 9, 24 | The substring `LastIndexOf` SIMD loops have no bounds asserts; the `IndexOf` counterparts do. |
| SPAN-16-1 | `SpanHelpers.Char.cs:530-870`, `SpanHelpers.Byte.cs:451-740` | 16, 24 | The null-terminator scans read past the terminator within a page (by design). `IndexOfNullByte` compares a length to an offset, which is misleading. |
| COMPR-16-1 | `DeflateZLib/Inflater.cs:58-69` | 9, 16, 22 | `Inflate(byte[], offset, length)` hands `bufPtr + offset`/`length` to zlib with no range check. |
| COMPR-16-2 | `Crc32Helper.ZLib.cs:12-19` | 9, 16, 22 | The length goes to native `crc32` with only a `Debug.Assert`. |
| COMPR-2-1 | `DeflateEncoder.cs:202-236`, `DeflateDecoder.cs:77-108`, `Inflater.cs:280-291`, `Deflater.cs:111-128` | 1, 2, 22 | `NextIn`/`NextOut` set inside `fixed` stay in the zlib state after the pin ends. |
| WS-2/22-1 | `WebSockets/Compression/WebSocketInflater.cs:126-252` | 2, 22 | Same as COMPR-2-1, but the buffer has also been returned to the pool before `Finish()` calls `inflate`. Safe only because `AvailIn == 0`, which is checked by `Debug.Assert` only. The deflater zeroes `NextIn`. |
| COMPR-5-1 | `Zstandard/ZstandardDictionary.cs:105-139` | 3, 5, 11, 16 | `ArrayPool<byte>.Rent(n * sizeof(nuint))` with an unchecked multiply, then `MemoryMarshal.Cast` to `nuint` for native code. This relies on array-data alignment. |
| COMPR-14-1 | `WinZipAesKeyMaterial.cs:42-67` | 14 | The `stackalloc` length's upper bound is `Debug.Assert` only. |
| URI-20-1 | `System.Private.Uri/src/System/Uri.cs:4310-4321` | 16, 20 | In-place unescape reads a slice of the `ValueStringBuilder` it appends to. If the builder grew, the array would go back to the pool mid-read. |
| URI-19/20-2 | `UriHelper.cs:153-192`, `UriExt.cs:576-616` | 19, 20 | A `ValueStringBuilder` over the caller's destination is assumed never to grow; the check is `Debug.Assert` only. |
| URI-9/19-3 | `Common/src/System/Text/ValueStringBuilder.cs:34-43, 78-85` | 9, 19 | The indexer and `Length` setter check against `_pos` in Debug only, over a `SkipLocalsInit` `stackalloc`. |
| STJ-1-1 | `Reader/JsonReaderHelper.netstandard.cs:20-139` (netstandard / .NET Framework builds only) | 1, 9, 24 | `Unsafe.AsPointer` on an unpinned byref to compute alignment (affects performance only), plus unchecked `AddByteOffset` reads. |
| STJ-16-1 | `Reader/JsonReaderHelper.Unescaping.cs:356-375, 513` | 9, 16 | `Unescape` ignores the `TryUnescape` result in Release. Line 513 uses `>=`, which may make `CopyString` reject a destination of exactly the unescaped length (functional; needs confirmation). |
| STJ-20-2 | `JsonSerializer.Write.Document.cs:127-156`, `Common/src/System/Net/ArrayBuffer.cs:60-70`, escape scratch buffers | 19, 20 | Serialized payloads and escape buffers go back to the shared pool uncleared, which contradicts the code comment. |
| TEW-13-1 | `System.Text.Encodings.Web/.../TextEncoder.cs:42-48, 539-547` | 4, 13, 16 | A null or past-the-end pinned pointer (with length 0) is passed to user-overridable `unsafe` virtual methods. |

Not memory-related: `Base64.EncodeToUtf8InPlace` returns `Done` for an empty buffer before it
validates `dataLength`.

Areas with no findings beyond these: the IP address parsers, `IriHelper`, `DomainNameHelper`, the
`ManagedWebSocket` receive and send paths, Brotli, zlib / Brotli / Zstd handle lifetimes,
`ProbabilisticMap` and `IndexOfAnyAsciiSearcher` vector loops, `SpanHelpers.T` / `.Packed`, UTF-8 / UTF-16
validation, `Utf8Formatter` / `Utf8Parser`, `OptimizedInboxTextEncoder`, and the `Reflection.Emit`
member accessor in System.Text.Json.

### Wave 2 (2026-10-04): interop, cryptography, networking, CoreLib text and core types

Same method as above, applied to 553 more files.

| Area | Files | Not covered |
|---|---|---|
| CoreLib core types and vector intrinsics | 63 | |
| CoreLib text / globalization | 62 | `CompareInfo.Utf8.cs` (UTF8CASE-1 exclusion) |
| Interop marshalling, CompilerServices | 73 | |
| System.Security.Cryptography (managed) | 104 | 7 pattern-scanned only |
| Crypto / security interop, Pkcs, Cose, Bcl | 121 | |
| HTTP, HttpListener, WinHttpHandler, QUIC | 57 | 4 generated WASI binding files |
| Sockets, TLS, DNS, NetworkInformation | 73 | |

Files listed under "Not covered" go to a later wave. Wave 2 found 18 withheld items, 6 functional
or leak bugs, and about 50 hardening gaps.

#### Withheld (MSRC; functional descriptions only)

These may have security impact. For the ones marked "needs confirmation", the code pattern is
verified but whether the triggering condition can occur in practice was not established. None was
reproduced.

| ID | Component | What can happen | Condition |
|---|---|---|---|
| NETB-22-1 | `SocketAsyncEventArgs` (Windows) | The native address buffer is sized for the first address family, but later receive operations report the IPv6 size to the OS and copy that much back. | A `SocketAsyncEventArgs` reused from an IPv4 to an IPv6 `ReceiveFrom` / `ReceiveMessageFrom` |
| NETA-9/16-1 | HttpListener request body read (Windows) | The per-chunk copy length is clamped to the whole read size, not the space left, so the copy can run past the caller's buffer. | http.sys returns two or more entity chunks (needs confirmation) |
| CRYPTO-7-1 | `X509Chain` (Windows) | `ChainStatus` reads the native chain after its handle was released. | The caller disposes `chain.SafeHandle`, then reads `ChainStatus` |
| CRYPTOI-7-1 | `TlsSocketSession` (OpenSSL) | Native TLS I/O and shutdown use a raw socket descriptor without holding the socket handle. | The socket handle is disposed or finalized while the session is alive |
| CRYPTO-16-2 | CNG key property strings (Windows) | A NUL scan with no length bound over a property value. | The provider or the caller supplies an unterminated value (needs confirmation) |
| CLTEXT-16-1 | ICU locale strings | `new string(char*)` over a 100-char stack buffer that ICU may leave unterminated. | An ICU result of exactly 100 code units (needs confirmation) |
| CLTEXT-22-1 | Browser locale info (WASM) | A JS-returned length is not checked against the 80-char stack buffer, and the JS fallback path writes unbounded. | An 81-85 char culture name accepted by ICU but rejected by `Intl` (needs confirmation) |
| NETA-7-3 | QUIC stream setup | A context GCHandle is freed twice. | The connection is disposed concurrently with opening a stream |
| NETA-7/22-4 | WinHttpHandler | A callback resolves a GCHandle that was already freed. | A synchronous `WinHttpSendRequest` failure followed by a late close callback (needs confirmation) |
| CRYPTOI-7-3 | OpenSSL session cache callbacks | A GCHandle lookup races with its release. | A `TlsContext` is disposed during a handshake (needs confirmation) |
| NETB-7-5 | SslStream on macOS / iOS | A native certificate is used after its managed owner became unreachable. | An intermediate certificate with a private key (needs confirmation) |
| NETB-20/22-7 | Network.framework TLS | A pooled buffer is unpinned and returned while a queued native block may still use it. | Dispose during a transport read (needs confirmation) |
| CRYPTOI-16-3 | Android bignum export | A native write with no capacity; a failed size query moves the start past the array. | A JNI failure in the size query (needs confirmation) |
| CLCORE-23/24-1 | `BitArray.CopyTo(bool[])` | Vector stores loop to a re-read length field, so they can go past the destination. | `Length` is grown concurrently (misuse; inconsistent with the type's own snapshot policy) |
| INTEROP-16-1 | ANSI `StringBuilder` marshalling | The NUL terminator is written 1 byte past the native block; NativeAOT helpers take no destination length. | The builder is grown concurrently during the call |
| CLTEXT-16-2 | `StringBuilder.Append(ref char, int)` | The source read length is recomputed from fields, so the read goes past the source. | The builder is mutated concurrently |
| CRYPTOI-9-1 | ML-KEM CNG blob reader | The header and parameter-set length are read before any length check. | A third-party key storage provider |
| NETB-7/22-2 | Managed NTLM (Android / tvOS) | Channel-binding memory is read with no reference held and no size or offset validation. | A caller-supplied `ChannelBinding` subclass |

#### Functional and leak bugs (public)

- **NETA-7/22-2:** `QuicStream` gives its safe handle a boxed copy of an empty `MsQuicBuffers`
  struct, so the native send buffers are never freed. It leaks per stream.
- **NativeAOT `Marshal.GetObjectForNativeVariant`**
  (`nativeaot/.../InteropServices/Marshal.Com.cs:324`): `VT_BOOL` is handled as
  `data->As<short>() != -1`. That throws for every `VT_BOOL` variant, and the comparison is
  inverted. The fix is `data->As<bool>()`.
- **NETB-12/21-4:** `NetSecurityTelemetry` (and `HttpTelemetry`) publish a `bool` argument as a
  4-byte EventSource payload, so 3 bytes of adjacent stack go into handshake events.
- **NETB-19-8:** the WSARecvMsg control buffer is parsed without checking the returned control
  length. Uninitialized stack data or stale data can surface as `IPPacketInformation` after the
  option was cleared with `SetRawSocketOption`.
- **`Ordinal.LastIndexOf(string, string, int, int, bool)`** (`Globalization/Ordinal.cs:598-656`):
  dead code with a missing `return`.
- **SSPI `CompleteAuthToken`** (`SecuritySafeHandles.cs:902`): an inverted `Debug.Assert`.

#### Hardening gaps (the assumption holds for every caller)

| ID | Where | Rules | What |
|---|---|---|---|
| CLCORE-4-1 | `Memory.cs:384-432`, `ReadOnlyMemory.cs:300-347` | 4, 9, 23 | `Pin()` doesn't re-validate `_index` against a torn struct; the `Span` getter does. |
| CLCORE-5/11-1 | `Numerics/Matrix4x4.cs:40-55` | 5, 11 | `Unsafe.As` to an `Impl` that has 16-byte alignment; relies on unaligned SIMD codegen. |
| CLTEXT-11-1 | `Text/UnicodeEncoding.cs:1338-1413` | 10, 11 | Checks the destination's alignment, then does aligned 8-byte source reads. |
| CLTEXT-3-1 | `String.Comparison.cs:57-99, 485-499, 768-899` | 3, 4, 11 | Reads padding, the terminator and the length field; relies on zeroed allocation. |
| CLTEXT-1-1 | `Text/Unicode/Utf8.cs`, `Text/Encoding.Internal.cs` | 1 | `Unsafe.AsPointer` on slices of a pinned span. |
| CLTEXT-14-1 | `Text/UTF8Encoding.Sealed.cs:56-145` | 14, 16 | `stackalloc` into raw pointers, then the unvalidated span constructor. |
| CLTEXT-17-1 | `String.cs:537-560` | 17, 19 | A raw pointer into a fresh string is handed to any `Encoding`; the count is `Debug.Assert` only. |
| INTEROP-1/8-1 | `coreclr/.../AsyncHelpers.CoreCLR.cs:184-284, 929-1165` | 1, 2, 8 | Stack addresses are published to thread statics with no `try/finally`. |
| INTEROP-1-1 | `TypeMapLazyDictionary.cs:421, 502` | 1, 7 | `QCallTypeHandle` built from a heap field. |
| INTEROP-3/9-1 | `AsyncStateMachineDiagnostics.cs:44-100` | 3, 4, 9 | An `int` read at a reflected offset with no type or size check (profiler only). |
| INTEROP-4/16-1 | `ComWrappers.cs:936-973` | 4, 16 | A span longer than its allocation; only the loop `break` bounds it. |
| INTEROP-4/13-1, CRYPTO-4-1 | `MemoryMarshal.cs:128-140`, crypto `Helpers.cs:366-378` | 4, 13 | A ref to address 1 for empty spans (documented, pin-only). |
| CRYPTO-1-1 | `OpenSslX509ChainProcessor.cs:642-701` | 1, 2, 8, 26 | A stack-local address is left as `X509_STORE_CTX` app data. |
| CRYPTO-16-1 | `LiteHash.Unix.cs:157-261` | 16, 22 | The destination length goes to a native finalizer that ignores it; the size check is Debug-only. |
| CRYPTO-20-1 | `X509CertificateLoader.Windows.cs:221-231`, `X509CertificateLoader.Pkcs12.cs:1082-1330` | 19, 20 | Plaintext private keys are left in unzeroed intermediates during Windows PFX import. |
| CRYPTO-19-1 | `UniversalCryptoDecryptor.cs:152-158` (+2) | 19 | Uninitialized arrays are returned; "fully written" is `Debug.Assert` only. |
| CRYPTO-20-2 | `AsymmetricAlgorithm.cs:778-835`, `RSA.cs`, `PemKeyHelpers.cs` | 19, 20 | A failed third-party `Try*` export leaves its partial output in the pool. |
| CRYPTO-19-2 | `HKDFManagedImplementation.cs:64-92`, `Rfc2898DeriveBytes.OneShot.cs` | 14, 19 | Derived-key residue is left on the stack or in the pool. |
| CRYPTO-9-1 | `X509Pal.Windows.PublicKey.cs:168-199` | 9, 16 | A blob header is read with a Debug-only length check. |
| CRYPTOI-7-2 | `SspiCli/SecuritySafeHandles.cs:405-443, 673-711, 957-961` | 7, 22 | `ChannelBinding` pointer used without AddRef; the Unix path does AddRef. |
| CRYPTOI-16-1 | `Interop.EvpPkey.cs:131-216`, `Interop.Encode.cs`, `Interop.OCSP.cs`, `Interop.Pkcs7.cs` | 16, 20, 22 | Size, then encode with no capacity passed; `written` is checked in Debug only. |
| CRYPTOI-22-1 | `Interop.BCryptSignHash.cs:118-155` | 19, 22 | An empty destination becomes NULL, which BCrypt treats as a size query. |
| CRYPTOI-16-4 | `Interop.EVP.Cipher.cs:94-143`, Android `Interop.Cipher.cs` | 16, 22 | Cipher update / final calls pass no output length. |
| CRYPTOI-2-1 | `Interop.OpenSsl.cs:1237-1246` | 1, 2 | A pointer escapes a `fixed` block (the memory is native). |
| NETA-7/8-5 | `HttpListenerRequest.Windows.cs:109-125, 292-301` | 7, 8, 23 | The request blob is a bare `IntPtr`; a concurrent `Close` frees it. |
| NETA-16-6 | `MsQuicTlsSecret.cs:52-76`, `MsQuicApi.cs:151-175` | 14, 16, 22 | Native lengths are used unclamped; strlen on a raw stackalloc. |
| NETA-20-7 | `WinHttpResponseStream.cs:104-170` | 20 | A pooled buffer is returned while still pinned. |
| NETB-7/8-6 | `TlsSession.OpenSsl.cs:196-223` | 7, 8, 23 | A span over a native BIO buffer is read without AddRef. |
| NETB-2-3 | `SocketPal.Unix.cs:483-536` | 2, 22 | A `MessageHeader` is used after its `fixed` block ends. |
| NETB-2/8-9 | `SocketAsyncContext.Unix.cs` | 2, 8 | A `byte*` from `fixed` is stored in queued operation objects; safe by design rule only. |
| NETB-16/22-10 | `SocketPal.Unix.cs`, `SocketPal.Windows.cs` | 9, 16, 22 | The kernel gets caller-supplied lengths without a clamp. |

### Wave 3 (2026-10-04): Tensors, rest of CoreLib, format / parser libraries, OS-facing libraries

Same method again, on 497 more files: every file in each scope was reviewed, plus the 12 files
left over from wave 2.

| Area | Files |
|---|---|
| System.Numerics.Tensors | 27 |
| CoreLib threading, I/O, tracing, reflection, environment, GC (CoreCLR / NativeAOT / Mono included) | 192 |
| Format / parser libraries (BigInteger, CodePages, XML, DataContract, Hashing, Reflection.Metadata, Formats.*, Regex, Immutable, LINQ) and the wave-2 leftovers | 126 |
| OS-facing libraries (Process, Console, PerformanceCounter, DirectoryServices, IO.Ports, EventLog, FileVersionInfo, Common interop) | 150 |

#### Withheld (MSRC; functional descriptions only)

| ID | Component | What can happen | Condition |
|---|---|---|---|
| OS2-22-1 | `Process.ReadAllText` / `ReadAllBytes` (Windows) | The overlapped state is freed and the buffers are unpinned and returned to the pool while the other pipe's read is still pending, so the kernel later completes into freed or moved memory. | A non-EOF pipe error, a `GetOverlappedResult` failure, or buffer growth failing on one stream |
| CLSYS1-22/16-1 | `RandomAccess.Read` / `ReadAsync(IReadOnlyList<Memory<byte>>)` (Unix) | The iovec count given to the kernel is re-read from the list, so the kernel can read uninitialized or out-of-range iovecs and write file data there. | The list is mutated during an async read, or a custom list's `Count` is unstable |
| CLSYS2-1/8-3 | `FileSystemEntry.FileName` (Unix) | Safe user code can get a span into dead stack storage. | Copy the ref struct, then return `copy.FileName` |
| OS2-7-1 | `CounterData` (PerformanceCounter) | A raw pointer into a native block that the owning dataset frees on `Dispose` or finalization. | A `CounterData` kept after its dataset |
| OS2-7-2 | `GetAuthorizationGroups` result enumeration | SID pointers into freed AuthZ buffers are dereferenced. | Enumerating after the result is disposed |
| OS1-11-1 | Shared performance-counter memory (cross-user) | Unaligned atomics at offsets another user controls (fault on Windows ARM64); offset cycles cause a stack overflow or a hang. | Another local user writes the shared mapping (needs confirmation) |
| FMT-9/16-1 | `System.Reflection.Metadata` WinMD string compare | A 1-byte read past the #Strings heap. | Malformed WinMD metadata |
| OS2-16-1 | SID parsing in DirectoryServices.AccountManagement / EventLog | Over-reads, and a wild read when the sub-authority count is 0. | Malformed `objectSid` from LDAP / SAM, or a mismatched event-record SID length (needs confirmation) |
| OS2-16-2 | `FileVersionInfo.GetVersionInfo` (Windows) | `VerQueryValue` lengths are ignored, so reads can go past version-resource values. | A crafted version resource (needs confirmation) |
| OS2-2-1 | `SerialPort` event loop (Windows) | The kernel writes the event mask into an unpinned field. | Shutdown while `WaitCommEvent` is incomplete (driver-dependent; needs confirmation) |
| OS1-19-3 | `TriggerSyncReplicaFromNeighbors` | 16 uninitialized heap bytes are passed as a source GUID to `DsReplicaSyncW`. | Always on that path; whether the GUID reaches the DC needs confirmation |
| CLSYS2-16/19-4 | `Environment.UserDomainName` (Windows) | An uninitialized, unterminated stack buffer is passed as a NUL-terminated name. | `GetUserNameExW` fails with another error (needs confirmation) |
| CLSYS1-23-1 | Windows thread pool native OVERLAPPED free list | No ABA protection: one OVERLAPPED can be handed out twice. | Concurrent allocate / free (needs confirmation) |
| OS1-7-1, OS1-7-2 | `Process.Kill` / priority / affinity; `SafeProcessHandle.Resume` | A non-owning handle alias, or a raw thread handle, is used without holding a reference, so the call can act on a recycled handle. | The owner is collected or disposed during the call |
| CLSYS2-9/16-1 | EventSource → EventListener decoding | Reads past the caller's `EventData` array and copies from that descriptor's pointer. | An EventSource whose `WriteEvent` call doesn't match the event's `byte[]` / Guid / decimal signature |
| CLSYS2-9-5 | Custom attribute prolog read (CoreCLR) | A 1-3 byte over-read of the attribute blob. | A malformed assembly |
| FMT-23/24-1 | `XxHash3` / `XxHash128.Append` | Overflows the 256-byte inline buffer. | Concurrent `Append` calls (misuse) |
| FMT-5/23-1 | LINQ `OfType<T>().Select(f).Last()` | A wrongly typed object is passed to the selector (`Unsafe.As` on the delegate). | A concurrent store into the source array (needs confirmation) |

#### Functional bugs and public issues

- **OS1-19-1** (`System.Console/src/System/ConsolePal.Unix.cs:519`): on an incomplete
  cursor-position reply, `TransferBytes(readBytes.Slice(readBytesPos), r)` pushes the unwritten
  tail of an unzeroed `stackalloc byte[256]` into stdin. The fix is `Slice(0, readBytesPos)`.
  - Effect: stale stack bytes are returned by `Console.Read` / `ReadKey` / `ReadLine`, and the
    bytes the user actually typed are lost.
  - Trigger: commonly a terminal without cursor-position-report support, reached through
    `Console.CursorLeft` / `CursorTop` / `GetCursorPosition`.
- **CLSYS1-3-1** (`Interlocked.cs:569-570`, `Volatile.cs:89-96` on 32-bit, and the CoreCLR /
  NativeAOT copies): `Interlocked.Read(ref readonly …)` is
  `CompareExchange(ref Unsafe.AsRef(in x), 0, 0)`. That writes to the location (it is not a JIT
  intrinsic) and faults on memory mapped read-only.
- **CLSYS1-12/21-1** (`FrameworkEventSource.cs:53-55`): a `bool` is published as a 4-byte
  payload. That leaks 3 stack bytes, and in-process listeners can decode `true` as `false`. This
  is the same class as NETB-12/21-4.
- **FMT-12/21-1:** binary XML `ReadArray(bool[])`, `ReadArray(decimal[])` and the little-endian
  `ReadDecimal` copy raw bytes with no normalization or validation.
- **FMT-XML-9-1:** a binary XML decimal with a scale of 39-255 throws `IndexOutOfRangeException`
  rather than `XmlException`.
- **FMT-XML-5-1:** binary XML on big-endian: characters are validated little-endian but returned
  in machine order, which bypasses `CheckCharacters`.
- **FMT-XML-16-1:** `XmlWriter.WriteChars(buf, buf.Length, 0)` throws `IndexOutOfRangeException`
  in the sync raw writers.
- **FMT-X509-19-1:** `SafePasswordHandle` zeroes only up to the first U+0000 of a password.
- **TENS-24-2:** `TensorMarshal.CreateTensorSpan(…, dataLength: -1, …)` silently skips the
  backing-length check, because -1 is an internal sentinel.
- **TENS-9-2:** latent. The in-place `SinCos` / `SinCosPi` vector tail would corrupt results once
  vectorized.
- Smaller items:
  - **OS2-16-3 / OS1-16-4:** the Windows OS encoding reports counts it never wrote, and
    `GetLeadByteRanges` tests the wrong array, so DBCS lead-byte tracking never runs.
  - The "is it S-1-5" SID test is misparenthesized.
  - **CLSYS2-22-6:** a stale `SetLastError` in the ANSI char-array marshaler.
  - **CLSYS2-13-8:** a NULL DACL causes a `NullReferenceException` in the named-object check.
  - TraceLogging writes 2-byte length prefixes from the high half on big-endian.
  - HTML writers' `WriteChars` skips HTML escaping.
  - `X509CertificateLoader.Unix.cs:444` has `Oids.Rsa or Oids.Rsa`.

#### Hardening gaps (the assumption holds for every caller)

| ID | Where | Rules | What |
|---|---|---|---|
| TENS-9-1 | `TensorShape.cs:494-622`, `TensorOperation.cs:312-367` | 4, 9, 24 | Broadcast compatibility is trusted via `Debug.Assert` only. |
| TENS-24-1 | `TensorPrimitives.IAggregationOperator.cs:2391-2601` | 5, 9, 24 | Mask-table vector loads have no row bound (zero slack). |
| TENS-11-1 | `TensorPrimitives.Single.netstandard.cs` | 5, 10, 11 | Aligned `Vector<float>` dereferences on float-aligned memory (netstandard asset). |
| TENS-5-1 | `TensorPrimitives.Helpers.cs:48-69` | 5, 9 | Span `BitCast` keeps `Length`; the size check is Debug-only. |
| CLSYS1-3/22-1 | `UnixHandleAsyncContext.Wasi.cs` | 3, 22 | Mirrors private wasi-libc structs and writes into libc memory. |
| CLSYS1-9-1 | NativeAOT `DynamicInvokeInfo.cs:315-765` | 9, 16 | Writes into a 4-slot byref buffer; the count is Debug-only. |
| CLSYS1-16-1 | `UnmanagedMemoryAccessor.cs:539-563` | 9, 16 | `WriteArray` doesn't check the accessor window (`ReadArray` does). |
| CLSYS1-2/7-1 | `EventProvider.cs:596-623` | 2, 7, 20 | Pointers escape `fixed`; pinned handles leak on a throw. |
| CLSYS1-1-1 | `ThreadBlockingInfo.cs:51-122` | 1 | `Unsafe.AsPointer(ref this)` is published to a thread static. |
| CLSYS2-10/11-9 | `EventPipeMetadataGenerator.cs:224-239` | 9, 10, 11 | Aligned typed stores at 2-aligned offsets. |
| CLSYS2-9/16-10 | `StubHelpers.cs:1328-1336` | 9, 16 | Blittable array marshaler `Memmove` has no bound against the managed array. |
| CLSYS2-22-7 | `NativeRuntimeEventSource.Threading.cs:489-504` | 16, 22 | Values passed as payload pointers (dead code today). |
| FMT-7-1 | CodePages `BaseCodePageEncoding.cs`, SBCS / DBCS / GB18030 | 7 | Cached table pointers without AddRef; `CheckMemorySection` is dead. |
| FMT-11-1 | `SBCSCodePageEncoding.cs`, `DBCSCodePageEncoding.cs` | 9, 10, 11, 16 | Aligned `ushort*` reads at odd addresses; unbounded table walk (trusted resource). |
| FMT-3-1, OS2-3-2 | `SequenceReader.cs`, `ImmutableInterlocked.cs`, `ActivityCreationOptions.cs`, `StringSequence` / `ObjectSequence` | 3, 15 | `readonly` fields mutated via `Unsafe.AsRef`; separate fields treated as an array. |
| FMT-9/18-1 | `RegexCompiler.cs:6514-6545` | 9, 18 | Emitted IL reads an array element unchecked, then `Unsafe.As`. |
| FMT-16-1 | `BlobUtilities.cs:64-133` | 9, 16 | `WriteUTF8` has no destination bound; two UTF-8 counters must agree. |
| FMT-XML-9-2 | XML / HTML raw text writers (templates) | 9, 16 | Escape bursts use a 32-element slack guarded only by comments. |
| FMT-XML-14-1 | `XPathConvert.cs` | 9, 14 | `stackalloc` into raw pointers with Debug-only bounds. |
| FMT-XML-20-1 | `XsdDuration.cs`, `XsdDateTime.cs` | 19, 20 | A `ValueStringBuilder` over the caller's destination is never disposed. |
| FMT-X509-7-1 | `AndroidCertificatePal.cs`; `DuplicateHandle` in `Interop.Rsa` / `EcKey` / `Dsa` | 7, 22 | Global references taken without keeping the source alive. |
| FMT-X509-22-2 | `StorePal.Android.*.cs` | 22 | An exception can escape an `UnmanagedCallersOnly` callback. |
| FMT-WASI-22-1 | Generated WASI HTTP bindings | 20, 22 | Pins and native buffers are released only on success. |
| OS1-7-3 | `SharedPerformanceCounter.cs` | 1, 7 | Raw view pointers without AddRef (narrow window after the category is deleted). |
| OS1-16/19-2 | SunOS `Interop.ProcFs.*.cs` | 16, 19, 22 | Native reports success when `/proc` can't be opened; an unbounded scan of uninitialized stack follows. |
| OS2-3-1 | `LdapSessionOptions.cs`, `Interop.Ldap.cs` | 3, 5 | Native code writes into the fields of a sequential class. |
| OS2-16-4 | FreeBSD `Interop.Process.GetProcInfo.cs` | 3, 16, 22 | `kinfo_proc` size check is Debug-only; allocator mismatch. |

### Waves 4-6 (2026-10-04): NativeAOT, JS interop and leftovers, CoreCLR tools, P/Invoke declarations

These waves used the same method on the remaining 1,025 files:

- 103 files in NativeAOT runtime libraries, JavaScript interop, Microsoft.CSharp and leftovers.
- 60 files in the CoreCLR build-time tools. Here the threat considered is malformed input images.
- 862 files whose unsafe use is only declarations: P/Invoke signatures, pointer-typed structs and
  fields. These were swept for rules 22, 12, 15 and 26, comparing against the native headers and
  sources.

#### Withheld (MSRC; functional descriptions only)

| ID | Component | What can happen | Condition |
|---|---|---|---|
| AOT-16-1 | NativeAOT `ByValTStr` ANSI struct-field marshalling | The UTF-16 length is capped at N-1, but the conversion writes the full encoded byte count plus a NUL into the N-byte inline field. Up to about 3(N-1)+1 bytes are written, overwriting the following fields or running past the native buffer. | Any non-ASCII string (Unix UTF-8; DBCS / UTF-8 ANSI code pages on Windows). No concurrency needed. CoreCLR's equivalent is bounded. |
| DECL1-22-2 | OpenLDAP SASL interactive bind (linux-arm32) | A `ulong` is used for C `unsigned long`, so the managed element is 8 bytes larger than native. Each element write spills into the next one and walks past the end of libsasl's array. | Any SASL bind with a non-empty challenge list on 32-bit Linux |
| DECL3-16/19-2 | `X509BasicConstraintsExtension` (legacy OID 2.5.29.10, Windows) | The CA flag is read from `pbData[0]` without checking `cbData > 0`, inside an unzeroed stack decode buffer. | A certificate with a zero-length subjectType bit string (needs confirmation) |
| MIX-1-1 | JS interop `ToJS(Span<T>)` | A raw pointer to unpinned span data is handed to JS. The generator never pins it, and JS can re-enter .NET and trigger a GC during the call. | Depends on runtime GC / conservative scanning behaviour (needs confirmation) |
| MIX-16-3 | `RegistryKey.GetValueNames()` on `HKEY_PERFORMANCE_DATA` | An unbounded NUL scan over a pooled buffer that was not cleared. | The OS leaves the name unterminated on the more-data path (needs confirmation) |
| DECL3-16-1 | `DeserializingResourceReader` (System.Resources.Extensions) | An `UnmanagedMemoryStream` over the resource blob uses a file-supplied length that is never checked against the remaining bytes. CoreLib's `ResourceReader` has this check. | A malformed .resources file read from a UMS (the reader is not meant for untrusted input) |

#### Functional bugs (public)

- **TOOL2-9-4** (`src/coreclr/tools/aot/ILCompiler.Compiler/Compiler/DependencyAnalysis/DehydratedDataNode.cs:276`):
  while it extends a run of relocations, NativeAOT reads the next relocation's addend at the
  *first* relocation's offset. Two adjacent relocations of the same type with different addends
  then get the wrong addend in the dehydrated data, which is a wrong pointer at runtime. Fix:
  `nextReloc.Offset`.
- **DECL1-22-1** (`Common/src/Interop/Interop.Ldap.cs:175-180` used by the OpenLDAP declarations):
  `LDAP_TIMEVAL {int, int}` is passed where libldap reads a 16-byte `struct timeval` on Linux
  x64/arm64 and macOS. Effects:
  - a sub-second `LdapConnection.Timeout` becomes enormous;
  - `-1` ("no limit") becomes 4,294,967,295 s;
  - the `{0,0}` poll gets 8 bytes of adjacent stack as `tv_usec`.
- **DECL1-22-2, all platforms:** the SASL default result length is in UTF-16 chars rather than
  UTF-8 bytes, so non-ASCII credentials are truncated, and native copies are leaked.
- **DECL2-22-1** (`MemoryMappedView.Windows.cs:59-91`): the result of `VirtualAlloc(MEM_COMMIT)`
  is discarded (the wrong handle is checked). A failed commit gives a view over reserved pages,
  and the first access crashes with an access violation instead of throwing.
- **TOOL1-9/16-1, TOOL2-22/16-1:** r2rdump / `ILCompiler.Reflection.ReadyToRun` read native
  memory past the image array for malformed Webcil section headers or R2R runtime-function
  sizes. These are developer tools.
- **DECL3-22-4:** `VirtualFree` has no `SetLastError`, but `MemoryFailPoint` reads the last
  error.
- **DECL3-12-3:** `VT_BYREF | VT_DECIMAL` is reinterpreted without clearing `wReserved` (an
  invalid decimal).
- **TOOL1-13-2** (latent): a write through `Unsafe.NullRef`.
- **TOOL2-22/12-1** (latent, no callers): `bool*` is passed for `BOOL*`, and the address of a
  managed object is passed as a COM pointer.

#### Hardening gaps (the assumption holds for every caller)

| ID | Where | Rules | What |
|---|---|---|---|
| AOT-1/3-2 | `CachedInterfaceDispatch.cs:26-32`, `RuntimeInstance.cpp:350-357` | 1, 3 | Native keeps a permanent pointer to a managed static (relies on the pinned object heap). |
| AOT-5/9-3 | `RuntimeExports.cs:245-291`, `RuntimeAugments.cs:143-159` | 5, 9, 16 | Unbox copies the source size; compatibility is Debug-only. |
| AOT-9/16-4 | `Array.NativeAot.cs:131-162` | 9, 14, 16 | The lengths count is trusted to equal the rank (Debug-only). |
| AOT-3/5-5 | TypeLoader `EETypeCreator.cs` and others | 3, 5 | `*(IntPtr*)&handle` instead of `.Value` / `FromIntPtr`. |
| MIX-3/5-2 | `JSHostImplementation.Types.cs:52-63` | 3, 5, 12 | An `IntPtr` overlaid on `RuntimeMethodHandle` (an object reference on CoreCLR; Mono-only caller). |
| MIX-6/3-4 | `JSMarshalerArgument.String.cs` | 3, 6 | Mono by-reference mode stores GC references as `IntPtr`. |
| MIX-5-5 | `BinaryFormatterWriter.cs:84-92` | 3, 5 | `Unsafe.As<DateTime, long>`. |
| MIX-1-6 | Microsoft.CSharp `ComRuntimeHelpers.cs`, `DynamicVariantExtensions.cs` | 1, 2 | `AsPointer` over expression-tree locals placed in DISPPARAMS. |
| TOOL2-7-1 | `UnmanagedPdbSymbolReader.cs` | 7 | COM wrappers make vcalls without `GC.KeepAlive` while finalizers `Release`. |
| TOOL2-16/22-2, TOOL2-9/16-3, TOOL2-9/16-5 | PDB reader buffers, dotnet-pgo LBR events, object-writer relocations | 9, 16, 22 | Unchecked buffer capacities / sizes. |
| TOOL1-14-3, TOOL1-5-4, TOOL1-21-5, TOOL1-2/5-6, TOOL1-15/3-7, TOOL1-2-8, TOOL1-1-9 | crossgen2 / ILCompiler / r2rdump | 1-21 | Negative `stackalloc` possible, class-to-struct `Unsafe.As`, raw `bool[]`, ref escaping `fixed`, field-spanning name buffer, leaked GCHandle, undocumented unmanaged-`this` contract. |
| DECL1-22-3, DECL1-16-5, DECL1-15-6, DECL1-16-7, DECL1-1-8 | Network.framework ALPN, GSS status, JIT instruction-set flags, Unix bignum, crypto alloc tracking | 1, 9, 15, 16, 22 | The native side ignores capacity, a NUL scan instead of the length, an unchecked fixed buffer, a delegate address as context. |
| DECL2-22-2 | `Interop.CertGetCertificateChain.cs:25-37` | 22 | A pointer field declared as `int` (88 vs 96 bytes on 64-bit). |
| DECL2-1/26-3, DECL3-1/26-8 | `Archiving.Utils.Windows.cs:53-86`, `PemEncoding.cs:735-757` | 1, 26 | Span addresses passed through `string.Create` state (same as B64URL-1/26-1). |
| DECL2-22-4 | `Interop.BCryptFinishHash.cs`, `HashProviderDispenser.Windows.cs:321` | 16, 22 | The length is independent of the span; one fallback path ignores NTSTATUS. |
| DECL2-7/22-5 | `LdapConnection.cs:880-929` | 7, 22 | The client certificate handle is returned to wldap32 without keeping it alive. |
| DECL2-22-6, DECL2-22-7 | `Interop.SSPI.cs:151-162`; CMSG union accessors | 22 | Mislabeled struct for the issuer list; Debug-only union discriminants. |
| DECL3-22-5 | `Interop.FILE_STANDARD_INFO.cs:12-19` | 22 | `BOOL` instead of `BOOLEAN` (32 vs 24 bytes). |
| DECL3-7/23-6 | `NetworkAddressChange.OSX.cs:191-246` | 7, 23 | Run-loop handle re-read without the lock (needs confirmation). |
| DECL3-16-7, DECL3-26-9 | `SafeChannelBindingHandle.cs:21-29`; `Marshal.Mono.cs` | 1, 6, 9, 16, 26 | Debug-only copy bound; suppressed ref-safety warning. |

### Coverage and totals

Every file in the repo that matches `unsafe`, `Unsafe.`, `MemoryMarshal.`, `stackalloc` or
`fixed (` has been reviewed: 2,235 files under `src/libraries/**/src`,
`src/coreclr/{System.Private.CoreLib,nativeaot,tools}` and `src/mono/System.Private.CoreLib`.

- 1,373 of them use those constructs for real work, and each was reviewed in full or at every
  unsafe site.
- The 862 that only declare were swept against the native side.
- No file remains unreviewed.

Native C/C++ code was out of scope except to verify callers.

| Wave | Files | Withheld (MSRC) | Public bugs | Hardening gaps |
|---|---|---|---|---|
| 1 | ~120 | 1 (+ B64URL-AVX2-1 from fuzzing) | 4 | 30 |
| 2 | 553 | 18 | 6 | ~30 |
| 3 | 497 | 18 | ~12 | ~27 |
| 4-6 | 1,025 | 6 | 9 | ~25 |

Nothing in this review was built or run. Each item's pattern was verified in the source, and its
reachability was traced through callers. Items marked "needs confirmation" depend on behaviour
(OS, native library, GC timing) that could not be established from source.

## Verification pass on the withheld items (2026-10-05)

Each of the 44 withheld items was independently re-reviewed by a second analyst whose task was to
**refute** it — find the Release-time guard the first pass missed, show no caller reaches the bad
state, or point to the OS/library behavior that prevents it. Still source analysis only; nothing was
built or run. The second analyst's refutations (not just the original claims) were spot-checked
against the source. Outcome: 5 refuted, 9 downgraded, 21 confirmed, 9 left resting on external
behavior.

### Refuted — false positives, removed

- **MIX-1-1** — Mono forces conservative stack marking (`sgen-mono.c:2704`), so the span's backing
  array is pinned for the synchronous JS call. The "missing" pin is supplied by the collector.
- **TEXT-24-1** — the over-read arithmetic is correct only for an odd `char*`; every caller passes
  2-byte-aligned char/string data, so the odd address is unreachable.
- **CLCORE-23/24-1** — the only way the `BitArray.CopyTo` bound moves past the destination is a
  concurrent `Length` setter, a data race on a type documented as not thread-safe; out of the
  threat model.
- **CRYPTOI-16-3** — the Android bignum export arithmetic is self-consistent (`offset =
  targetSize - compactSize >= 0`, native writes exactly `compactSize`), and the `FAIL==0` corner
  is unreachable because a bad handle fails both JNI calls and throws.
- **OS1-19-3** — the GUID is uninitialized only on the `sourceServer == null` path, and both such
  call sites pass `DS_REPSYNC_ALL_SOURCES`, under which `DsReplicaSyncW` ignores that argument.

### Downgraded — real pattern, not memory-unsafe in supported use

Each of these is safe single-threaded / on the supported path; the bad outcome needs concurrent
misuse of a non-thread-safe type, a crafted assembly, or a trusted-input violation, or the worst
case is only a wrong value / leak:

- **CLTEXT-16-2**, **FMT-23/24-1**, **FMT-5/23-1** — safe single-threaded; the OOB (read / write /
  type-confusion) needs a concurrent race on `StringBuilder` / `XxHash3` / a LINQ source array.
- **INTEROP-16-1** — capacity-bounded single-threaded; the 1-byte (CoreCLR) or multi-byte (AOT)
  overrun needs a `StringBuilder` grown concurrently mid-marshal.
- **CLSYS2-9/16-1** — out-of-bounds **read** only, and needs a buggy `EventSource` subclass feeding
  a self-inconsistent payload through the manual (explicitly unsafe) `WriteEventCore` contract plus
  an in-proc listener.
- **CLSYS2-9-5** — a 1-3 byte read of a crafted assembly's metadata (loading untrusted assemblies
  is already outside the threat model); lands in the mapped metadata heap and is then validated.
- **DECL3-16-1** — the OOB branch only fires for a memory-mapped embedded resource (a trusted
  artifact); ordinary streams and `MemoryMappedViewStream` take the bounds-checked path.
- **CRYPTOI-7-3** — the callback-vs-release race is real, but `GCHandle.FromIntPtr(..).Target` is a
  bounded handle-table lookup (null, or a type-rejected cast); the worst case is a logic error, not
  an OOB/UAF.
- **OS1-11-1** — the alignment is gated behind `IsMisaligned` and every offset is bounds-checked by
  `ResolveOffset`/`ResolveAddress`; the residual is cross-user DoS/integrity (offset-cycle loops,
  bogus counter values), not OOB/UAF.

### Confirmed — survive scrutiny

These could not be refuted on the managed side; the unsafe outcome and reachability both hold.
Grouped by how hard they are to reach.

**Reachable on an ordinary single-threaded path (report first):**
- **AOT-16-1** — NativeAOT `ByValTStr`-ANSI struct-field marshalling of a non-ASCII string writes
  up to `(N-1)*maxBytesPerChar + 1` bytes into an N-byte inline field (out-of-bounds **write**).
  Ordinary `Marshal.StructureToPtr` / P/Invoke struct marshalling, no race. CoreCLR's marshaller
  passes the capacity and is bounded; the AOT path omits it.
- **NETB-22-1** — reusing one `SocketAsyncEventArgs` from an IPv4 to an IPv6 `ReceiveMessageFrom`
  reports the 28-byte address size over a 16-byte un-realloc'd native block → WSARecvMsg OOB
  **write** (~12 bytes) plus copy-back OOB read. Windows.
- **CLSYS1-22/16-1** — the Unix vectored `RandomAccess.Read` passes `buffers.Count` to the syscall
  (re-read) rather than the cached count used to fill the iovec array; a custom `IReadOnlyList`
  with an unstable `Count` (single-threaded, legal) makes the kernel **write** file data through
  uninitialized iovec pointers.
- **CRYPTO-7-1** — reading `X509Chain.ChainStatus` (lazy) after disposing `chain.SafeHandle` reads
  the freed native chain context (UAF read). Single-threaded, Windows.
- **FMT-9/16-1** — the `i > limit` guard should be `i >= limit`; a malformed WinMD image gives a
  1-byte read past the #Strings heap.
- **CLTEXT-16-1**, **CLTEXT-22-1** — a locale display string of exactly 100 units over-reads a
  stack buffer (ICU gives no terminator); an 81-85 char culture name overruns the 80-char WASM
  buffer. (CLTEXT-16-1 rests partly on ICU's documented not-terminated behavior; the in-repo native
  code provides no termination.)

**Reachable only under a concurrency race / unordered finalization (not thread-safe types):**
- **CLSYS1-23-1** (OVERLAPPED free-list ABA — but this is concurrent-by-design runtime code, so the
  race is in scope), **OS2-22-1** (pipe overlapped freed on an unexpected error while the sibling
  read is pending), **OS2-7-1** / **OS2-7-2** (raw pointer / SID into a block freed by a parent's
  Dispose or finalizer), **OS1-7-1** / **OS1-7-2** (non-owning process/thread handle used without
  AddRef; note OS1-7-1's filed repro was wrong — the alias path needs `_haveProcessHandle`),
  **NETA-7-3** (GCHandle double-free if the parent closes between StreamOpen and the ctor's
  AddRef), **NETB-7/22-2** (channel-binding read without AddRef), **NETB-7-5** (reloaded
  certificate unrooted before the native call), **CRYPTOI-7-1** (TLS socket fd used after
  close/finalize-order; experimental Unix API).

**Reachable only with an untrusted/third-party source or a specific RID:**
- **OS2-16-1** (malformed `objectSid` from an untrusted LDAP/SAM server; many sibling sites already
  guard with `IsValidSid`, so it is a validation inconsistency), **CRYPTOI-9-1** (third-party NCrypt
  KSP returning an inconsistent ML-KEM blob), **DECL1-22-2** (linux-arm32 only: `ulong` for C
  `unsigned long`), **CLSYS2-1/8-3** (safe-code footgun: copy a `FileSystemEntry` and return
  `FileName` → dangling read-only span; documented in-comment).

### Unresolved — managed read is real, safety hinges on external behavior (to MSRC with that caveat)

- **MIX-16-3** (RegEnumValueW NUL-terminating a perf-data value name on ERROR_MORE_DATA),
  **DECL3-16/19-2** (CryptDecodeObjectEx X509_BASIC_CONSTRAINTS `pbData`/`cbData` shape),
  **CLSYS2-16/19-4** (LookupAccountNameW scanning an unterminated LPCWSTR), **OS2-2-1** (serial
  driver completing a canceled WaitCommEvent after the pin ends), **OS2-16-2** (version.dll
  returning an unterminated / undersized version-resource value), **NETA-9/16-1** (http.sys ever
  returning ≥2 inline entity chunks — ~20 years with no known CVE suggests not, but unprovable from
  the repo), **NETA-7/22-4** (WinHTTP delivering HANDLE_CLOSING asynchronously after dispose; the
  double-free sub-claim was refuted), **CRYPTO-16-2** (an NCrypt/BCrypt provider returning a
  non-terminated property value), **NETB-20/22-7** (nw_framer_deliver_input retaining the input
  pointer async).

### Where this leaves the list

| Verdict | Count | Action |
|---|---|---|
| Refuted (false positive) | 5 | dropped |
| Downgraded (not memory-unsafe as shipped) | 9 | keep as hardening notes, not MSRC |
| Confirmed, ordinary single-threaded path | 7 | MSRC first — AOT-16-1, NETB-22-1, CLSYS1-22/16-1, CRYPTO-7-1, FMT-9/16-1, CLTEXT-16-1, CLTEXT-22-1 |
| Confirmed, race / finalization only | 10 | MSRC, flagged as concurrency-gated |
| Confirmed, untrusted-source / specific-RID / footgun | 4 | MSRC / issue, flagged |
| Unresolved-native | 9 | MSRC with the exact external question to settle |

Still not reproduced: confirmation here is independent source review plus caller/native tracing, not
execution. B64URL-AVX2-1 (from the fuzzer) remains the only item backed by actual crashes.

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
- `Utf8Formatter` throws `NotSupportedException` for `'G'` with a precision (by design).
- `Uri` created with `DangerousDisablePathAndQueryCanonicalization` throws from `GetComponents()`
  for path/query (documented).
- `PEReader.GetSectionData` with a negative RVA throws `ArgumentOutOfRangeException` (documented).
- `AsnWriter.WriteEncodedValue` validates the value against the writer's own rule set, so BER
  values can only be passed through a BER writer.
- Round 3: `DataTable` expressions let `DivideByZeroException`, `FormatException` (literal
  conversions) and `IndexOutOfRangeException("Cannot find column ...")` through, as they always have;
  under ODBC rules `DbConnectionStringBuilder` keeps the braces of a quoted value and always braces
  the `Driver` value; `ContentDisposition` parameter order isn't stable (a `StringDictionary`);
  `HttpUtility.UrlPathEncode` only encodes the path of anything that looks like a URL (scheme,
  `//`, UNC, `?`, `#`); `SortedSet` views throw for out-of-range elements in `UnionWith` /
  `SymmetricExceptWith` too; `Select(...).Last()` in LINQ skips the selector for earlier elements
  where `LastAsync` runs it; `CborWriter` writes floats in the shortest exact width and simple values
  20–22 as `false` / `true` / `null`; a reader without `allowMultipleRootLevelValues` stops after the
  first value; single-reader unbounded channels don't support `Count`; Hijri year 9666 only has four
  months; week 55 exists in 13-month lunisolar years. Harness bugs fixed along the way: comparing
  truncated text (the binary XML copy splits long bytes records into differently sized base64
  chunks, which only compare equal in full), replaying CBOR past the 10,000-token read limit, and
  dropping ODBC `{}` values (a value of its own) as empty.

## Limitations

- `datetime`, `encoding` and `enum` findings from the Sep 26 runs were triaged by the parallel
  session (branch `feature/sharpfuzz-corelib-instrument-fc6ce9`), not here.
- Coverage feedback only comes from managed code, so the JIT's lowering of vector intrinsics is
  exercised only through the differential checks and the ISA-varied secondaries.
- Campaigns were short (30–60 minutes per target) and shared 12 hardware threads.
- Guard pages (`SHARPFUZZ_GUARD=1`, see `Guarded.cs`) catch reads and writes just past the ends of
  spans the harness allocates, not overruns inside the framework's own arrays or buffers.


---

## Consolidated triage — all confirmed findings, with model verdict (appended 2026-10-08, unsorted)

_The full per-wave finding tables (every hardening gap, public bug and informational item) are in the wave sections above. This appendix is the consolidated triage of the confirmed memory-safety findings with their adversarial-refutation verdicts and their classification against the .NET vulnerability model, pulled in verbatim from TRIAGE-MSRC.md for manual sorting._

# Worst offenders — MSRC triage sheet

Confirmed memory-safety findings from the unsafe-code review (verification pass 2026-10-05).
Only items that **survived** adversarial re-review are here. The 5 refuted false positives and 9
downgraded (not-memory-unsafe-as-shipped) items are NOT in this list — see the "Verification pass"
section of FINDINGS-CORELIB.md for those.

Confirmation level: independent source + caller + native tracing, adversarially re-reviewed.
**Not executed.** Nothing here was run or reproduced (except B64URL-AVX2-1, which is crash-backed by
the fuzzer). The `MSRC?` column is for your decision.

Severity is my rough guess (CVSS-ish): H = out-of-bounds write / UAF on a normal path; M = OOB write/UAF
that needs a race, a nonstandard caller, or an untrusted local source; L = OOB read, small / bounded /
needs malformed trusted-only input.

---

## Tier 1 — confirmed memory-unsafe, reachable on an ordinary single-threaded path

| ID | Class | Sev | Platform | File:line | Precondition / reachability | Suggested fix | MSRC? |
|----|-------|-----|----------|-----------|------------------------------|---------------|-------|
| AOT-16-1 | OOB **write** | H | NativeAOT (all OS) | `coreclr/nativeaot/System.Private.CoreLib/src/Internal/Runtime/CompilerHelpers/InteropHelpers.cs:37-55` → `System/Runtime/InteropServices/PInvokeMarshal.cs:489-525` | Marshal a struct with `[MarshalAs(ByValTStr, SizeConst=N)]` ANSI field holding a **non-ASCII** string (`Marshal.StructureToPtr` or ordinary P/Invoke). Writes up to `(N-1)*maxBytesPerChar + 1` bytes into the N-byte inline field. No race. CoreCLR's `CSTRMarshaler` passes the capacity and is bounded; AOT omits it. | pass N as the destination capacity to the conversion; truncate + terminate in-buffer | [ ] |
| NETB-22-1 | OOB **write** (native heap) + OOB read | H | Windows | `System.Net.Sockets/.../SocketAsyncEventArgs.Windows.cs:981-992, 549-550, 1253-1259` | Reuse one `SocketAsyncEventArgs` from an IPv4 `ReceiveMessageFrom(Async)` to an IPv6 one. The sockaddr block is allocated once (no realloc) but the length/capacity are always set to the current family's max → WSARecvMsg writes ~12 bytes past a 16-byte block; copy-back reads OOB. | reallocate when the needed size grows, or always allocate the max and recheck per op | [ ] |
| CLSYS1-22/16-1 | OOB **write** (kernel → uninit pointers) | H | Unix | `System.Private.CoreLib/.../IO/RandomAccess.Unix.cs:58-99` (async: `SafeFileHandle.ThreadPoolValueTaskSource.cs:106`) | `RandomAccess.Read/ReadAsync(SafeFileHandle, IReadOnlyList<Memory<byte>>, long)` with a custom `IReadOnlyList` whose `Count` returns a larger value on the syscall's re-read (lines 79/89) than during the iovec fill. **No race needed.** Kernel writes file bytes through uninitialized `IOVector.Base`. | cache `Count` once; size, fill, and pass the syscall count from that single value (the write path already does) | [ ] |
| CRYPTO-7-1 | use-after-free **read** | M–H | Windows | `System.Security.Cryptography/.../X509Certificates/ChainPal.Windows.cs:63-103`; `X509Chain.cs:52-58, 77-85` | `X509Chain.Build`, then dispose `chain.SafeHandle` (same handle is public), then read `chain.ChainStatus` (lazy, not materialized during Build) → dereferences the freed `CERT_CHAIN_CONTEXT`. Single-threaded. | wrap both getters in `DangerousAddRef`/`Release` like `CertificatePal.InvokeWithCertContext` | [ ] |
| CLTEXT-22-1 | OOB **write** + read | M | Browser/WASM | `System.Private.CoreLib/.../Globalization/CultureData.Browser.cs:42-60`; `src/mono/browser/runtime/globalization-locale.ts:32-37, 64-69` | A culture/locale name ~81-85 chars that `Intl.getCanonicalLocales` rejects: the JS "forward malformed name" paths write past the 80-char dst in wasm linear memory and return `resultLength > 80`; managed `new string(buffer, 0, resultLength)` then over-reads the stack buffer. | bound the JS forward paths by `dstMaxLength`; check `resultLength <= 80` in managed | [ ] |
| FMT-9/16-1 | OOB **read** (1 byte) | L–M | all | `System.Reflection.Metadata/.../Utilities/MemoryBlock.cs:473-505` | Reading a **malformed WinMD** image whose #Strings offset == heap length, or whose last string is unterminated. Guard `i > limit` should be `i >= limit`; reads `*p` at `Pointer + Length`. Reachable via `StringHeap.EqualsRaw`/`BinarySearchRaw` ← `MetadataReader.WinMD.cs`. Faults only if the heap ends on a page boundary of a native buffer. | change guard to `i >= limit`; check `offset + asciiString.Length < Length` before the final read | [ ] |
| CLTEXT-16-1 | OOB **read** (stack) | L–M | all (ICU) | `System.Private.CoreLib/.../Globalization/CultureData.Icu.cs:241-249` (native `pal_localeStringData.c:214-402`) | A locale whose display/language/country string is **exactly 100 UTF-16 units**: ICU sets `U_STRING_NOT_TERMINATED_WARNING` (still `U_SUCCESS`) and writes no NUL into the `stackalloc char[100]`; `new string(buffer)` over-reads the stack. Partly rests on ICU's documented truncation behavior; the in-repo native side gives no terminator. | use the bounded span + `IndexOf('\0')` pattern already at lines 320-331 | [ ] |
| B64URL-AVX2-1 | OOB access (crash-backed) | ? | x64 AVX2 | `System.Private.CoreLib/.../Buffers/Text/Base64Helper/Base64DecoderHelper.cs` (Avx2Decode, Base64Url UTF-8) | **The only crash-backed item.** 156 guard-page AVs under the fuzzer in `Base64Url.DecodeFromUtf8`'s AVX2 path with short destinations. Open step: replay the saved inputs (`/root/sharpfuzz/out-b64g/base64guard/*/crashes`) on stock RC1 — that replay belongs with MSRC. | (pending root-cause; hand crash inputs to MSRC) | [ ] |

## Tier 2 — confirmed, but only under a concurrency race or unordered finalization

These need a not-thread-safe object used concurrently, or a Dispose/GC in a specific window. Vendors
often treat these as lower priority or "documented misuse," but each is a real missing guard. (CLSYS1-23-1
is the exception — it is concurrent-by-design runtime code, so its ABA race is in scope.)

| ID | Class | Platform | File:line | Trigger window | MSRC? |
|----|-------|----------|-----------|----------------|-------|
| CLSYS1-23-1 | double-handout → aliased OVERLAPPED | Windows | `Threading/Win32ThreadPoolNativeOverlapped.cs:48-62, 161-173` | ABA on the lock-free free list under concurrent alloc/free (Windows thread pool). No tag/hazard pointer. | [ ] |
| NETA-7-3 | GCHandle double-free | all (QUIC) | `System.Net.Quic/.../Internal/MsQuicSafeHandle.cs:112-134`; `QuicStream.cs:196-257` | connection SafeHandle closed between StreamOpen and the ctor's `DangerousAddRef`; ctor catch + finalizer both `Free` the same GCHandle copy. | [ ] |
| OS2-22-1 | write-after-free | Windows | `System.Diagnostics.Process/.../Process.Multiplexing.Windows.cs:213-339` | `Process.ReadAllText/ReadAllBytes`: a non-EOF pipe error or buffer-growth OOM while the sibling pipe's overlapped read is pending → buffers freed/returned, kernel completes into them. | [ ] |
| OS2-7-1 | use-after-free r/w | Windows | `System.Diagnostics.PerformanceCounter/.../CounterSetInstanceCounterDataSet.cs:15-188` | a `CounterData` used after its owning dataset is Disposed/finalized (it holds a raw `long*`, no owner ref). | [ ] |
| OS2-7-2 | use-after-free read | Windows | `System.DirectoryServices.AccountManagement/.../AuthZSet.cs:153-470` | enumerate `GetAuthorizationGroups()` results after disposing the `PrincipalSearchResult` (SID pointers into a freed block; no parent disposed-check). | [ ] |
| OS1-7-1 | handle-recycle (wrong kernel object) | Windows | `System.Diagnostics.Process/.../Process.Windows.cs:468-491` | concurrent `Process.Dispose`/GC during `Kill`/priority/affinity via the non-owning handle alias (only when `_haveProcessHandle`; the originally-filed `GetProcessById().Kill()` repro was wrong). | [ ] |
| OS1-7-2 | handle-recycle | Windows | `System.Diagnostics.Process/.../SafeProcessHandle.Windows.cs:53-62, 777-788` | concurrent Dispose/GC during `Resume()` (raw `_mainThreadHandle`, no AddRef, TOCTOU). | [ ] |
| NETB-7/22-2 | UAF read / OOB read | Android, tvOS | `System.Net.Security/.../NegotiateAuthenticationPal.ManagedNtlm.cs:483-508` | caller-supplied `ChannelBinding` read without AddRef (dispose race) or a subclass whose `Size` overstates its buffer. Read-only. | [ ] |
| NETB-7-5 | dangling native handle | macOS | `System.Net.Security/.../Pal.OSX/SafeDeleteSslContext.cs:368-399` | an intermediate cert with a private key: the reloaded copy is unrooted before the native `SslSetCertificate`; GC in the window → dangling `SecCertificateRef`. | [ ] |
| CRYPTOI-7-1 | use-after-close (fd recycle) | Unix (OpenSSL) | `Common/.../Interop.Ssl.cs:124-125, 181-186, 659-702` | dispose/finalize the socket handle out of order with the SSL handle (experimental `LowLevelTlsDiagId` API); SslShutdown writes to a closed/recycled fd. | [ ] |

## Tier 3 — confirmed, but gated on an untrusted source, a specific RID, or safe-code misuse

| ID | Class | Gate | File:line | MSRC? |
|----|-------|------|-----------|-------|
| OS2-16-1 | OOB read + wild read | **untrusted** LDAP/SAM server returning a malformed short `objectSid` | `System.DirectoryServices.AccountManagement/.../Utils.cs:183-266, 827-860` (dup in `System.DirectoryServices/.../ActiveDirectory/Utils.cs`) | [ ] |
| CRYPTOI-9-1 | OOB read | **third-party** NCrypt KSP returning an inconsistent ML-KEM blob | `Common/.../MLKem.Windows.cs:14-50` | [ ] |
| DECL1-22-2 | OOB r/w of libsasl array | **linux-arm32** only (`ulong` for C `unsigned long`) | `Common/src/Interop/Linux/OpenLdap/Interop.Ldap.cs:31-40`; `LdapPal.Linux.cs:190-233` | [ ] |
| CLSYS2-1/8-3 | dangling span (read) | safe-code footgun: copy a `FileSystemEntry`, return its `FileName` | `System.Private.CoreLib/.../IO/Enumeration/FileSystemEntry.Unix.cs:24-30, 96-109` | [ ] |

## Unresolved-native — managed read is real; safety hinges on an external guarantee

Route to MSRC as questions, each with the exact behavior that must be checked. Not re-listed here;
see the "Verification pass" section of FINDINGS-CORELIB.md: MIX-16-3, DECL3-16/19-2, CLSYS2-16/19-4,
OS2-2-1, OS2-16-2, NETA-9/16-1, NETA-7/22-4, CRYPTO-16-2, NETB-20/22-7.

---

Triage guidance (my read): Tier 1 is where the MSRC case is strongest — AOT-16-1 (OOB write, no race,
GA next month) is the clearest. B64URL-AVX2-1 is the only one with actual crashes. Tier 2 is genuine
but concurrency-gated; vendors vary on whether racing a non-thread-safe type counts. Tier 3 and the
unresolved-native set are worth reporting but are either trust-gated or need a vendor to confirm the
platform behavior. None of these has a reproducer — MSRC validates those in a controlled setting.

---

# Assessed against the .NET vulnerability model (2026-10-05)

Checked against dotnet/core `security-foundations/vulnerability-theory.md` and
`baseline-security-assumptions.md`. The model's deciding tests:
- **Taint:** a memory-safety defect is a *vulnerability* when **tainted data** (provenance beyond the
  authority boundary — network, untrusted files, certificates, serialized/parsed untrusted input)
  drives it, or when an actor **across an authority boundary** (another local user, a remote peer)
  gains unintended privilege/DoS.
- **Out of scope:** "Vulnerability reports that are predicated on an invariant being violated are
  closed as won't fix or by design." That covers data races on non-thread-safe types,
  use-after-dispose, and caller-supplied implementations that break a contract. In-process
  composition is not a security boundary, and **loaded assemblies/metadata are fully trusted**
  (malformed-assembly reports are out of scope — loading already implies code execution).

This re-sorts the confirmed list. Severity letters from the tiers above are unchanged; what changes
is **whether the model treats it as a vulnerability at all.**

## A1 — Take to MSRC (strongest, each still caveated)

Applying the model strictly, only these two clear the bar as plausible vulnerabilities worth the
vendor's time — and each carries one caveat that could still disqualify it.

| ID | Why it clears the bar | The caveat that could still kill it | MSRC? |
|----|-----------------------|-------------------------------------|-------|
| B64URL-AVX2-1 | genuinely-untrusted input (base64 tokens/URLs/network) → OOB **write** of attacker-controlled decoded bytes; crash-backed, so reachability is proven under *some* buffer sizing | real one-shot callers size the destination with `GetMaxDecodedLength` (slack), so the overshoot may be unreachable outside the fuzzer's exact-sized guard-paged buffers. Confirm a *realistic* caller sizes tight before filing. | [ ] |
| DECL3-16/19-2 | a certificate is genuinely untrusted data (the reason cert validation exists); malformed legacy basic-constraints → OOB **read** (infoleak) reachable from any cert's `Extensions` | it is a read, not a write (confidentiality, not RCE), and it depends on CryptoAPI actually yielding a zero-length `SubjectType.pbData` for a decodable cert. If CryptoAPI never does, it's unreachable. | [ ] |

## A2 — Demoted: a boundary exists only under a narrow / unusual condition

Previously in bucket A / A?. Each *could* be a vulnerability, but only if an uncommon precondition
holds; by default the model treats them as out of scope. **Don't file unless the precondition is
confirmed for a real deployment.**

| ID | Would-be driver | Why it's demoted (the precondition that's usually false) | MSRC? |
|----|-----------------|----------------------------------------------------------|-------|
| AOT-16-1 | tainted string → `ByValTStr` ANSI struct → native | OOB write is real, but needs a specific, niche pattern: a network/file-tainted string marshalled through that exact struct shape on NativeAOT. If the marshalled strings are app-controlled it's in-process → out. | [ ] |
| OS2-16-1 | `objectSid` from a directory | in almost all deployments the directory (your DC) is **trusted infrastructure**; a "malicious directory" isn't a realistic actor (if the DC is compromised, it's over anyway). Only genuinely untrusted/third-party LDAP makes it relevant. | [ ] |
| NETA-9/16-1 | HTTP request body (remote) | ~20 years with no CVE strongly suggests http.sys never returns ≥2 inline entity chunks, i.e. the OOB write is never reached. | [ ] |
| CLTEXT-22-1 | tainted culture/locale name | OOB write, but confined to the **WASM sandbox** (can't reach host RCE), and in many Blazor apps the culture comes from the user's own browser → no cross-boundary attacker. | [ ] |
| CLTEXT-16-1 | tainted locale name | needs the attacker to pick a valid locale whose ICU display string is *exactly* 100 UTF-16 units; a read (infoleak) if hit. | [ ] |
| OS2-16-2 | untrusted PE/version resource | needs an app that runs `FileVersionInfo.GetVersionInfo` on attacker-supplied files **and** version.dll to return an unterminated/undersized value; a read. | [ ] |
| NETB-20/22-7 | TLS wire data (remote) | UAF only if `nw_framer_deliver_input` retains the input pointer across its async completion (macOS Network.framework behavior). | [ ] |

## B — In scope: cross-user DoS / integrity (boundary crossing, not memory-corruption)

| ID | Why | MSRC? |
|----|-----|-------|
| OS1-11-1 | the product's own ACL makes the shared perf-counter mapping writable by **Authenticated Users**; a lower-privileged local user can corrupt counter values or plant offset-cycles that hang/stack-overflow another user's process — a cross-authority integrity/availability grant. (Not OOB — alignment and offsets are guarded — but *is* a boundary-crossing DoS/integrity issue, which the model counts.) | [ ] |

## C — Out of scope by the model: invariant / contract violation by a trusted in-process component

Real missing guards (worth a hardening PR), but the model closes these "by design" — they need a
data race on a not-thread-safe type, use-after-dispose, or a caller-supplied implementation that
breaks a contract, all in-process / fully trusted.

- **Dispose / lifetime misuse:** CRYPTO-7-1 (use after disposing the chain handle), OS2-7-1, OS2-7-2,
  OS1-7-1, OS1-7-2, NETB-7-5, CRYPTOI-7-1.
- **Concurrent misuse of a non-thread-safe type:** OS2-22-1, NETA-7-3, NETB-7/22-2.
- **Caller-supplied implementation breaking a contract:** CLSYS1-22/16-1 (unstable `IReadOnlyList.Count`).
- **In-process API footgun:** CLSYS2-1/8-3 (copy a `FileSystemEntry`, return its `FileName`).
- **Exception — stays a candidate:** CLSYS1-23-1. The thread-pool OVERLAPPED free list is
  **concurrent-by-design**, so its ABA race is a genuine defect, not misuse. Keep in play.

## D — Out of scope: malformed *loaded* / trusted artifact

- **FMT-9/16-1** and **CLSYS2-9-5** — malformed WinMD / assembly metadata. Loading an assembly is
  full trust. *Caveat:* `System.Reflection.Metadata` can also read a file purely as **data** (no
  code load); if a tool parses an **untrusted** .winmd as data, FMT-9/16-1 moves to bucket A. Decide
  per consumer.
- **CRYPTOI-9-1** — a third-party NCrypt KSP is an in-process loaded provider (trusted).
- **CRYPTO-16-2** — CNG property values from a provider (trusted); the `SetProperty` round-trip is
  in-process.
- **MIX-16-3** — registering perf-counter names is admin-gated (fully trusted).
- **CLSYS2-16/19-4** — the username comes from the OS token (trusted, not tainted).

## N — Reliability / correctness defects, memory-safety but no boundary-crossing driver

- **NETB-22-1** — the WSARecvMsg OOB write is driven by the app's own SAEA-reuse + family-size
  bookkeeping, not by any attacker-controlled data; a remote peer cannot choose to trigger it. Serious
  integrity defect, but no tainted driver → likely **reliability**, not a vuln, under the model.
  (Still worth fixing — SAEA reuse is a supported, encouraged pattern, so this is not caller misuse.)
- **DECL1-22-2** — the arm32 SASL struct-size mismatch is a layout bug that manifests on the platform
  regardless of attacker data; correctness bug, linux-arm32 only.
- **OS2-2-1** — serial driver / pin-lifetime timing; reliability.

## Bottom line for triage

Applied strictly, the model disqualifies the large majority of the confirmed findings, and the honest
security yield is small:

- **Take to MSRC (A1): two**, each with a caveat that must clear first — **B64URL-AVX2-1** (OOB write,
  untrusted input, crash-backed; confirm a realistic caller sizes the destination tight) and
  **DECL3-16/19-2** (cert OOB read; confirm CryptoAPI yields the zero-length field). B64URL is the
  only one that is both a write primitive and reachable from genuinely untrusted data, so it is the
  single most defensible item and the one with RCE potential.
- **One lower-severity model-clean item (B): OS1-11-1**, a cross-user DoS/integrity issue (not memory
  corruption).
- **Demoted (A2): seven** that need an uncommon precondition to be a real boundary — file only if that
  precondition is confirmed for a real deployment; otherwise they are out of scope.
- **Out of scope (C/D/N): everything else** — invariant violations (races, dispose, broken caller
  contracts), trusted in-process components/providers, malformed loaded assemblies/metadata, and
  reliability bugs with no boundary-crossing driver. These are legitimate **hardening PRs**, but by
  .NET's own definition they are **not** security vulnerabilities and would come back "by design /
  won't fix (security)" if sent to MSRC.

Blunt version: of ~21 confirmed memory-safety findings, realistically **one or two** are worth MSRC
(and even those carry a live caveat). The durable value of the campaign is the hardening PRs, not the
vulnerability reports — which is the normal result of holding "unsafe-code smells" to a rigorous
vulnerability definition.
