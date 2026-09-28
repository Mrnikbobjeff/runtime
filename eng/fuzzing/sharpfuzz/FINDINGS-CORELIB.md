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
area on at most 12 threads.

### Round 4 campaign statistics

| Target | Assemblies | Wall-clock | Execs | Edges | Result |
|---|---|---|---|---|---|
ROUND4_STATS

### Round 4 summary

| ID | Component | Kind | Severity (my assessment) | Versions |
|----|-----------|------|--------------------------|----------|
| [SR-BOM-1](#sr-bom-1) | `StreamReader` (BOM detection, the default) | When the first read returns 1–2 bytes, BOM detection runs again on later buffers: BOM-like bytes mid-stream are dropped or switch the decoding to UTF-16 / UTF-32; a BOM split across reads is missed | **Medium** | .NET 8, 9, 10, 11 |
| [COMP-EXACT-1](#comp-exact-1) | `DeflateEncoder.TryCompress` (new in 11) | Fails for a destination of exactly the compressed size; one byte more works | Low–Medium | new .NET 11 API |
| [MARSHAL-TSTR-1](#marshal-tstr-1) | `Marshal.StructureToPtr` (ANSI `ByValTStr`, ANSI by-value `char[]`) | A non-ASCII string is cut inside a UTF-8 sequence, or throws when its UTF-8 is longer than `SizeConst`; any non-ASCII char in a by-value `char[]` throws; ASCII strings are truncated | Low–Medium | .NET 8, 9, 10, 11 (exception type changed in 11) |
| [BR-CHARS-1](#br-chars-1) | `BinaryReader.ReadChars` | Throws `ArgumentException` ("output char buffer is too small") for invalid UTF-8, or a character outside the BMP, at the end of the requested count | Low–Medium | .NET 8, 9, 10, 11 |
| [JSON-DEEPEQ-1](#json-deepeq-1) | `JsonElement.DeepEquals`, `JsonNode.DeepEquals` | Throw `ArgumentOutOfRangeException` for any number whose exponent doesn't fit in an `int`, even when comparing a document with itself | Low–Medium | .NET 9, 10, 11 |
| [ZIP-ENC-1](#zip-enc-1) | `ZipArchiveEntry.Open` / `OpenAsync` (encryption support new in 11) | For an encrypted entry with an unknown encryption method, `Open` throws `InvalidDataException` and `OpenAsync` `NotSupportedException`; the two also check header, method and password in different orders | Low | new .NET 11 API |
| [COMP-EMPTY-1](#comp-empty-1) | `DeflateDecoder` / `ZLibDecoder` / `GZipDecoder.TryDecompress` (new in 11) | Decompressing an empty payload into an empty destination returns `false` | Low | new .NET 11 API |
| [ROUND4-MISC](#round4-misc) | various | See the list at the end of this section | Informational | |

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
- `BinaryReader.ReadChars` never flushes its decoder: an incomplete UTF-8 / UTF-16 sequence at the end
  of the stream is dropped, where `Encoding.GetString` and `StreamReader` produce U+FFFD.
- `JsonNode.ToJsonString` of a node parsed from a string with an escaped lone surrogate throws
  `InvalidOperationException`, the same as JSON-SURR-1 (round 3) through the node API.

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
