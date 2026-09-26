# CA1881: Prefer `MemoryExtensions.Split` over `string.Split` with a count

This is the analyzer proposed in [dotnet/runtime#85487](https://github.com/dotnet/runtime/issues/85487). It flags `string.Split` calls that pass a count and suggests the span-based `MemoryExtensions.Split`/`SplitAny` overloads added in .NET 8.

CA rules no longer live in dotnet/runtime. They moved from dotnet/roslyn-analyzers to [dotnet/sdk](https://github.com/dotnet/sdk/tree/main/src/Microsoft.CodeAnalysis.NetAnalyzers), so this change is written against that tree and kept here in two forms:

- `src/Microsoft.CodeAnalysis.NetAnalyzers/...` holds the new analyzer and test files, at the same paths they have in dotnet/sdk.
- `upstream/0001-Add-CA1881.patch` is the full change, including the edits to existing upstream files (resx, xlf, release tracking, ID ranges, generated docs). It applies with `git am` on top of dotnet/sdk `3b1d59f` (2026-09-25).

Nothing in this repo's own build picks these files up.

## What the API review approved

The issue was approved in the [2023-06-01 API review](https://github.com/dotnet/apireviews/blob/main/2023/06-01-quick-reviews/README.md) ([video, from 17:22](https://www.youtube.com/watch?v=cAbUh4CD0Qg&t=0h17m22s)). The notes say:

> Out of a concern of false positives, it seems like the initial version of this analyzer should be limited to those callsites where a count was passed into `string.Split`, as that pattern has a perfect analogue in the span-based split.
>
> Using uncounted string.Split in a foreach would be better handled by an iterator-based split (which we don't have yet). Other uses of uncounted split might be analyzable, but they're harder to describe, so they should probably be a different diagnostic ID (once the pattern can be analyzed) just to keep the docs/explanation sane.
>
> The suggestion regarding Trim/TrimEnd/TrimStart may have merit, but seems like it might need some more thought (as it depends heavily on what happens after the call to Trim)... and should be addressed in a separate issue, with more details/examples.
>
> Category: Performance
> Severity: Info

The video transcript isn't here yet because YouTube was blocked in the environment this was built in. See [api-review-transcript.md](api-review-transcript.md).

## What the rule does

| Reported call | Suggested replacement |
|---|---|
| `s.Split(char, int[, StringSplitOptions])` | `s.AsSpan().Split(Span<Range>, char, StringSplitOptions)` |
| `s.Split(string, int[, StringSplitOptions])` | `s.AsSpan().Split(Span<Range>, ReadOnlySpan<char>, StringSplitOptions)` |
| `s.Split(char[], int[, StringSplitOptions])` | `s.AsSpan().SplitAny(Span<Range>, ReadOnlySpan<char>, StringSplitOptions)` |
| `s.Split(string[], int, StringSplitOptions)` | `s.AsSpan().SplitAny(Span<Range>, ReadOnlySpan<string>, StringSplitOptions)` |

The destination's length plays the role of the count. The last range holds the rest of the input, just like the last element of the array from `string.Split`.

For example:

```csharp
string[] parts = line.Split('=', 2);            // CA1881
string key = parts[0], value = parts[1];

Span<Range> ranges = stackalloc Range[2];       // no string[] or substrings allocated
int n = line.AsSpan().Split(ranges, '=');
ReadOnlySpan<char> key2 = line.AsSpan(ranges[0]);
```

Details:

- It's C# only. VB can't use `Span<T>`, so there's nothing to suggest there.
- It stays silent when the target framework doesn't have the span overloads (anything before .NET 8). Each `string.Split` overload is only mapped if its matching `MemoryExtensions` overload exists.
- It skips calls inside expression trees, async methods, async lambdas, async local functions and iterators. Span locals aren't allowed in any of those (async and iterators allow them from C# 13 on, but the rule doesn't try to tell the difference yet).
- There's no code fix. The issue itself doubted a fixer is practical, and the review didn't ask for one.
- Descriptor: `RuleLevel.IdeSuggestion` (Info, enabled by default), category Performance.

## Files in the upstream change

- `Microsoft.NetCore.Analyzers/Performance/PreferSpanSplitOverCountedStringSplit.cs` (new): the analyzer.
- `tests/.../Performance/PreferSpanSplitOverCountedStringSplitTests.cs` (new): 26 MSTest cases.
- `MicrosoftNetCoreAnalyzersResources.resx`: title, message and description strings.
- `xlf/*.xlf` (13 files): new `state="new"` entries for those strings.
- `AnalyzerReleases.Unshipped.md`: the CA1881 row.
- `Utilities/Compiler/DiagnosticCategoryAndIdRanges.txt`: Performance range extended to `CA1881`.
- `Utilities/Compiler/WellKnownTypeNames.cs`: adds `System.StringSplitOptions`.
- `Microsoft.CodeAnalysis.NetAnalyzers.md` and `.sarif.template`: CA1881 entries.

## How it was verified

The real dotnet/sdk build couldn't run in the build environment. It needs the Arcade SDK and the dnceng Azure DevOps feeds, and both were blocked. Instead, a throwaway harness (not committed) did the following:

- compiled the analyzer against Roslyn 4.14.0, the version upstream's analyzers build against, using upstream's own `Analyzer.Utilities.projitems`, the real resx, and the `Microsoft.CodeAnalysis.Analyzers` release-tracking checks, with warnings as errors;
- ran the test file through upstream's `Test.Utilities.CSharpCodeFixVerifier` sources, with `Microsoft.CodeAnalysis.CSharp.CodeFix.Testing` 1.1.2 and the .NET 7/8 reference assemblies from nuget.org.

All 26 tests pass. To check that the tests can actually fail, each guard was broken on purpose and the matching tests failed:

- with the expression-tree/async/iterator guard removed, 4 tests failed;
- with the iterator check alone removed, 1 failed;
- with the ".NET 8 API exists" check removed, 1 failed;
- with reporting disabled, 12 failed.

The example above was also built as a .NET 8 console app with the analyzer attached. CA1881 fired on the `Split('=', 2)` line, and both versions produced the same parts (`a` and `b=c`).

Things that still need doing in a real dotnet/sdk checkout:

- Rebuild once, so `GenerateAnalyzerConfigAndDocumentationFiles` and `/t:UpdateXlf` confirm the hand-written md, sarif and xlf entries. Commit anything they change.
- `IMethodSymbol.IsIterator` isn't available in Roslyn 4.14. The analyzer finds iterators by looking for `yield` in the method's own body instead.

## Open items

- **Diagnostic ID.** CA1881 is the next ID after the Performance range (`CA1800-CA1880`) as of `3b1d59f`. Open dotnet/sdk PRs couldn't be checked from here, so run `.github/skills/add-net-analyzer/scripts/NextDiagnosticId.cs Performance` before opening a PR and renumber if it's taken.
- **Docs page.** Upstream requires a `ca1881.md` page in [dotnet/docs](https://github.com/dotnet/docs/tree/main/docs/fundamentals/code-analysis/quality-rules) within a week of the rule merging.
- **Real-code validation.** Upstream asks for new rules to be run over a large codebase (dotnet/runtime, dotnet/roslyn), with the hits triaged, before merging at Info.
- **Transcript.** The video transcript still needs to be fetched and checked against this design.

Later work the review pointed at, each needing its own issue or diagnostic ID:

- uncounted `Split` in `foreach`, now possible with the .NET 9 `MemoryExtensions.Split` that returns a `SpanSplitEnumerator<char>`;
- other uncounted `Split` patterns;
- `Split` followed by `Trim`/`TrimStart`/`TrimEnd`;
- reporting inside async methods and iterators when compiling as C# 13 or later.
