#nullable disable warnings
using System.Globalization;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// The ICU interop layer (libSystem.Globalization.Native: collation, normalization, casing, IDN and
/// locale data, all with native buffer-sizing loops) against its documented invariants:
/// Normalize / IsNormalized in every form (idempotence, agreement, consistent rejection of invalid
/// UTF-16), CompareInfo in several cultures and option sets (antisymmetry, equal-implies-equal-hash,
/// sort keys ordering like Compare, span sort keys into exactly sized guarded buffers, IndexOf /
/// LastIndexOf / IsPrefix / IsSuffix consistency with matchLength), TextInfo casing (string vs char,
/// span overloads into guarded buffers, idempotence, Turkish i), IdnMapping round trips, and
/// CultureInfo / RegionInfo lookups with fuzzed names. Needs a harness built with
/// InvariantGlobalization=false (harness-icu).
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 flags; byte 2 culture; byte 3 length of a (chars)
///   rest       a (UTF-16LE), then b (UTF-16LE, the rest)
/// </remarks>
public static unsafe class GlobalizationTarget
{
    private static readonly string[] s_cultures = ["", "en-US", "de-DE", "tr-TR", "ja-JP", "sv-SE", "da-DK", "th-TH", "zh-CN", "ar-SA", "he-IL", "hi-IN", "fr-FR", "cs-CZ", "vi-VN", "ko-KR"];
    private static readonly CompareOptions[] s_options =
    [
        CompareOptions.None, CompareOptions.IgnoreCase, CompareOptions.IgnoreNonSpace, CompareOptions.IgnoreSymbols, CompareOptions.IgnoreKanaType, CompareOptions.IgnoreWidth,
        CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace, CompareOptions.IgnoreCase | CompareOptions.IgnoreSymbols | CompareOptions.IgnoreKanaType | CompareOptions.IgnoreWidth,
        CompareOptions.StringSort, CompareOptions.NumericOrdering, CompareOptions.IgnoreCase | CompareOptions.NumericOrdering, CompareOptions.Ordinal, CompareOptions.OrdinalIgnoreCase,
        CompareOptions.IgnoreNonSpace | CompareOptions.IgnoreWidth, CompareOptions.IgnoreCase | CompareOptions.IgnoreNonSpace | CompareOptions.IgnoreSymbols | CompareOptions.IgnoreKanaType | CompareOptions.IgnoreWidth | CompareOptions.StringSort,
    ];

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;
    private static readonly bool s_icu = "Å".Normalize(NormalizationForm.FormD) == "Å";

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (!s_icu)
        {
            throw new InvalidOperationException("The globalization target needs a harness built with InvariantGlobalization=false (see build-icu).");
        }

        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte flags = input.Byte();
        CultureInfo culture = CultureInfo.GetCultureInfo(s_cultures[input.Byte() % s_cultures.Length]);
        int lengthA = input.Byte();
        string a = Utf16(input.Bytes(lengthA * 2));
        string b = Utf16(input.Rest());
        switch (op % 5)
        {
            case 0: Normalization(a, flags); break;
            case 1: Collation(culture, a, b, flags); break;
            case 2: Casing(culture, a, flags); break;
            case 3: Idn(a, flags); break;
            default: Cultures(a, flags); break;
        }
    }

    /// <summary>Raw UTF-16 code units from the bytes (lone surrogates included), up to 300 chars.</summary>
    private static string Utf16(ReadOnlySpan<byte> bytes)
    {
        ReadOnlySpan<char> chars = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, char>(bytes.Slice(0, bytes.Length & ~1));
        return new string(chars.Slice(0, Math.Min(chars.Length, 300)));
    }

    private static bool HasLoneSurrogate(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(s[i]))
            {
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------ normalization

    private static void Normalization(string a, byte flags)
    {
        string what = $"Normalize of {Check.Show(a)}";
        bool invalid = HasLoneSurrogate(a);
        foreach (NormalizationForm form in (NormalizationForm[])[NormalizationForm.FormC, NormalizationForm.FormD, NormalizationForm.FormKC, NormalizationForm.FormKD])
        {
            string normalized;
            bool isNormalized;
            try
            {
                normalized = a.Normalize(form);
                isNormalized = a.IsNormalized(form);
            }
            catch (ArgumentException)
            {
                Check.That(invalid, $"{what} ({form}): ArgumentException for valid UTF-16");
                try
                {
                    a.IsNormalized(form);
                    Check.That(false, $"{what} ({form}): Normalize threw but IsNormalized didn't");
                }
                catch (ArgumentException)
                {
                }

                continue;
            }

            Check.That(!invalid, $"{what} ({form}): accepted a lone surrogate");
            Check.Equal(a == normalized, isNormalized, $"{what} ({form}): IsNormalized vs Normalize");
            Check.That(normalized.IsNormalized(form), $"{what} ({form}): the result isn't normalized");
            Check.Equal(normalized, normalized.Normalize(form), $"{what} ({form}): not idempotent");
        }

        if (!invalid)
        {
            // Canonical equivalence survives compatibility decomposition, and NFC / NFD agree on NFKC / NFKD.
            Check.Equal(a.Normalize(NormalizationForm.FormKC), a.Normalize(NormalizationForm.FormC).Normalize(NormalizationForm.FormKC), $"{what}: NFKC(NFC) != NFKC");
            Check.Equal(a.Normalize(NormalizationForm.FormKD), a.Normalize(NormalizationForm.FormD).Normalize(NormalizationForm.FormKD), $"{what}: NFKD(NFD) != NFKD");
            Check.Equal(a.Normalize(NormalizationForm.FormC), a.Normalize(NormalizationForm.FormD).Normalize(NormalizationForm.FormC), $"{what}: NFC(NFD) != NFC");
            Check.Equal(a.Normalize(NormalizationForm.FormD), a.Normalize(NormalizationForm.FormC).Normalize(NormalizationForm.FormD), $"{what}: NFD(NFC) != NFD");
            // Canonically equivalent strings compare equal under culture-sensitive comparison.
            CompareInfo ci = CultureInfo.InvariantCulture.CompareInfo;
            Check.Equal(0, ci.Compare(a.Normalize(NormalizationForm.FormC), a.Normalize(NormalizationForm.FormD), CompareOptions.None), $"{what}: NFC and NFD compare differently");
            // Expansion is bounded (ICU's worst case is 3x for NFD, 18x for NFKD... in UTF-16 up to 3x / 18x).
            Check.That(a.Normalize(NormalizationForm.FormD).Length <= 3 * Math.Max(1, a.Length) && a.Normalize(NormalizationForm.FormKD).Length <= 18 * Math.Max(1, a.Length), $"{what}: decomposition longer than the bound");
        }
    }

    // ------------------------------------------------------------ collation

    private static void Collation(CultureInfo culture, string a, string b, byte flags)
    {
        CompareInfo ci = culture.CompareInfo;
        CompareOptions options = s_options[flags % s_options.Length];
        string what = $"{culture.Name switch { "" => "invariant", var n => n }} {options} of {Check.Show(a)} / {Check.Show(b)}";
        int ab;
        try
        {
            ab = Math.Sign(ci.Compare(a, b, options));
        }
        catch (ArgumentException)
        {
            // An invalid combination: every entry point must reject it the same way.
            foreach ((string name, Action call) in (ValueTuple<string, Action>[])
            [
                ("GetHashCode", () => ci.GetHashCode(a, options)), ("IndexOf", () => ci.IndexOf(a, b, options)), ("IsPrefix", () => ci.IsPrefix(a, b, options)),
                ("IsSuffix", () => ci.IsSuffix(a, b, options)), ("LastIndexOf", () => ci.LastIndexOf(a, b, options)), ("GetSortKey", () => ci.GetSortKey(a, options)),
                ("span Compare", () => ci.Compare(a.AsSpan(), b.AsSpan(), options)), ("span IndexOf", () => ci.IndexOf(a.AsSpan(), b.AsSpan(), options)),
                ("GetSortKeyLength", () => ci.GetSortKeyLength(a.AsSpan(), options)), ("string.Compare", () => string.Compare(a, b, culture, options)),
            ])
            {
                try
                {
                    call();
                    Check.That(false, $"{what}: Compare rejected the options but {name} accepted them");
                }
                catch (ArgumentException)
                {
                }
            }

            return;
        }

        int ba = Math.Sign(ci.Compare(b, a, options));
        Check.Equal(-ab, ba, $"{what}: Compare isn't antisymmetric");
        Check.Equal(0, ci.Compare(a, a, options), $"{what}: Compare(a, a)");
        Check.Equal(ab, Math.Sign(ci.Compare(a.AsSpan(), b.AsSpan(), options)), $"{what}: span Compare differs");
        Check.Equal(ab, Math.Sign(string.Compare(a, b, culture, options)), $"{what}: string.Compare differs");
        if (ab == 0)
        {
            Check.Equal(ci.GetHashCode(a, options), ci.GetHashCode(b, options), $"{what}: equal strings with different hash codes");
        }

        Check.Equal(ci.GetHashCode(a, options), ci.GetHashCode(a.AsSpan(), options), $"{what}: span GetHashCode differs");
        if ((options & (CompareOptions.Ordinal | CompareOptions.OrdinalIgnoreCase)) == 0)
        {
            // Sort keys order like Compare, and the span overload writes exactly GetSortKeyLength bytes.
            SortKey ka = ci.GetSortKey(a, options), kb = ci.GetSortKey(b, options);
            Check.Equal(ab, Math.Sign(SortKey.Compare(ka, kb)), $"{what}: sort keys order differently from Compare");
            Check.Equal(ab, Math.Sign(ka.KeyData.AsSpan().SequenceCompareTo(kb.KeyData)), $"{what}: sort key bytes order differently from Compare");
            int length = ci.GetSortKeyLength(a.AsSpan(), options);
            Check.Equal(ka.KeyData.Length, length, $"{what}: GetSortKeyLength vs KeyData.Length");
            Span<byte> exact = new(Guarded.Allocate(length, (flags & 0x80) != 0), length);
            Check.Equal(length, ci.GetSortKey(a.AsSpan(), exact, options), $"{what}: span GetSortKey length");
            Check.That(exact.SequenceEqual(ka.KeyData), $"{what}: span GetSortKey bytes");
            if (length > 0)
            {
                Span<byte> tooShort = new(Guarded.Allocate(length - 1, (flags & 0x80) == 0), length - 1);
                try
                {
                    ci.GetSortKey(a.AsSpan(), tooShort, options);
                    Check.That(false, $"{what}: GetSortKey into a short buffer succeeded");
                }
                catch (ArgumentException)
                {
                }
            }
        }

        // Searching: a match found by IndexOf compares equal to what was searched for, and the prefix / suffix helpers agree.
        // ICU's prefix / suffix / search semantics differ around characters the collator ignores (COLLATION-1), so
        // those consistency checks only run when neither string contains an ignorable character.
        bool ignorables = !s_reportKnownIssues && (a.Any(c => IsIgnorable(ci, c, options)) || b.Any(c => IsIgnorable(ci, c, options)));
        int index, matchLength;
        try
        {
            index = ci.IndexOf(a.AsSpan(), b.AsSpan(), options, out matchLength);
        }
        catch (ArgumentException)
        {
            // Documented: the search APIs don't take StringSort or NumericOrdering; all of them must say so.
            Check.That((options & (CompareOptions.StringSort | CompareOptions.NumericOrdering)) != 0, $"{what}: IndexOf rejected options without StringSort / NumericOrdering");
            if (b.Length == 0)
            {
                return; // the empty value short-circuits before the options are validated
            }

            foreach ((string name, Action call) in (ValueTuple<string, Action>[])
            [
                ("IndexOf(string)", () => ci.IndexOf(a, b, options)), ("IndexOf(span)", () => ci.IndexOf(a.AsSpan(), b.AsSpan(), options)), ("LastIndexOf", () => ci.LastIndexOf(a, b, options)),
                ("IsPrefix", () => ci.IsPrefix(a, b, options)), ("IsSuffix", () => ci.IsSuffix(a, b, options)), ("IsPrefix(span)", () => ci.IsPrefix(a.AsSpan(), b.AsSpan(), options)),
            ])
            {
                try
                {
                    call();
                    Check.That(false, $"{what}: {name} accepted options that IndexOf with matchLength rejected");
                }
                catch (ArgumentException)
                {
                }
            }

            return;
        }

        Check.Equal(index, ci.IndexOf(a, b, options), $"{what}: IndexOf span vs string");
        if (index >= 0)
        {
            Check.That(index + matchLength <= a.Length && matchLength >= 0, $"{what}: IndexOf match {index}+{matchLength} outside the string");
            Check.That(ignorables || ci.Compare(a.Substring(index, matchLength), b, options) == 0, $"{what}: IndexOf match at {index}+{matchLength} doesn't compare equal");
        }

        bool prefix = ci.IsPrefix(a, b, options);
        Check.Equal(prefix, ci.IsPrefix(a.AsSpan(), b.AsSpan(), options), $"{what}: IsPrefix span vs string");
        Check.That(ignorables || !prefix || index == 0 || b.Length == 0 && index >= 0, $"{what}: IsPrefix true but IndexOf {index}");
        bool suffix = ci.IsSuffix(a, b, options);
        Check.Equal(suffix, ci.IsSuffix(a.AsSpan(), b.AsSpan(), options), $"{what}: IsSuffix span vs string");
        int last = ci.LastIndexOf(a.AsSpan(), b.AsSpan(), options, out int lastLength);
        Check.Equal(last, ci.LastIndexOf(a, b, options), $"{what}: LastIndexOf span vs string");
        Check.That(ignorables || !suffix || last >= 0 && last + lastLength == a.Length || b.Length == 0, $"{what}: IsSuffix true but LastIndexOf {last}+{lastLength} of {a.Length}");
        Check.That(ignorables || index < 0 == last < 0, $"{what}: IndexOf {index} and LastIndexOf {last} disagree on whether there is a match");
        Check.Equal(0, ci.IndexOf(a, "", options), $"{what}: IndexOf empty");
        Check.That(ci.IsPrefix(a, "", options) && ci.IsSuffix(a, "", options), $"{what}: empty prefix / suffix");
    }

    private static bool IsIgnorable(CompareInfo ci, char c, CompareOptions options) =>
        char.IsSurrogate(c) || ci.Compare(c.ToString(), "", options) == 0;

    // ------------------------------------------------------------ casing

    private static void Casing(CultureInfo culture, string a, byte flags)
    {
        TextInfo ti = culture.TextInfo;
        string what = $"{culture.Name switch { "" => "invariant", var n => n }} casing of {Check.Show(a)}";
        string upper = ti.ToUpper(a), lower = ti.ToLower(a);
        Check.Equal(a.Length, upper.Length, $"{what}: ToUpper changed the length");
        Check.Equal(a.Length, lower.Length, $"{what}: ToLower changed the length");
        Check.Equal(upper, ti.ToUpper(upper), $"{what}: ToUpper not idempotent");
        Check.Equal(lower, ti.ToLower(lower), $"{what}: ToLower not idempotent");
        Check.Equal(upper, a.ToUpper(culture), $"{what}: string.ToUpper(culture) differs");
        Check.Equal(lower, a.ToLower(culture), $"{what}: string.ToLower(culture) differs");
        if (!a.Any(char.IsSurrogate))
        {
            // Simple case mapping: the string result is the per-char result.
            var sb = new StringBuilder(a.Length);
            foreach (char c in a)
            {
                sb.Append(ti.ToUpper(c));
            }

            Check.Equal(sb.ToString(), upper, $"{what}: ToUpper(string) differs from ToUpper(char) per char");
            sb.Clear();
            foreach (char c in a)
            {
                sb.Append(char.ToLower(c, culture));
            }

            Check.Equal(sb.ToString(), lower, $"{what}: ToLower(string) differs from char.ToLower(c, culture) per char");
        }

        // Span overloads into exactly sized guarded buffers, and a short one.
        Span<char> dest = new((char*)Guarded.Allocate(a.Length * 2L, (flags & 1) != 0), a.Length);
        Check.Equal(a.Length, a.AsSpan().ToUpper(dest, culture), $"{what}: span ToUpper length");
        Check.That(dest.SequenceEqual(upper), $"{what}: span ToUpper contents");
        Check.Equal(a.Length, a.AsSpan().ToLower(dest, culture), $"{what}: span ToLower length");
        Check.That(dest.SequenceEqual(lower), $"{what}: span ToLower contents");
        if (a.Length > 0)
        {
            Span<char> shortDest = new((char*)Guarded.Allocate((a.Length - 1) * 2L, (flags & 1) == 0), a.Length - 1);
            Check.Equal(-1, a.AsSpan().ToUpper(shortDest, culture), $"{what}: span ToUpper into a short buffer");
            Check.Equal(-1, a.AsSpan().ToLower(shortDest, culture), $"{what}: span ToLower into a short buffer");
        }

        Check.Equal(a.ToUpperInvariant(), CultureInfo.InvariantCulture.TextInfo.ToUpper(a), $"{what}: ToUpperInvariant vs TextInfo.Invariant");
        Check.Equal(a.ToLowerInvariant(), CultureInfo.InvariantCulture.TextInfo.ToLower(a), $"{what}: ToLowerInvariant vs TextInfo.Invariant");
        if (culture.Name == "tr-TR")
        {
            Check.Equal("İ", ti.ToUpper("i"), "Turkish i");
            Check.Equal("ı", ti.ToLower("I"), "Turkish I");
        }

        _ = ti.ToTitleCase(a.Length > 100 ? a.Substring(0, 100) : a);
    }

    // ------------------------------------------------------------ IDN

    private static void Idn(string a, byte flags)
    {
        var idn = new IdnMapping { AllowUnassigned = (flags & 1) != 0, UseStd3AsciiRules = (flags & 2) != 0 };
        string what = $"IdnMapping(unassigned {idn.AllowUnassigned}, std3 {idn.UseStd3AsciiRules}) of {Check.Show(a)}";
        string ascii;
        try
        {
            ascii = idn.GetAscii(a);
        }
        catch (ArgumentException)
        {
            return;
        }

        Check.That(ascii.All(c => c < 0x80), $"{what}: GetAscii returned non-ASCII {Check.Show(ascii)}");
        Check.That(ascii.Length <= 255, $"{what}: GetAscii returned {ascii.Length} chars");
        string unicode = idn.GetUnicode(ascii);
        string again = idn.GetAscii(unicode);
        Check.Equal(ascii, again, $"{what}: GetAscii(GetUnicode(GetAscii)) differs: {Check.Show(unicode)}");
        Check.Equal(unicode, idn.GetUnicode(again), $"{what}: GetUnicode not idempotent");
        // The same through the offset / length overloads.
        Check.Equal(ascii, idn.GetAscii(a, 0, a.Length), $"{what}: GetAscii(string, index, count)");
        // A label that is pure ASCII already stays as is apart from case.
        if (a.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.') && a.Length > 0 && !a.StartsWith('-') && !a.EndsWith('-') && !a.Contains("--") && !a.Contains('.'))
        {
            Check.Equal(a, ascii, $"{what}: an ASCII label changed");
        }
    }

    // ------------------------------------------------------------ cultures

    private static void Cultures(string a, byte flags)
    {
        var sb = new StringBuilder();
        foreach (char c in a)
        {
            if (c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_')
            {
                sb.Append(c);
            }
            else if (c < 0x80)
            {
                sb.Append('-');
            }

            if (sb.Length >= 100)
            {
                break;
            }
        }

        string name = sb.ToString();
        string what = $"culture {Check.Show(name)}";
        CultureInfo culture;
        try
        {
            culture = CultureInfo.GetCultureInfo(name);
        }
        catch (CultureNotFoundException)
        {
            try
            {
                _ = new CultureInfo(name);
                Check.That(false, $"{what}: GetCultureInfo threw but the constructor succeeded");
            }
            catch (CultureNotFoundException)
            {
            }

            return;
        }
        catch (ArgumentException)
        {
            Check.That(name.Length > 85 || name.Length == 0, $"{what}: ArgumentException for a short name");
            return;
        }

        Check.That(culture.Name.Length <= 85, $"{what}: Name {Check.Show(culture.Name)} is too long");
        Check.Equal(culture.Name, CultureInfo.GetCultureInfo(culture.Name).Name, $"{what}: Name doesn't round trip");
        Check.Equal(culture.Name, new CultureInfo(name).Name, $"{what}: constructor Name differs");
        Check.That(culture.NumberFormat is not null && culture.DateTimeFormat is not null && culture.TextInfo is not null && culture.CompareInfo is not null, $"{what}: null data");
        _ = culture.DisplayName; _ = culture.NativeName; _ = culture.EnglishName; _ = culture.TwoLetterISOLanguageName; _ = culture.Calendar; _ = culture.OptionalCalendars;
        _ = culture.NumberFormat.CurrencySymbol; _ = culture.DateTimeFormat.ShortDatePattern; _ = culture.DateTimeFormat.MonthNames; _ = culture.DateTimeFormat.DayNames;
        _ = 1234.5.ToString("N", culture); _ = new DateTime(2024, 2, 29, 13, 14, 15).ToString("F", culture);
        Check.Equal(culture.Name, CultureInfo.GetCultureInfo(culture.Name.ToUpperInvariant()).Name, $"{what}: case-insensitive lookup");
        try
        {
            CultureInfo predefined = CultureInfo.GetCultureInfo(name, predefinedOnly: true);
            Check.Equal(culture.Name, predefined.Name, $"{what}: predefined lookup differs");
        }
        catch (CultureNotFoundException)
        {
            // Not a predefined culture: ICU accepted it as a custom locale name.
        }

        if (!culture.IsNeutralCulture && culture.Name.Length > 0)
        {
            try
            {
                var region = new RegionInfo(culture.Name);
                Check.That(region.Name.Length > 0 && region.TwoLetterISORegionName.Length > 0, $"{what}: empty RegionInfo");
            }
            catch (ArgumentException)
            {
            }
        }
    }
}
