#nullable disable warnings
using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes SearchValues and the vectorized IndexOfAny / Contains family against naive loops.</summary>
/// <remarks>
/// Input layout:
///   byte 0     low 2 bits: mode (0 bytes, 1 chars, 2 strings, 3 chars widened from Latin-1);
///              0x04 OrdinalIgnoreCase (strings); 0x08 haystack from UTF-8 text (strings)
///   byte 1     haystack start offset (low 4 bits, to vary alignment)
///   byte 2     number of values
///   values     n bytes / n UTF-16LE chars / n '\0'-terminated UTF-8 strings
///   rest       haystack (bytes, UTF-16LE chars, or UTF-8 text)
/// The machine's widest vector ISA is used by default; fuzz.sh can run instances with AVX-512 or
/// AVX2 disabled so the Vector256/Vector128 paths get the same treatment.
/// </remarks>
public static class SearchValuesTarget
{
    private const int MaxHaystack = 4096;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        int offset = input.Byte() & 15;
        int count = input.Byte();
        switch (mode & 3)
        {
            case 0:
            {
                byte[] values = input.Bytes(count).ToArray();
                byte[] haystack = input.Rest().ToArray();
                if (haystack.Length <= MaxHaystack)
                {
                    Bytes(values, haystack.AsSpan(Math.Min(offset, haystack.Length)));
                }

                break;
            }

            case 1 or 3:
            {
                char[] values = (mode & 3) == 1
                    ? MemoryMarshal.Cast<byte, char>(input.Bytes(2 * count)).ToArray()
                    : input.Bytes(count).ToArray().Select(b => (char)b).ToArray();
                ReadOnlySpan<byte> rest = input.Rest();
                char[] haystack = (mode & 3) == 1
                    ? MemoryMarshal.Cast<byte, char>(rest.Slice(0, rest.Length & ~1)).ToArray()
                    : rest.ToArray().Select(b => (char)b).ToArray();
                if (haystack.Length <= MaxHaystack)
                {
                    Chars(values, haystack.AsSpan(Math.Min(offset, haystack.Length)));
                }

                break;
            }

            default:
            {
                var values = new List<string>();
                for (int i = 0; i < Math.Min(count, 64) && input.Remaining > 0; i++)
                {
                    values.Add(input.Segment());
                }

                ReadOnlySpan<byte> rest = input.Rest();
                string haystack = (mode & 8) != 0 ? Encoding.UTF8.GetString(rest) : MemoryMarshal.Cast<byte, char>(rest.Slice(0, rest.Length & ~1)).ToString();
                if (haystack.Length <= MaxHaystack && values.All(v => v.Length <= 64))
                {
                    Strings([.. values], haystack.AsSpan(Math.Min(offset, haystack.Length)), (mode & 4) != 0 ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
                }

                break;
            }
        }
    }

    private static void Bytes(byte[] values, ReadOnlySpan<byte> haystack)
    {
        var set = new bool[256];
        foreach (byte v in values)
        {
            set[v] = true;
        }

        int first = -1, last = -1, firstExcept = -1, lastExcept = -1;
        for (int i = 0; i < haystack.Length; i++)
        {
            if (set[haystack[i]]) { if (first < 0) { first = i; } last = i; }
            else { if (firstExcept < 0) { firstExcept = i; } lastExcept = i; }
        }

        string what = $"bytes {Check.Show(values)} in {haystack.Length}-byte haystack";
        SearchValues<byte> sv = SearchValues.Create(values);
        Check.Equal(first, haystack.IndexOfAny(sv), $"IndexOfAny(SearchValues) for {what}");
        Check.Equal(last, haystack.LastIndexOfAny(sv), $"LastIndexOfAny(SearchValues) for {what}");
        Check.Equal(firstExcept, haystack.IndexOfAnyExcept(sv), $"IndexOfAnyExcept(SearchValues) for {what}");
        Check.Equal(lastExcept, haystack.LastIndexOfAnyExcept(sv), $"LastIndexOfAnyExcept(SearchValues) for {what}");
        Check.Equal(first >= 0, haystack.ContainsAny(sv), $"ContainsAny(SearchValues) for {what}");
        Check.Equal(firstExcept >= 0, haystack.ContainsAnyExcept(sv), $"ContainsAnyExcept(SearchValues) for {what}");
        for (int b = 0; b < 256; b++)
        {
            Check.Equal(set[b], sv.Contains((byte)b), $"SearchValues<byte>.Contains({b}) for {what}");
        }

        Check.Equal(first, haystack.IndexOfAny(values), $"IndexOfAny(span) for {what}");
        Check.Equal(last, haystack.LastIndexOfAny(values), $"LastIndexOfAny(span) for {what}");
        Check.Equal(firstExcept, haystack.IndexOfAnyExcept(values), $"IndexOfAnyExcept(span) for {what}");
        Check.Equal(lastExcept, haystack.LastIndexOfAnyExcept(values), $"LastIndexOfAnyExcept(span) for {what}");
        Check.Equal(first >= 0, haystack.ContainsAny(values), $"ContainsAny(span) for {what}");
        FixedArity(haystack, values, what);

        if (values.Length >= 2)
        {
            byte lo = Math.Min(values[0], values[1]), hi = Math.Max(values[0], values[1]);
            RangeChecks(haystack, lo, hi, b => b >= lo && b <= hi, what);
        }

        int occurrences = 0;
        if (values.Length > 0)
        {
            foreach (byte b in haystack) { if (b == values[0]) { occurrences++; } }
            Check.Equal(occurrences, haystack.Count(values[0]), $"Count({values[0]}) for {what}");
            Check.Equal(Array.IndexOf(haystack.ToArray(), values[0]), haystack.IndexOf(values[0]), $"IndexOf({values[0]}) for {what}");
            Check.Equal(Array.LastIndexOf(haystack.ToArray(), values[0]), haystack.LastIndexOf(values[0]), $"LastIndexOf({values[0]}) for {what}");
        }
    }

    private static void Chars(char[] values, ReadOnlySpan<char> haystack)
    {
        var set = new HashSet<char>(values);
        int first = -1, last = -1, firstExcept = -1, lastExcept = -1;
        for (int i = 0; i < haystack.Length; i++)
        {
            if (set.Contains(haystack[i])) { if (first < 0) { first = i; } last = i; }
            else { if (firstExcept < 0) { firstExcept = i; } lastExcept = i; }
        }

        string what = $"chars {Check.Show(new string(values))} in {haystack.Length}-char haystack";
        SearchValues<char> sv = SearchValues.Create(values);
        Check.Equal(first, haystack.IndexOfAny(sv), $"IndexOfAny(SearchValues) for {what}");
        Check.Equal(last, haystack.LastIndexOfAny(sv), $"LastIndexOfAny(SearchValues) for {what}");
        Check.Equal(firstExcept, haystack.IndexOfAnyExcept(sv), $"IndexOfAnyExcept(SearchValues) for {what}");
        Check.Equal(lastExcept, haystack.LastIndexOfAnyExcept(sv), $"LastIndexOfAnyExcept(SearchValues) for {what}");
        Check.Equal(first >= 0, haystack.ContainsAny(sv), $"ContainsAny(SearchValues) for {what}");
        Check.Equal(firstExcept >= 0, haystack.ContainsAnyExcept(sv), $"ContainsAnyExcept(SearchValues) for {what}");
        foreach (char c in haystack.ToArray().Concat(values).Concat(values.Select(v => (char)(v ^ 1))).Concat(values.Select(v => (char)(v ^ 0x20))))
        {
            Check.Equal(set.Contains(c), sv.Contains(c), $"SearchValues<char>.Contains(U+{(int)c:X4}) for {what}");
        }

        Check.Equal(first, haystack.IndexOfAny(values), $"IndexOfAny(span) for {what}");
        Check.Equal(last, haystack.LastIndexOfAny(values), $"LastIndexOfAny(span) for {what}");
        Check.Equal(firstExcept, haystack.IndexOfAnyExcept(values), $"IndexOfAnyExcept(span) for {what}");
        Check.Equal(lastExcept, haystack.LastIndexOfAnyExcept(values), $"LastIndexOfAnyExcept(span) for {what}");
        string hay = haystack.ToString();
        Check.Equal(first, hay.IndexOfAny(values), $"string.IndexOfAny for {what}");
        Check.Equal(last, hay.LastIndexOfAny(values), $"string.LastIndexOfAny for {what}");
        if (hay.Length > 2)
        {
            int start = hay.Length / 3, len = hay.Length / 2;
            int expected = -1;
            for (int i = start; i < start + len; i++) { if (set.Contains(hay[i])) { expected = i; break; } }
            Check.Equal(expected, hay.IndexOfAny(values, start, len), $"string.IndexOfAny(start {start}, count {len}) for {what}");
        }

        FixedArity(haystack, values, what);
        if (values.Length >= 2)
        {
            char lo = (char)Math.Min(values[0], values[1]), hi = (char)Math.Max(values[0], values[1]);
            RangeChecks(haystack, lo, hi, c => c >= lo && c <= hi, what);
        }

        if (values.Length > 0)
        {
            Check.Equal(hay.IndexOf(values[0]), haystack.IndexOf(values[0]), $"IndexOf(char) for {what}");
            Check.Equal(hay.Count(c => c == values[0]), haystack.Count(values[0]), $"Count(char) for {what}");
            int manualLast = -1;
            for (int i = 0; i < hay.Length; i++) { if (hay[i] == values[0]) { manualLast = i; } }
            Check.Equal(manualLast, haystack.LastIndexOf(values[0]), $"LastIndexOf(char) for {what}");
            Check.Equal(hay.Replace(values[0], '￿'), string.Create(hay.Length, hay, (dst, h) => h.AsSpan().Replace(dst, values[0], '￿')), $"MemoryExtensions.Replace for {what}");
        }
    }

    /// <summary>The 1-, 2-, 3-, 4- and 5-value IndexOfAny overloads have their own vectorized paths.</summary>
    private static void FixedArity<T>(ReadOnlySpan<T> haystack, T[] values, string what)
        where T : IEquatable<T>
    {
        for (int arity = 1; arity <= Math.Min(5, values.Length); arity++)
        {
            T[] subset = values[..arity];
            int expected = -1, expectedLast = -1, expectedExcept = -1, expectedLastExcept = -1;
            for (int i = 0; i < haystack.Length; i++)
            {
                if (Array.IndexOf(subset, haystack[i]) >= 0) { if (expected < 0) { expected = i; } expectedLast = i; }
                else { if (expectedExcept < 0) { expectedExcept = i; } expectedLastExcept = i; }
            }

            int actual = arity switch
            {
                1 => haystack.IndexOf(subset[0]),
                2 => haystack.IndexOfAny(subset[0], subset[1]),
                3 => haystack.IndexOfAny(subset[0], subset[1], subset[2]),
                _ => haystack.IndexOfAny(subset),
            };
            Check.Equal(expected, actual, $"IndexOfAny with {arity} values for {what}");
            int actualLast = arity switch
            {
                1 => haystack.LastIndexOf(subset[0]),
                2 => haystack.LastIndexOfAny(subset[0], subset[1]),
                3 => haystack.LastIndexOfAny(subset[0], subset[1], subset[2]),
                _ => haystack.LastIndexOfAny(subset),
            };
            Check.Equal(expectedLast, actualLast, $"LastIndexOfAny with {arity} values for {what}");
            int actualExcept = arity switch
            {
                1 => haystack.IndexOfAnyExcept(subset[0]),
                2 => haystack.IndexOfAnyExcept(subset[0], subset[1]),
                3 => haystack.IndexOfAnyExcept(subset[0], subset[1], subset[2]),
                _ => haystack.IndexOfAnyExcept(subset),
            };
            Check.Equal(expectedExcept, actualExcept, $"IndexOfAnyExcept with {arity} values for {what}");
            int actualLastExcept = arity switch
            {
                1 => haystack.LastIndexOfAnyExcept(subset[0]),
                2 => haystack.LastIndexOfAnyExcept(subset[0], subset[1]),
                3 => haystack.LastIndexOfAnyExcept(subset[0], subset[1], subset[2]),
                _ => haystack.LastIndexOfAnyExcept(subset),
            };
            Check.Equal(expectedLastExcept, actualLastExcept, $"LastIndexOfAnyExcept with {arity} values for {what}");
            Check.Equal(expected >= 0, arity switch
            {
                1 => haystack.Contains(subset[0]),
                2 => haystack.ContainsAny(subset[0], subset[1]),
                3 => haystack.ContainsAny(subset[0], subset[1], subset[2]),
                _ => haystack.ContainsAny(subset),
            }, $"ContainsAny with {arity} values for {what}");
        }
    }

    private static void RangeChecks<T>(ReadOnlySpan<T> haystack, T lo, T hi, Func<T, bool> inRange, string what)
        where T : IComparable<T>
    {
        int first = -1, last = -1, firstExcept = -1, lastExcept = -1;
        for (int i = 0; i < haystack.Length; i++)
        {
            if (inRange(haystack[i])) { if (first < 0) { first = i; } last = i; }
            else { if (firstExcept < 0) { firstExcept = i; } lastExcept = i; }
        }

        Check.Equal(first, haystack.IndexOfAnyInRange(lo, hi), $"IndexOfAnyInRange({lo}, {hi}) for {what}");
        Check.Equal(last, haystack.LastIndexOfAnyInRange(lo, hi), $"LastIndexOfAnyInRange({lo}, {hi}) for {what}");
        Check.Equal(firstExcept, haystack.IndexOfAnyExceptInRange(lo, hi), $"IndexOfAnyExceptInRange({lo}, {hi}) for {what}");
        Check.Equal(lastExcept, haystack.LastIndexOfAnyExceptInRange(lo, hi), $"LastIndexOfAnyExceptInRange({lo}, {hi}) for {what}");
        Check.Equal(first >= 0, haystack.ContainsAnyInRange(lo, hi), $"ContainsAnyInRange({lo}, {hi}) for {what}");
        Check.Equal(firstExcept >= 0, haystack.ContainsAnyExceptInRange(lo, hi), $"ContainsAnyExceptInRange({lo}, {hi}) for {what}");
    }

    private static void Strings(string[] values, ReadOnlySpan<char> haystack, StringComparison comparison)
    {
        SearchValues<string> sv;
        try
        {
            sv = SearchValues.Create(values, comparison);
        }
        catch (ArgumentException) when (values.Length == 0)
        {
            return;
        }

        string what = $"{values.Length} strings [{string.Join(", ", values.Take(8).Select(Check.Show))}{(values.Length > 8 ? ", ..." : "")}] ({comparison}) in {Check.Show(haystack.ToString())}";
        int expected = -1;
        for (int i = 0; i <= haystack.Length && expected < 0; i++)
        {
            foreach (string v in values)
            {
                if (i + v.Length <= haystack.Length && haystack.Slice(i, v.Length).Equals(v, comparison))
                {
                    expected = i;
                    break;
                }
            }
        }

        Check.Equal(expected, haystack.IndexOfAny(sv), $"IndexOfAny(SearchValues<string>) for {what}");
        Check.Equal(expected >= 0, haystack.ContainsAny(sv), $"ContainsAny(SearchValues<string>) for {what}");

        // IndexOf(string, comparison) for each value, as a second opinion on the same semantics.
        int viaIndexOf = -1;
        foreach (string v in values)
        {
            int i = haystack.IndexOf(v, comparison);
            if (i >= 0 && (viaIndexOf < 0 || i < viaIndexOf))
            {
                viaIndexOf = i;
            }
        }

        Check.Equal(expected, viaIndexOf, $"min IndexOf(value, {comparison}) for {what}");

        foreach (string v in values)
        {
            Check.That(sv.Contains(v), $"SearchValues<string>.Contains({Check.Show(v)}) is false for a value it was created from, {what}");
        }

        string hay = haystack.ToString();
        bool expectedContains = values.Any(v => string.Equals(v, hay, comparison));
        Check.Equal(expectedContains, sv.Contains(hay), $"SearchValues<string>.Contains(haystack) for {what}");
    }
}
