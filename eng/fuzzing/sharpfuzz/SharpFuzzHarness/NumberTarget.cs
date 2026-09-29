#nullable disable warnings
using System.Globalization;
using System.Numerics;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes number parsing and formatting in System.Private.CoreLib (System.Number) for every
/// primitive numeric type.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     low nibble: type (see <see cref="Run"/>); 0x10 fuzzed NumberFormatInfo
///   byte 1-2   NumberStyles (masked to the defined bits unless bit 15 is set)
///   [NumberFormatInfo fields, see <see cref="FormatInfos.Number"/>]
///   segment    text to parse
///   segment    format string
/// Checks: Parse / TryParse (string, UTF-16 span, UTF-8 span) agree; integer results agree with
/// BigInteger; Half/float/double agree on syntax and are consistently rounded; ToString /
/// TryFormat (UTF-16 and UTF-8, exact and short buffers) agree; standard formats round-trip.
/// </remarks>
public static class NumberTarget
{
    private const int MaxTextLength = 512;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte kind = input.Byte();
        ushort rawStyles = input.UInt16();
        var styles = (NumberStyles)((rawStyles & 0x8000) != 0 ? rawStyles & 0x7FFF : rawStyles & 0x7FF);
        NumberFormatInfo nfi = FormatInfos.Number(ref input, (kind & 0x10) != 0);
        byte[] utf8 = input.SegmentBytes().ToArray();
        string format = input.Segment();
        if (utf8.Length > MaxTextLength || !IsSaneFormat(format))
        {
            return;
        }

        string text = Encoding.UTF8.GetString(utf8);
        if (Environment.GetEnvironmentVariable("SHARPFUZZ_DEBUG") is not null)
        {
            Console.WriteLine($"kind={kind & 0xF} styles={styles} text={Check.Show(text)} format={Check.Show(format)}");
            foreach (var p in typeof(NumberFormatInfo).GetProperties().Where(p => p.PropertyType == typeof(string) || p.PropertyType == typeof(int) || p.PropertyType == typeof(int[])))
            {
                object? v = p.GetValue(nfi);
                Console.WriteLine($"  {p.Name} = {(v is int[] a ? string.Join(",", a) : v is string s ? Check.Show(s) : v)}");
            }
        }

        bool validUtf8 = System.Text.Unicode.Utf8.IsValid(utf8);
        var c = new Case(text, utf8, validUtf8, styles, nfi, format);

        switch (kind & 0x0F)
        {
            case 0: Integer<sbyte>(c); break;
            case 1: Integer<byte>(c); break;
            case 2: Integer<short>(c); break;
            case 3: Integer<ushort>(c); break;
            case 4: Integer<int>(c); break;
            case 5: Integer<uint>(c); break;
            case 6: Integer<long>(c); break;
            case 7: Integer<ulong>(c); break;
            case 8: Integer<Int128>(c); break;
            case 9: Integer<UInt128>(c); break;
            case 10: Integer<nint>(c); break;
            case 11: Integer<nuint>(c); break;
            case 12 or 13 or 14: Floats(c); break;
            default: Decimal(c); break;
        }
    }

    private sealed record Case(string Text, byte[] Utf8, bool ValidUtf8, NumberStyles Styles, NumberFormatInfo Nfi, string Format);

    // Standard formats with huge precision ("F999999999") allocate gigabytes; keep them small.
    private static bool IsSaneFormat(string format)
    {
        if (format.Length > 64)
        {
            return false;
        }

        int digits = 0;
        foreach (char ch in format)
        {
            digits = char.IsAsciiDigit(ch) ? digits + 1 : 0;
            if (digits > 3)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsParseError(Exception e) => e is FormatException or OverflowException or ArgumentException;

    private static bool IsStyleError(Exception e) => e is ArgumentException;

    internal static bool HasHugeExponent(string text)
    {
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] is 'e' or 'E')
            {
                int j = i + 1;
                while (j < text.Length && !char.IsAsciiDigit(text[j]) && j - i < 4)
                {
                    j++; // a sign (possibly a multi-char custom one)
                }

                int digits = 0;
                while (j < text.Length && char.IsAsciiDigit(text[j]))
                {
                    j++;
                    digits++;
                }

                if (digits >= 6)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsHexOrBinary(NumberStyles styles) => (styles & (NumberStyles.AllowHexSpecifier | NumberStyles.AllowBinarySpecifier)) != 0;

    /// <summary>Runs all parse overloads and checks that they agree. Returns the TryParse outcome.</summary>
    private static Outcome<(bool Ok, T Value)> ParseAll<T>(Case c, IEqualityComparer<T>? comparer = null)
        where T : INumberBase<T>
    {
        var parse = Outcome<T>.Of(() => T.Parse(c.Text, c.Styles, c.Nfi), IsParseError);
        var tryParse = Outcome<(bool, T)>.Of(() => (T.TryParse(c.Text, c.Styles, c.Nfi, out T v), v), IsStyleError);
        var trySpan = Outcome<(bool, T)>.Of(() => (T.TryParse(c.Text.AsSpan(), c.Styles, c.Nfi, out T v), v), IsStyleError);
        var tryUtf8 = Outcome<(bool, T)>.Of(() => (T.TryParse(c.Utf8.AsSpan(), c.Styles, c.Nfi, out T v), v), IsStyleError);

        var alternatives = new List<(string, Outcome<(bool, T)>)> { ("TryParse(span)", trySpan) };
        // Known (UTF8CASE-1): the UTF-8 case-insensitive symbol comparison used for NaN/Infinity,
        // signs and currency symbols mismatches for non-ASCII symbols and symbols of 16+ bytes.
        if (c.ValidUtf8 && (s_reportKnownIssues || HasShortAsciiSymbols(c.Nfi)))
        {
            alternatives.Add(("TryParse(UTF-8)", tryUtf8));
        }

        Check.ParseAgreement($"{typeof(T).Name} {Check.Show(c.Text)} styles={c.Styles}", comparer ?? EqualityComparer<T>.Default,
            parse, [typeof(FormatException), typeof(OverflowException)], tryParse, alternatives.ToArray());
        return tryParse;
    }

    private static void Integer<T>(Case c)
        where T : IBinaryInteger<T>, IMinMaxValue<T>
    {
        var parsed = ParseAll<T>(c);

        // BigInteger shares the front end but not the digit accumulation / overflow checks.
        // Known (BIGINTEGER-EXP-1): BigInteger materializes the value of a huge exponent ("1e100000000"
        // takes a minute and 300 MB), so skip the reference for exponents of 6+ digits.
        if (parsed.Ok && !IsHexOrBinary(c.Styles) && !HasHugeExponent(c.Text))
        {
            bool refOk = BigInteger.TryParse(c.Text, c.Styles, c.Nfi, out BigInteger reference);
            bool inRange = refOk && reference >= BigInteger.CreateTruncating(T.MinValue) && reference <= BigInteger.CreateTruncating(T.MaxValue);
            // Known (NUMBER-NEGZERO-1): unsigned types accept "-0" and "-0e5" but reject "-0." and "-0.0".
            if (!s_reportKnownIssues && inRange && !parsed.Value.Ok && reference.IsZero && T.IsZero(T.MinValue) && c.Text.Contains(c.Nfi.NumberDecimalSeparator, StringComparison.Ordinal))
            {
                inRange = false;
            }

            Check.That(parsed.Value.Ok == inRange && (!inRange || BigInteger.CreateTruncating(parsed.Value.Value) == reference),
                $"{typeof(T).Name}.TryParse {parsed} but BigInteger.TryParse {(refOk ? reference.ToString() : "failed")} for {Check.Show(c.Text)} styles={c.Styles}");
        }

        T value = parsed.Ok && parsed.Value.Ok ? parsed.Value.Value : T.CreateTruncating(Check.Hash(c.Utf8));

        Formats(value, c.Format, c.Nfi);
        foreach (string standard in (string[])["G", "D", "D20", "N", "N0", "X", "x8", "B", "C", "E", "F2", "P", "R", "e30"])
        {
            Formats(value, standard, c.Nfi);
        }

        var inv = NumberFormatInfo.InvariantInfo;
        RoundTrip(value, value.ToString("D", inv), NumberStyles.Integer, inv);
        RoundTrip(value, value.ToString("X", inv), NumberStyles.HexNumber, inv);
        RoundTrip(value, value.ToString("B", inv), NumberStyles.BinaryNumber, inv);
        RoundTrip(value, value.ToString("N0", inv), NumberStyles.Number, inv);
        RoundTrip(value, value.ToString("E40", inv), NumberStyles.Float, inv);
        if (SaneSigns(c.Nfi))
        {
            RoundTrip(value, value.ToString("D", c.Nfi), NumberStyles.Integer, c.Nfi);
        }
    }

    // Round-tripping through fuzzed symbols is only well-defined when the signs can't be confused
    // with digits, whitespace or each other.
    private static bool SaneSigns(NumberFormatInfo nfi) =>
        nfi.NegativeSign.Length > 0 && nfi.PositiveSign.Length > 0 &&
        !nfi.NegativeSign.StartsWith(nfi.PositiveSign, StringComparison.Ordinal) &&
        !nfi.PositiveSign.StartsWith(nfi.NegativeSign, StringComparison.Ordinal) &&
        !(nfi.NegativeSign + nfi.PositiveSign).Any(ch => char.IsAsciiDigit(ch) || char.IsWhiteSpace(ch) || ch == '\0');

    private static void RoundTrip<T>(T value, string text, NumberStyles styles, NumberFormatInfo nfi)
        where T : INumberBase<T>
    {
        bool ok = T.TryParse(text, styles, nfi, out T back);
        Check.That(ok && back == value, $"{typeof(T).Name} {value} formatted as {Check.Show(text)} parses back as {(ok ? back.ToString() : "failure")} (styles={styles})");
        bool ok8 = T.TryParse(Encoding.UTF8.GetBytes(text), styles, nfi, out T back8);
        Check.That(ok8 && back8 == value, $"{typeof(T).Name} {value} formatted as {Check.Show(text)} parses back from UTF-8 as {(ok8 ? back8.ToString() : "failure")}");
    }

    /// <summary>ToString, TryFormat(char) and TryFormat(UTF-8) must agree; short buffers must fail cleanly.</summary>
    internal static void Formats<T>(T value, string? format, IFormatProvider provider)
        where T : ISpanFormattable, IUtf8SpanFormattable
    {
        var str = Outcome<string>.Of(() => value.ToString(format, provider), e => e is FormatException);
        string what = $"{typeof(T).Name} {Check.Show(value)} format={Check.Show(format)}";
        int size = str.Ok ? str.Value!.Length + 16 : 4096;
        var chars = Outcome<string>.Of(() =>
        {
            char[] buffer = new char[size];
            Check.That(value.TryFormat(buffer, out int written, format, provider), $"TryFormat(char) into {size} chars failed for {what}");
            return new string(buffer, 0, written);
        }, e => e is FormatException);
        Check.That(str.SameAs(chars), $"ToString {str} != TryFormat(char) {chars} for {what}");
        if (!str.Ok)
        {
            return;
        }

        string s = str.Value!;
        char[] exact = new char[s.Length];
        Check.That(value.TryFormat(exact, out int n, format, provider) && n == s.Length && exact.AsSpan().SequenceEqual(s), $"TryFormat(char) into exact buffer failed for {what}");
        if (s.Length > 0)
        {
            Check.That(!value.TryFormat(new char[s.Length - 1], out n, format, provider) && n == 0, $"TryFormat(char) into short buffer succeeded for {what}");
        }

        // Known (UTF8FMT-1): UTF-8 formatting throws ArgumentOutOfRangeException from new Rune(char)
        // when a custom format (or a DateTimeFormatInfo pattern it expands to) contains a surrogate.
        byte[] expected = Encoding.UTF8.GetBytes(s);
        var utf8 = Outcome<string>.Of(() =>
        {
            byte[] buffer = new byte[expected.Length + 16];
            Check.That(value.TryFormat(buffer, out int written, format, provider), $"TryFormat(UTF-8) into {buffer.Length} bytes failed for {what}");
            return Encoding.UTF8.GetString(buffer, 0, written);
        }, e => !s_reportKnownIssues && e is ArgumentOutOfRangeException { ParamName: "ch" } && HasSurrogate(format, provider));
        if (!utf8.Ok)
        {
            return;
        }

        Check.That(utf8.Value == s, $"TryFormat(UTF-8) gives {Check.Show(utf8.Value)} but ToString gives {Check.Show(s)} for {what}");
        byte[] bytes = new byte[expected.Length];
        Check.That(value.TryFormat(bytes, out n, format, provider) && n == expected.Length && bytes.AsSpan().SequenceEqual(expected), $"TryFormat(UTF-8) into exact buffer failed (wrote {n} of {expected.Length}) for {what}");
        if (expected.Length > 0)
        {
            Check.That(!value.TryFormat(new byte[expected.Length - 1], out n, format, provider) && n == 0, $"TryFormat(UTF-8) into short buffer succeeded for {what}");
        }
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static bool HasShortAsciiSymbols(NumberFormatInfo nfi) =>
        ((string[])[nfi.NaNSymbol, nfi.PositiveInfinitySymbol, nfi.NegativeInfinitySymbol, nfi.PositiveSign, nfi.NegativeSign,
            nfi.CurrencySymbol, nfi.PercentSymbol, nfi.PerMilleSymbol, nfi.NumberDecimalSeparator, nfi.NumberGroupSeparator,
            nfi.CurrencyDecimalSeparator, nfi.CurrencyGroupSeparator])
        .All(s => s.Length < 16 && System.Text.Ascii.IsValid(s));

    // Whether a surrogate can reach the custom-format literal path: in the format itself or in any
    // DateTimeFormatInfo pattern a standard format expands to.
    private static bool HasSurrogate(string? format, IFormatProvider provider)
    {
        static bool Any(string? s) => s is not null && s.AsSpan().IndexOfAnyInRange('\uD800', '\uDFFF') >= 0;
        if (Any(format))
        {
            return true;
        }

        return provider.GetFormat(typeof(DateTimeFormatInfo)) is DateTimeFormatInfo dtfi &&
            (Any(dtfi.ShortDatePattern) || Any(dtfi.LongDatePattern) || Any(dtfi.ShortTimePattern) || Any(dtfi.LongTimePattern) ||
             Any(dtfi.FullDateTimePattern) || Any(dtfi.MonthDayPattern) || Any(dtfi.YearMonthPattern));
    }

    private static void Floats(Case c)
    {
        var d = ParseAll<double>(c, new FloatComparer<double>());
        var f = ParseAll<float>(c, new FloatComparer<float>());
        var h = ParseAll<Half>(c, new FloatComparer<Half>());
        string what = $"{Check.Show(c.Text)} styles={c.Styles}";
        Check.That(d.Ok == f.Ok && d.Ok == h.Ok && (!d.Ok || (d.Value.Ok == f.Value.Ok && d.Value.Ok == h.Value.Ok)),
            $"double {d} / float {f} / Half {h} disagree on validity of {what}");
        if (d.Ok && d.Value.Ok)
        {
            CheckNarrowing(d.Value.Value, f.Value.Value, what);
            CheckNarrowing(d.Value.Value, h.Value.Value, what);
        }

        double dv = d.Ok && d.Value.Ok ? d.Value.Value : BitConverter.Int64BitsToDouble((long)Check.Hash(c.Utf8));
        float fv = f.Ok && f.Value.Ok ? f.Value.Value : (float)dv;
        Half hv = h.Ok && h.Value.Ok ? h.Value.Value : (Half)dv;
        FloatFormats(dv, c, ["R", "G17", "E16"]);
        FloatFormats(fv, c, ["R", "G9", "E8"]);
        FloatFormats(hv, c, ["R", "G5", "E4"]);
    }

    private static void FloatFormats<T>(T value, Case c, string[] exactFormats)
        where T : IBinaryFloatingPointIeee754<T>
    {
        Formats(value, c.Format, c.Nfi);
        foreach (string standard in (string[])["G", "R", "N", "C", "E", "F", "P", "G3", "F30", "E0", "N20"])
        {
            Formats(value, standard, c.Nfi);
        }

        var inv = NumberFormatInfo.InvariantInfo;
        foreach (string format in exactFormats.Append(""))
        {
            string text = value.ToString(format, inv);
            bool ok = T.TryParse(text, NumberStyles.Float | NumberStyles.AllowThousands, inv, out T back);
            Check.That(ok && SameFloat(value, back), $"{typeof(T).Name} {Bits(value)} formatted with {Check.Show(format)} as {Check.Show(text)} parses back as {(ok ? Bits(back) : "failure")}");
        }
    }

    private static bool SameFloat<T>(T a, T b) where T : IBinaryFloatingPointIeee754<T> =>
        T.IsNaN(a) ? T.IsNaN(b) : a == b && T.IsNegative(a) == T.IsNegative(b);

    private static string Bits<T>(T value) where T : IBinaryFloatingPointIeee754<T> =>
        value.ToString("R", CultureInfo.InvariantCulture) + " (0x" + (value switch
        {
            double d => BitConverter.DoubleToInt64Bits(d).ToString("X16"),
            float f => BitConverter.SingleToInt32Bits(f).ToString("X8"),
            Half h => BitConverter.HalfToInt16Bits(h).ToString("X4"),
            _ => "?",
        }) + ")";

    /// <summary>
    /// A float/Half parse must round the exact decimal value correctly. The double result is within
    /// half a double ulp of it, so the narrow result must equal the double rounded to T, unless the
    /// double lies within a double ulp of a T rounding boundary (where double rounding can differ).
    /// </summary>
    private static void CheckNarrowing<T>(double d, T narrow, string what)
        where T : IBinaryFloatingPointIeee754<T>, IMinMaxValue<T>
    {
        if (double.IsNaN(d))
        {
            Check.That(T.IsNaN(narrow), $"double NaN but {typeof(T).Name} {Bits(narrow)} for {what}");
            return;
        }

        T fromDouble = typeof(T) == typeof(float) ? (T)(object)(float)d : (T)(object)(Half)d;
        if (SameFloat(fromDouble, narrow))
        {
            return;
        }

        double ulp = Math.BitIncrement(Math.Abs(d)) - Math.Abs(d);
        double boundary;
        double n = double.CreateTruncating(narrow);
        if (T.IsInfinity(narrow) || T.IsInfinity(fromDouble))
        {
            double max = double.CreateTruncating(T.MaxValue);
            boundary = max + (max - double.CreateTruncating(T.BitDecrement(T.MaxValue))) / 2;
            Check.That(Math.Abs(Math.Abs(d) - boundary) <= ulp, $"{typeof(T).Name} {Bits(narrow)} vs double {Bits(d)} (overflow boundary) for {what}");
            return;
        }

        T neighbour = n < d ? T.BitIncrement(narrow) : T.BitDecrement(narrow);
        boundary = (n + double.CreateTruncating(neighbour)) / 2;
        Check.That(Math.Abs(d - boundary) <= ulp, $"{typeof(T).Name} parse {Bits(narrow)} is not the rounding of double parse {Bits(d)} (expected {Bits(fromDouble)}) for {what}");
    }

    private sealed class FloatComparer<T> : IEqualityComparer<T> where T : IBinaryFloatingPointIeee754<T>
    {
        public bool Equals(T? x, T? y) => SameFloat(x!, y!);
        public int GetHashCode(T obj) => 0;
    }

    private static void Decimal(Case c)
    {
        var parsed = ParseAll<decimal>(c, new DecimalComparer());
        decimal value = parsed.Ok && parsed.Value.Ok ? parsed.Value.Value : new decimal((int)Check.Hash(c.Utf8), c.Utf8.Length, 7, c.Text.Length % 2 == 0, (byte)(c.Text.Length % 29));
        Formats(value, c.Format, c.Nfi);
        foreach (string standard in (string[])["G", "N", "C", "E", "F", "P", "G3", "F30", "E0", "N20", "R"])
        {
            Formats(value, standard, c.Nfi);
        }

        var inv = NumberFormatInfo.InvariantInfo;
        string text = value.ToString(inv);
        bool ok = decimal.TryParse(text, NumberStyles.Number, inv, out decimal back);
        Check.That(ok && back == value && back.ToString(inv) == text, $"decimal {text} parses back as {(ok ? back.ToString(inv) : "failure")}");
        string e = value.ToString("E28", inv);
        ok = decimal.TryParse(e, NumberStyles.Float, inv, out back);
        Check.That(ok && back == value, $"decimal {text} formatted as {e} parses back as {(ok ? back.ToString(inv) : "failure")}");
    }

    // Same value and same scale (1.0 and 1.00 are equal decimals but format differently).
    private sealed class DecimalComparer : IEqualityComparer<decimal>
    {
        public bool Equals(decimal x, decimal y) => x == y && x.Scale == y.Scale;
        public int GetHashCode(decimal obj) => 0;
    }
}
