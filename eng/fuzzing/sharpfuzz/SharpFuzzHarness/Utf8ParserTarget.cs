#nullable disable warnings
using System.Buffers;
using System.Buffers.Text;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes System.Buffers.Text.Utf8Parser and Utf8Formatter (CoreLib) for every type they support,
/// against the types' own Parse / ToString.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     type (see <see cref="Run"/>)
///   byte 1     format selector
///   byte 2     precision (formatter; 0xFF = none)
///   rest       UTF-8 text to parse; also hashed into a value to format
/// Checks: whatever prefix Utf8Parser consumes means the same value to the type's own parser
/// (T.Parse with the equivalent NumberStyles, Guid/TimeSpan/DateTime.ParseExact); Utf8Formatter
/// writes exactly the bytes of ToString(format, InvariantCulture), fails cleanly on a buffer one byte
/// short, and its output parses back with Utf8Parser, consuming everything.
/// </remarks>
public static class Utf8ParserTarget
{
    private const int MaxLength = 256;
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private delegate bool Parser<T>(ReadOnlySpan<byte> source, out T value, out int consumed, char format);
    private delegate bool Formatter<T>(T value, Span<byte> destination, out int written, StandardFormat format);

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte type = input.Byte();
        byte selector = input.Byte();
        byte precision = input.Byte();
        byte[] text = input.Rest().ToArray();
        if (text.Length > MaxLength)
        {
            return;
        }

        ulong hash = Check.Hash(text);
        switch (type % 15)
        {
            case 0: Integer<sbyte>(text, selector, precision, (sbyte)hash, Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 1: Integer<byte>(text, selector, precision, (byte)hash, Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 2: Integer<short>(text, selector, precision, (short)hash, Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 3: Integer<ushort>(text, selector, precision, (ushort)hash, Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 4: Integer<int>(text, selector, precision, (int)hash, Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 5: Integer<uint>(text, selector, precision, (uint)hash, Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 6: Integer<long>(text, selector, precision, (long)hash, Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 7: Integer<ulong>(text, selector, precision, hash, Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 8: Floating<double>(text, selector, precision, BitConverter.Int64BitsToDouble((long)hash), Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 9: Floating<float>(text, selector, precision, BitConverter.Int32BitsToSingle((int)hash), Utf8Parser.TryParse, Utf8Formatter.TryFormat); break;
            case 10: Decimal(text, selector, precision, hash); break;
            case 11: GuidOps(text, selector, hash); break;
            case 12: TimeSpanOps(text, selector, hash); break;
            case 13: DateTimeOps(text, selector, hash); break;
            default: BoolOps(text, selector, hash); break;
        }
    }

    private static string Ascii(ReadOnlySpan<byte> bytes) => Encoding.Latin1.GetString(bytes);

    private static string What(byte[] text, char format) => $"{Check.Show(Ascii(text))} format '{(format == '\0' ? "default" : format.ToString())}'";

    // ---------------------------------------------------------------------------------------------

    private static void Integer<T>(byte[] text, byte selector, byte precision, T sample, Parser<T> parse, Formatter<T> format)
        where T : IBinaryInteger<T>
    {
        char f = (selector % 5) switch { 0 => '\0', 1 => 'G', 2 => 'D', 3 => 'N', _ => 'X' };
        string what = $"{typeof(T).Name} {What(text, f)}";
        if (parse(text, out T value, out int consumed, f))
        {
            NumberStyles styles = f switch { 'N' => NumberStyles.AllowLeadingSign | NumberStyles.AllowThousands | NumberStyles.AllowDecimalPoint, 'X' => NumberStyles.AllowHexSpecifier, _ => NumberStyles.AllowLeadingSign };
            string prefix = Ascii(text.AsSpan(0, consumed));
            bool ok = T.TryParse(prefix, styles, Inv, out T expected);
            Check.That(consumed > 0 && ok && expected == value, $"Utf8Parser gives {value} for the prefix {Check.Show(prefix)} ({consumed} bytes), {typeof(T).Name}.TryParse gives {(ok ? expected : "failure")}, for {what}");
        }

        foreach (T v in (T[])[value, sample])
        {
            char symbol = (selector / 5 % 5) switch { 0 => 'G', 1 => 'D', 2 => 'N', 3 => 'X', _ => 'x' };
            Formats(v, symbol, precision, format, (x, s) => x.ToString(s, Inv), parse, symbol is 'x' ? 'X' : symbol, exactRoundTrip: symbol is not 'N' || precision is 0xFF or 0);
        }
    }

    private static void Floating<T>(byte[] text, byte selector, byte precision, T sample, Parser<T> parse, Formatter<T> format)
        where T : IBinaryFloatingPointIeee754<T>
    {
        char f = (selector % 4) switch { 0 => '\0', 1 => 'G', 2 => 'E', _ => 'F' };
        string what = $"{typeof(T).Name} {What(text, f)}";
        if (parse(text, out T value, out int consumed, f))
        {
            string prefix = Ascii(text.AsSpan(0, consumed));
            bool ok = T.TryParse(prefix, NumberStyles.Float, Inv, out T expected);

            // Known (UTF8PARSER-FLOAT-1): with zeros after the decimal point, an input exactly halfway
            // between two values is rounded up instead of to even ("63732000000000900.000").
            bool knownTie = !s_reportKnownIssues && ok && prefix.Contains('.') && (value == T.BitIncrement(expected) || value == T.BitDecrement(expected));
            Check.That(consumed > 0 && ok && (knownTie || (T.IsNaN(value) ? T.IsNaN(expected) : expected == value && T.IsNegative(expected) == T.IsNegative(value))),
                $"Utf8Parser gives {value:R} for the prefix {Check.Show(prefix)}, {typeof(T).Name}.TryParse gives {(ok ? expected.ToString("R", Inv) : "failure")}, for {what}");
        }

        foreach (T v in (T[])[value, sample])
        {
            char symbol = (selector / 4 % 3) switch { 0 => 'G', 1 => 'E', _ => 'F' };
            Formats(v, symbol, precision, format, (x, s) => x.ToString(s, Inv), parse, symbol,
                exactRoundTrip: symbol == 'G' && precision == 0xFF, compare: (a, b) => T.IsNaN(a) ? T.IsNaN(b) : a == b);
        }
    }

    private static void Decimal(byte[] text, byte selector, byte precision, ulong hash)
    {
        char f = (selector % 4) switch { 0 => '\0', 1 => 'G', 2 => 'E', _ => 'F' };
        string what = $"Decimal {What(text, f)}";
        if (Utf8Parser.TryParse(text, out decimal value, out int consumed, f))
        {
            string prefix = Ascii(text.AsSpan(0, consumed));
            bool ok = decimal.TryParse(prefix, NumberStyles.Float, Inv, out decimal expected);

            // Known (UTF8PARSER-DECIMAL-1): digits beyond decimal's precision are rounded half away from
            // zero by Utf8Parser but half to even by decimal.Parse, so the last digit can differ by one.
            bool knownMidpoint = !s_reportKnownIssues && ok && Math.Abs(value - expected) == new decimal(1, 0, 0, false, expected.Scale);
            Check.That(consumed > 0 && ok && (knownMidpoint || expected == value),$"Utf8Parser gives {value} for the prefix {Check.Show(prefix)}, decimal.TryParse gives {(ok ? expected : "failure")}, for {what}");
        }

        decimal sample = new((int)hash, (int)(hash >> 32), (int)(hash >> 16), (hash & 1) != 0, (byte)(hash % 29));
        foreach (decimal v in (decimal[])[value, sample])
        {
            char symbol = (selector / 4 % 3) switch { 0 => 'G', 1 => 'E', _ => 'F' };
            Formats(v, symbol, precision, Utf8Formatter.TryFormat, (x, s) => x.ToString(s, Inv), Utf8Parser.TryParse, symbol, exactRoundTrip: symbol == 'G' && precision == 0xFF);
        }
    }

    private static void GuidOps(byte[] text, byte selector, ulong hash)
    {
        char f = (selector % 5) switch { 0 => '\0', 1 => 'D', 2 => 'B', 3 => 'P', _ => 'N' };
        string what = $"Guid {What(text, f)}";
        if (Utf8Parser.TryParse(text, out Guid value, out int consumed, f))
        {
            string prefix = Ascii(text.AsSpan(0, consumed));
            bool ok = Guid.TryParseExact(prefix, f == '\0' ? "D" : f.ToString(), out Guid expected);
            Check.That(ok && expected == value, $"Utf8Parser gives {value} for the prefix {Check.Show(prefix)}, Guid.TryParseExact gives {(ok ? expected : "failure")}, for {what}");
        }

        var sample = new Guid((int)hash, (short)(hash >> 32), (short)(hash >> 48), (byte)hash, (byte)(hash >> 8), 1, 2, 3, 4, 5, (byte)(hash >> 56));
        char symbol = f == '\0' ? 'D' : f;
        foreach (Guid v in (Guid[])[value, sample])
        {
            Formats(v, symbol, 0xFF, Utf8Formatter.TryFormat, (x, s) => x.ToString(s), Utf8Parser.TryParse, symbol, exactRoundTrip: true);
        }
    }

    private static void TimeSpanOps(byte[] text, byte selector, ulong hash)
    {
        char f = (selector % 6) switch { 0 => '\0', 1 => 'c', 2 => 't', 3 => 'T', 4 => 'g', _ => 'G' };
        string what = $"TimeSpan {What(text, f)}";
        if (Utf8Parser.TryParse(text, out TimeSpan value, out int consumed, f))
        {
            string prefix = Ascii(text.AsSpan(0, consumed));
            string net = f is 'g' or 'G' ? f.ToString() : "c";
            bool ok = TimeSpan.TryParseExact(prefix, net, Inv, out TimeSpan expected) || TimeSpan.TryParse(prefix, Inv, out expected);
            Check.That(ok && expected == value, $"Utf8Parser gives {value} for the prefix {Check.Show(prefix)}, TimeSpan.TryParse(Exact) gives {(ok ? expected : "failure")}, for {what}");
        }

        var sample = new TimeSpan((long)hash);
        char symbol = f is '\0' or 't' or 'T' ? 'c' : f;
        foreach (TimeSpan v in (TimeSpan[])[value, sample])
        {
            Formats(v, symbol, 0xFF, Utf8Formatter.TryFormat, (x, s) => x.ToString(s, Inv), Utf8Parser.TryParse, symbol, exactRoundTrip: true);
        }
    }

    private static void DateTimeOps(byte[] text, byte selector, ulong hash)
    {
        char f = (selector % 5) switch { 0 => '\0', 1 => 'G', 2 => 'R', 3 => 'O', _ => 'l' };
        string what = $"DateTime {What(text, f)}";
        if (Utf8Parser.TryParse(text, out DateTime value, out int consumed, f) && f is 'R' or 'O')
        {
            // 'O' results are local or UTC depending on the offset, so compare instants.
            string prefix = Ascii(text.AsSpan(0, consumed));
            bool ok = DateTime.TryParseExact(prefix, f.ToString(), Inv, f == 'O' ? DateTimeStyles.RoundtripKind : DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime expected);
            Check.That(ok && (f == 'O' ? expected.ToUniversalTime() == value.ToUniversalTime() : expected.Ticks == value.Ticks),
                $"Utf8Parser gives {value:O} for the prefix {Check.Show(prefix)}, DateTime.TryParseExact gives {(ok ? expected.ToString("O") : "failure")}, for {what}");
        }

        var sample = new DateTime((long)(hash % (ulong)DateTime.MaxValue.Ticks), (DateTimeKind)(hash % 3));
        char symbol = f == '\0' ? 'G' : f;
        foreach (DateTime v in (DateTime[])[value, sample])
        {
            Formats(v, symbol, 0xFF, Utf8Formatter.TryFormat, (x, s) => s == "l" ? x.ToString("R", Inv).ToLowerInvariant() : x.ToString(s, Inv), Utf8Parser.TryParse, symbol,
                exactRoundTrip: false);
        }
    }

    private static void BoolOps(byte[] text, byte selector, ulong hash)
    {
        char f = (selector % 3) switch { 0 => '\0', 1 => 'G', _ => 'l' };
        if (Utf8Parser.TryParse(text, out bool value, out int consumed, f))
        {
            string prefix = Ascii(text.AsSpan(0, consumed));
            bool ok = bool.TryParse(prefix, out bool expected);
            Check.That(ok && expected == value, $"Utf8Parser gives {value} for the prefix {Check.Show(prefix)}, bool.TryParse gives {(ok ? expected : "failure")}, for bool {What(text, f)}");
        }

        char symbol = f == '\0' ? 'G' : f;
        foreach (bool v in (bool[])[value, (hash & 1) != 0])
        {
            Formats(v, symbol, 0xFF, Utf8Formatter.TryFormat, (x, s) => s == "l" ? x.ToString().ToLowerInvariant() : x.ToString(), Utf8Parser.TryParse, symbol, exactRoundTrip: true);
        }
    }

    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Utf8Formatter must write the bytes of <paramref name="toString"/>, fail cleanly one byte short,
    /// and (with <paramref name="exactRoundTrip"/>) parse back to the same value, consuming everything.
    /// </summary>
    private static void Formats<T>(T value, char symbol, byte precision, Formatter<T> format, Func<T, string, string> toString, Parser<T> parse, char parseFormat,
        bool exactRoundTrip, Func<T, T, bool> compare = null)
    {
        compare ??= EqualityComparer<T>.Default.Equals;
        byte p = precision == 0xFF ? StandardFormat.NoPrecision : (byte)(precision % 100);
        var standard = new StandardFormat(symbol, p);
        string netFormat = symbol + (p == StandardFormat.NoPrecision ? "" : p.ToString(Inv));
        string what = $"{typeof(T).Name} {Check.Show(value)} format {standard}";

        var expected = Outcome<string>.Of(() => toString(value, netFormat), e => e is FormatException);
        byte[] buffer = new byte[512];
        var formatted = Outcome<string>.Of(() => format(value, buffer, out int n, standard) ? Encoding.UTF8.GetString(buffer, 0, n) : null, e => e is FormatException or NotSupportedException);
        if (!formatted.Ok)
        {
            return; // Utf8Formatter supports fewer formats than ToString (no 'N' for floating point, no 'G' with a precision).
        }

        Check.That(formatted.Value is not null, $"Utf8Formatter.TryFormat into 512 bytes failed for {what}");
        Check.That(expected.Ok && formatted.Value == expected.Value, $"Utf8Formatter writes {Check.Show(formatted.Value)}, ToString(\"{netFormat}\") gives {expected} for {what}");
        byte[] exact = new byte[formatted.Value.Length];
        Check.That(format(value, exact, out int written, standard) && written == exact.Length, $"Utf8Formatter.TryFormat into an exact buffer failed for {what}");
        if (exact.Length > 0)
        {
            Check.That(!format(value, new byte[exact.Length - 1], out written, standard) && written == 0, $"Utf8Formatter.TryFormat into a short buffer succeeded (wrote {written}) for {what}");
        }

        if (exactRoundTrip)
        {
            bool ok = parse(exact, out T back, out int consumed, parseFormat);
            Check.That(ok && consumed == exact.Length && compare(back, value),
                $"Utf8Parser reads {Check.Show(formatted.Value)} back as {(ok ? Check.Show(back) : "failure")} (consumed {consumed} of {exact.Length}) for {what}");
        }
    }
}
