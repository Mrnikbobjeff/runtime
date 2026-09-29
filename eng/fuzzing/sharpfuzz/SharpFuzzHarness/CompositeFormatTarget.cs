#nullable disable warnings
using System.Globalization;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes composite formatting: CompositeFormat, string.Format, StringBuilder.AppendFormat, TryWrite.</summary>
/// <remarks>
/// Input layout:
///   byte 0     low 3 bits: argument count (0-7); 0x08 custom ICustomFormatter provider;
///              0x10 fuzzed NumberFormatInfo
///   byte 1..n  argument kinds (see <see cref="MakeArgument"/>)
///   [NumberFormatInfo fields]
///   segment    format string
///   segments   argument texts
/// Checks: CompositeFormat.Parse rejects a format exactly when string.Format does for syntax
/// reasons; given enough arguments every API produces the same string; with too few they all
/// throw FormatException; TryWrite fails cleanly on short buffers.
/// </remarks>
public static class CompositeFormatTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte header = input.Byte();
        int argCount = header & 7;
        byte[] kinds = input.Bytes(argCount).ToArray();
        NumberFormatInfo nfi = FormatInfos.Number(ref input, (header & 0x10) != 0);
        IFormatProvider provider = (header & 0x08) != 0 ? new CustomProvider(nfi) : nfi;
        string format = input.Segment();
        if (format.Length > 512)
        {
            return;
        }

        // Known (COMPOSITEFORMAT-1): CompositeFormat.Parse doesn't enforce string.Format's 1,000,000
        // limits on the index and alignment, so they overflow int: "{4294967297}" formats argument 1,
        // others throw IndexOutOfRangeException or allocate huge alignments. Numbers that long are also
        // how "X999999999"-style precisions allocate gigabytes, so skip them altogether.
        if (!s_reportKnownIssues && HasLongDigitRun(format, 7))
        {
            return;
        }

        object?[] args = new object?[argCount];
        for (int i = 0; i < argCount; i++)
        {
            args[i] = MakeArgument(i < kinds.Length ? kinds[i] : (byte)0, input.Segment());
        }

        string what = $"format {Check.Show(format)} with {argCount} args [{string.Join(", ", args.Select(a => a?.GetType().Name ?? "null"))}]";
        Func<Exception, bool> formatError = e => e is FormatException;
        var formatted = Outcome<string>.Of(() => string.Format(provider, format, args), formatError);
        var parsed = Outcome<CompositeFormat>.Of(() => CompositeFormat.Parse(format), formatError);
        var builder = Outcome<string>.Of(() => new StringBuilder("x").AppendFormat(provider, format, args).ToString().Substring(1), formatError);
        Check.That(formatted.SameAs(builder), $"string.Format {formatted} != StringBuilder.AppendFormat {builder} for {what}");
        var spanArgs = Outcome<string>.Of(() => string.Format(provider, format, (ReadOnlySpan<object?>)args), formatError);
        Check.That(formatted.SameAs(spanArgs), $"string.Format(object[]) {formatted} != string.Format(ReadOnlySpan<object>) {spanArgs} for {what}");
        var writer = Outcome<string>.Of(() =>
        {
            var sw = new StringWriter(provider);
            sw.Write(format, args);
            return sw.ToString();
        }, formatError);
        Check.That(formatted.SameAs(writer), $"string.Format {formatted} != StringWriter.Write {writer} for {what}");

        if (!parsed.Ok)
        {
            Check.That(!formatted.Ok, $"CompositeFormat.Parse rejects {what} ({parsed}) but string.Format gives {formatted}");
            return;
        }

        CompositeFormat cf = parsed.Value!;
        Check.Equal(format, cf.Format, $"CompositeFormat.Format for {what}");
        bool enough = argCount >= cf.MinimumArgumentCount;
        // With enough arguments string.Format can still fail, but only because an argument rejects
        // its format string (int with "Q", ...), which the CompositeFormat overloads must repeat.
        Check.That(enough || !formatted.Ok, $"string.Format {formatted} but CompositeFormat.MinimumArgumentCount is {cf.MinimumArgumentCount} for {what}");

        var viaCf = Outcome<string>.Of(() => string.Format(provider, cf, args), formatError);
        Check.That(formatted.SameAs(viaCf), $"string.Format(string) {formatted} != string.Format(CompositeFormat) {viaCf} for {what}");
        var builderCf = Outcome<string>.Of(() => new StringBuilder().AppendFormat(provider, cf, args).ToString(), formatError);
        Check.That(formatted.SameAs(builderCf), $"string.Format {formatted} != AppendFormat(CompositeFormat) {builderCf} for {what}");
        if (argCount <= 3)
        {
            var generic = Outcome<string>.Of(() => argCount switch
            {
                0 => string.Format(provider, cf, args),
                1 => string.Format(provider, cf, args[0]),
                2 => string.Format(provider, cf, args[0], args[1]),
                _ => string.Format(provider, cf, args[0], args[1], args[2]),
            }, formatError);
            Check.That(formatted.SameAs(generic), $"string.Format {formatted} != generic string.Format<...>(CompositeFormat) {generic} for {what}");
        }

        if (formatted.Ok)
        {
            string expected = formatted.Value!;
            char[] exact = new char[expected.Length];
            Check.That(exact.AsSpan().TryWrite(provider, cf, out int written, args) && written == expected.Length && exact.AsSpan().SequenceEqual(expected),
                $"TryWrite(CompositeFormat) into an exact buffer != string.Format {Check.Show(expected)} for {what}");
            if (expected.Length > 0)
            {
                Check.That(!new char[expected.Length - 1].AsSpan().TryWrite(provider, cf, out written, args), $"TryWrite(CompositeFormat) into a short buffer succeeded for {what}");
            }
        }
    }

    /// <summary>Argument kinds: value types, strings, null, and formattables that echo what they're asked.</summary>
    private static object? MakeArgument(byte kind, string text) => (kind % 16) switch
    {
        0 => text,
        1 => null,
        2 => int.TryParse(text, CultureInfo.InvariantCulture, out int i) ? i : text.Length - 7,
        3 => double.TryParse(text, CultureInfo.InvariantCulture, out double d) ? d : -text.Length / 3.0,
        4 => decimal.TryParse(text, CultureInfo.InvariantCulture, out decimal m) ? m : 12.50m,
        5 => new DateTime(2024, 2, 29, 13, 45, 7, 123, DateTimeKind.Utc).AddDays(text.Length),
        6 => new Echo(text),
        7 => new SpanEcho(text),
        8 => text.Length % 2 == 0,
        9 => text.Length > 0 ? text[0] : '\0',
        10 => (long)text.Length << 40,
        11 => TimeSpan.FromTicks(text.Length * 123456789L),
        12 => DayOfWeek.Friday,
        13 => new Guid(0x01234567, 0x89ab, 0xcdef, 1, 2, 3, 4, 5, 6, 7, (byte)text.Length),
        14 => new object[] { text },
        _ => (Half)text.Length,
    };

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static bool HasLongDigitRun(string s, int length)
    {
        int run = 0;
        foreach (char c in s)
        {
            run = char.IsAsciiDigit(c) ? run + 1 : 0;
            if (run >= length)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>IFormattable that echoes the format string it receives.</summary>
    /// <remarks>
    /// Known (COMPOSITEFORMAT-2): for an empty item format ("{0:}") string.Format passes null and
    /// CompositeFormat passes "", so null is only shown as such when known issues are reported.
    /// </remarks>
    private sealed class Echo(string text) : IFormattable
    {
        public string ToString(string? format, IFormatProvider? formatProvider) => $"<{text}|{format ?? (s_reportKnownIssues ? "null" : "")}>";
        public override string ToString() => $"<{text}>";
    }

    /// <summary>ISpanFormattable that echoes its format and reports "too small" until the buffer fits.</summary>
    private readonly struct SpanEcho(string text) : ISpanFormattable
    {
        public string ToString(string? format, IFormatProvider? formatProvider) => $"[{text}|{format}]";

        public bool TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
        {
            string s = ToString(format.ToString(), provider);
            if (s.Length > destination.Length)
            {
                charsWritten = 0;
                return false;
            }

            s.CopyTo(destination);
            charsWritten = s.Length;
            return true;
        }
    }

    /// <summary>Provider with an ICustomFormatter: composite formatting must consult it for every hole.</summary>
    private sealed class CustomProvider(NumberFormatInfo nfi) : IFormatProvider, ICustomFormatter
    {
        public object? GetFormat(Type? formatType) => formatType == typeof(ICustomFormatter) ? this : formatType == typeof(NumberFormatInfo) ? nfi : null;

        public string Format(string? format, object? arg, IFormatProvider? formatProvider) =>
            arg is int or string or null ? $"{{{format}:{arg}}}" : arg is IFormattable f ? f.ToString(format, nfi) : arg.ToString() ?? "";
    }
}
