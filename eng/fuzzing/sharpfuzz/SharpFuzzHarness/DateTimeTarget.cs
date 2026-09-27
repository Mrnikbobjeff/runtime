#nullable disable warnings
using System.Globalization;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes DateTime, DateTimeOffset, DateOnly, TimeOnly and TimeSpan parsing and formatting
/// (System.DateTimeParse, System.DateTimeFormat, TimeSpanParse/TimeSpanFormat).
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     low 3 bits: type; 0x08 fuzzed DateTimeFormatInfo; 0x10 multiple exact formats
///   byte 1     DateTimeStyles (all 8 bits) / TimeSpanStyles (bit 0)
///   [DateTimeFormatInfo fields, see <see cref="FormatInfos.DateTime"/>]
///   segment    text to parse
///   segment    format string ('\n' separates formats in multi-format mode)
/// Checks: Parse / TryParse / span overloads agree; ParseExact with one format agrees with the
/// string[] overload; ToString / TryFormat (UTF-16, UTF-8) agree; standard invariant formats
/// round-trip through ParseExact (exactly, for the lossless ones).
/// </remarks>
public static class DateTimeTarget
{
    private const int MaxTextLength = 256;

    private static readonly Type[] s_parseFailures = [typeof(FormatException)];
    private static readonly Type[] s_timeSpanFailures = [typeof(FormatException), typeof(OverflowException)];

    private static bool IsParseError(Exception e) => e is FormatException or ArgumentException or OverflowException;

    private static bool IsArgumentError(Exception e) => e is ArgumentException;

    private sealed record Case(string Text, string Format, string[] Formats, DateTimeFormatInfo Dtfi, DateTimeStyles Styles, TimeSpanStyles TimeSpanStyles, ulong Seed);

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte kind = input.Byte();
        byte styles = input.Byte();
        DateTimeFormatInfo dtfi = FormatInfos.DateTime(ref input, (kind & 0x08) != 0);
        string text = input.Segment();
        string format = input.Segment();
        if (text.Length > MaxTextLength || format.Length > MaxTextLength)
        {
            return;
        }

        string[] formats = (kind & 0x10) != 0 ? format.Split('\n') : [format];
        var c = new Case(text, format, formats, dtfi, (DateTimeStyles)styles, (TimeSpanStyles)(styles & 1), Check.Hash(data));
        switch (kind & 7)
        {
            case 0 or 5: DateTimes(c); break;
            case 1 or 6: DateTimeOffsets(c); break;
            case 2: DateOnlys(c); break;
            case 3: TimeOnlys(c); break;
            default: TimeSpans(c); break;
        }
    }

    private static readonly Check.By<DateTime> s_dateTimeExact = new((a, b) => a.Ticks == b.Ticks && a.Kind == b.Kind);
    private static readonly Check.By<DateTimeOffset> s_offsetExact = new((a, b) => a.EqualsExact(b));

    private static void DateTimes(Case c)
    {
        string what = $"DateTime {Check.Show(c.Text)} styles={c.Styles}";
        Check.ParseAgreement(what, s_dateTimeExact,
            Outcome<DateTime>.Of(() => DateTime.Parse(c.Text, c.Dtfi, c.Styles), IsParseError), s_parseFailures,
            Outcome<(bool, DateTime)>.Of(() => (DateTime.TryParse(c.Text, c.Dtfi, c.Styles, out DateTime v), v), IsArgumentError),
            ("TryParse(span)", Outcome<(bool, DateTime)>.Of(() => (DateTime.TryParse(c.Text.AsSpan(), c.Dtfi, c.Styles, out DateTime v), v), IsArgumentError)));

        var exact = Outcome<(bool, DateTime)>.Of(() => (DateTime.TryParseExact(c.Text, c.Formats, c.Dtfi, c.Styles, out DateTime v), v), IsArgumentError);
        var alternatives = new List<(string, Outcome<(bool, DateTime)>)>
        {
            ("TryParseExact(span, string[])", Outcome<(bool, DateTime)>.Of(() => (DateTime.TryParseExact(c.Text.AsSpan(), c.Formats, c.Dtfi, c.Styles, out DateTime v), v), IsArgumentError)),
        };
        if (c.Formats.Length == 1)
        {
            alternatives.Add(("TryParseExact(string, string)", Outcome<(bool, DateTime)>.Of(() => (DateTime.TryParseExact(c.Text, c.Format, c.Dtfi, c.Styles, out DateTime v), v), IsArgumentError)));
            alternatives.Add(("TryParseExact(span, span)", Outcome<(bool, DateTime)>.Of(() => (DateTime.TryParseExact(c.Text.AsSpan(), c.Format.AsSpan(), c.Dtfi, c.Styles, out DateTime v), v), IsArgumentError)));
        }

        Check.ParseAgreement(what + $" formats={Check.Show(c.Format)}", s_dateTimeExact,
            Outcome<DateTime>.Of(() => DateTime.ParseExact(c.Text, c.Formats, c.Dtfi, c.Styles), IsParseError), s_parseFailures,
            exact, alternatives.ToArray());

        DateTime value = exact.Ok && exact.Value.Item1 ? exact.Value.Item2 : new DateTime((long)(c.Seed % (ulong)DateTime.MaxValue.Ticks), (DateTimeKind)(c.Seed % 3));
        FormatAll(value, c);

        var inv = DateTimeFormatInfo.InvariantInfo;
        string o = value.ToString("O", inv);
        RoundTrip(value, o, s_dateTimeExact, DateTime.ParseExact(o, "O", inv, DateTimeStyles.RoundtripKind), "O");
        RoundTrip(value, o, s_dateTimeExact, DateTime.Parse(o, inv, DateTimeStyles.RoundtripKind), "O via Parse");
        // No "M" (month-day): it parses into the current year, which may not have a Feb 29.
        foreach (string f in (string[])["d", "D", "f", "F", "g", "G", "s", "t", "T", "u", "Y", "R", "yyyy-MM-dd HH:mm:ss.FFFFFFF", "dddd, MMMM d, yyyy h:mm:ss tt"])
        {
            string s = value.ToString(f, inv);
            bool ok = DateTime.TryParseExact(s, f, inv, DateTimeStyles.None, out _);
            Check.That(ok, $"DateTime {o} formatted with {Check.Show(f)} as {Check.Show(s)} doesn't parse back with the same format");
        }
    }

    private static void DateTimeOffsets(Case c)
    {
        string what = $"DateTimeOffset {Check.Show(c.Text)} styles={c.Styles}";
        Check.ParseAgreement(what, s_offsetExact,
            Outcome<DateTimeOffset>.Of(() => DateTimeOffset.Parse(c.Text, c.Dtfi, c.Styles), IsParseError), s_parseFailures,
            Outcome<(bool, DateTimeOffset)>.Of(() => (DateTimeOffset.TryParse(c.Text, c.Dtfi, c.Styles, out DateTimeOffset v), v), IsArgumentError),
            ("TryParse(span)", Outcome<(bool, DateTimeOffset)>.Of(() => (DateTimeOffset.TryParse(c.Text.AsSpan(), c.Dtfi, c.Styles, out DateTimeOffset v), v), IsArgumentError)));

        var exact = Outcome<(bool, DateTimeOffset)>.Of(() => (DateTimeOffset.TryParseExact(c.Text, c.Formats, c.Dtfi, c.Styles, out DateTimeOffset v), v), IsArgumentError);
        var alternatives = new List<(string, Outcome<(bool, DateTimeOffset)>)>
        {
            ("TryParseExact(span, string[])", Outcome<(bool, DateTimeOffset)>.Of(() => (DateTimeOffset.TryParseExact(c.Text.AsSpan(), c.Formats, c.Dtfi, c.Styles, out DateTimeOffset v), v), IsArgumentError)),
        };
        if (c.Formats.Length == 1)
        {
            alternatives.Add(("TryParseExact(string, string)", Outcome<(bool, DateTimeOffset)>.Of(() => (DateTimeOffset.TryParseExact(c.Text, c.Format, c.Dtfi, c.Styles, out DateTimeOffset v), v), IsArgumentError)));
        }

        Check.ParseAgreement(what + $" formats={Check.Show(c.Format)}", s_offsetExact,
            Outcome<DateTimeOffset>.Of(() => DateTimeOffset.ParseExact(c.Text, c.Formats, c.Dtfi, c.Styles), IsParseError), s_parseFailures,
            exact, alternatives.ToArray());

        DateTimeOffset value = exact.Ok && exact.Value.Item1
            ? exact.Value.Item2
            : new DateTimeOffset((long)(c.Seed % (ulong)(DateTime.MaxValue.Ticks - TimeSpan.TicksPerDay)) + TimeSpan.TicksPerDay / 2, TimeSpan.FromMinutes((long)(c.Seed >> 48) % (28 * 60) - 14 * 60));
        FormatAll(value, c);

        var inv = DateTimeFormatInfo.InvariantInfo;
        string o = value.ToString("O", inv);
        RoundTrip(value, o, s_offsetExact, DateTimeOffset.ParseExact(o, "O", inv), "O");
        RoundTrip(value, o, s_offsetExact, DateTimeOffset.Parse(o, inv), "O via Parse");
        foreach (string f in (string[])["d", "D", "f", "F", "g", "G", "s", "t", "T", "u", "Y", "R", "yyyy-MM-dd HH:mm:ss.FFFFFFF zzz"])
        {
            string s = value.ToString(f, inv);
            bool ok = DateTimeOffset.TryParseExact(s, f, inv, DateTimeStyles.AssumeUniversal, out _);
            Check.That(ok, $"DateTimeOffset {o} formatted with {Check.Show(f)} as {Check.Show(s)} doesn't parse back with the same format");
        }
    }

    private static void DateOnlys(Case c)
    {
        string what = $"DateOnly {Check.Show(c.Text)} styles={c.Styles}";
        var eq = EqualityComparer<DateOnly>.Default;
        Check.ParseAgreement(what, eq,
            Outcome<DateOnly>.Of(() => DateOnly.Parse(c.Text, c.Dtfi, c.Styles), IsParseError), s_parseFailures,
            Outcome<(bool, DateOnly)>.Of(() => (DateOnly.TryParse(c.Text, c.Dtfi, c.Styles, out DateOnly v), v), IsArgumentError),
            ("TryParse(span)", Outcome<(bool, DateOnly)>.Of(() => (DateOnly.TryParse(c.Text.AsSpan(), c.Dtfi, c.Styles, out DateOnly v), v), IsArgumentError)));

        var exact = Outcome<(bool, DateOnly)>.Of(() => (DateOnly.TryParseExact(c.Text, c.Formats, c.Dtfi, c.Styles, out DateOnly v), v), IsArgumentError);
        Check.ParseAgreement(what + $" formats={Check.Show(c.Format)}", eq,
            Outcome<DateOnly>.Of(() => DateOnly.ParseExact(c.Text, c.Formats, c.Dtfi, c.Styles), IsParseError), s_parseFailures,
            exact,
            ("TryParseExact(span, string[])", Outcome<(bool, DateOnly)>.Of(() => (DateOnly.TryParseExact(c.Text.AsSpan(), c.Formats, c.Dtfi, c.Styles, out DateOnly v), v), IsArgumentError)));

        DateOnly value = exact.Ok && exact.Value.Item1 ? exact.Value.Item2 : DateOnly.FromDayNumber((int)(c.Seed % (ulong)DateOnly.MaxValue.DayNumber));
        FormatAll(value, c);
        var inv = DateTimeFormatInfo.InvariantInfo;
        foreach (string f in (string[])["O", "R", "d", "D", "Y", "yyyy-MM-dd"])
        {
            string s = value.ToString(f, inv);
            bool ok = DateOnly.TryParseExact(s, f, inv, DateTimeStyles.None, out DateOnly back);
            Check.That(ok && (f is "Y" || back == value), $"DateOnly {value.DayNumber} formatted with {Check.Show(f)} as {Check.Show(s)} parses back as {(ok ? back.DayNumber : "failure")}");
        }
    }

    private static void TimeOnlys(Case c)
    {
        string what = $"TimeOnly {Check.Show(c.Text)} styles={c.Styles}";
        var eq = EqualityComparer<TimeOnly>.Default;
        Check.ParseAgreement(what, eq,
            Outcome<TimeOnly>.Of(() => TimeOnly.Parse(c.Text, c.Dtfi, c.Styles), IsParseError), s_parseFailures,
            Outcome<(bool, TimeOnly)>.Of(() => (TimeOnly.TryParse(c.Text, c.Dtfi, c.Styles, out TimeOnly v), v), IsArgumentError),
            ("TryParse(span)", Outcome<(bool, TimeOnly)>.Of(() => (TimeOnly.TryParse(c.Text.AsSpan(), c.Dtfi, c.Styles, out TimeOnly v), v), IsArgumentError)));

        var exact = Outcome<(bool, TimeOnly)>.Of(() => (TimeOnly.TryParseExact(c.Text, c.Formats, c.Dtfi, c.Styles, out TimeOnly v), v), IsArgumentError);
        Check.ParseAgreement(what + $" formats={Check.Show(c.Format)}", eq,
            Outcome<TimeOnly>.Of(() => TimeOnly.ParseExact(c.Text, c.Formats, c.Dtfi, c.Styles), IsParseError), s_parseFailures,
            exact,
            ("TryParseExact(span, string[])", Outcome<(bool, TimeOnly)>.Of(() => (TimeOnly.TryParseExact(c.Text.AsSpan(), c.Formats, c.Dtfi, c.Styles, out TimeOnly v), v), IsArgumentError)));

        TimeOnly value = exact.Ok && exact.Value.Item1 ? exact.Value.Item2 : new TimeOnly((long)(c.Seed % (ulong)TimeOnly.MaxValue.Ticks));
        FormatAll(value, c);
        var inv = DateTimeFormatInfo.InvariantInfo;
        foreach (string f in (string[])["O", "R", "t", "T", "HH:mm:ss.fffffff"])
        {
            string s = value.ToString(f, inv);
            bool ok = TimeOnly.TryParseExact(s, f, inv, DateTimeStyles.None, out TimeOnly back);
            Check.That(ok && (f is not ("O" or "HH:mm:ss.fffffff") || back == value), $"TimeOnly {value.Ticks} formatted with {Check.Show(f)} as {Check.Show(s)} parses back as {(ok ? back.Ticks : "failure")}");
        }
    }

    private static void TimeSpans(Case c)
    {
        string what = $"TimeSpan {Check.Show(c.Text)}";
        var eq = EqualityComparer<TimeSpan>.Default;
        Check.ParseAgreement(what, eq,
            Outcome<TimeSpan>.Of(() => TimeSpan.Parse(c.Text, c.Dtfi), IsParseError), s_timeSpanFailures,
            Outcome<(bool, TimeSpan)>.Of(() => (TimeSpan.TryParse(c.Text, c.Dtfi, out TimeSpan v), v), IsArgumentError),
            ("TryParse(span)", Outcome<(bool, TimeSpan)>.Of(() => (TimeSpan.TryParse(c.Text.AsSpan(), c.Dtfi, out TimeSpan v), v), IsArgumentError)));

        var exact = Outcome<(bool, TimeSpan)>.Of(() => (TimeSpan.TryParseExact(c.Text, c.Formats, c.Dtfi, c.TimeSpanStyles, out TimeSpan v), v), IsArgumentError);
        var alternatives = new List<(string, Outcome<(bool, TimeSpan)>)>
        {
            ("TryParseExact(span, string[])", Outcome<(bool, TimeSpan)>.Of(() => (TimeSpan.TryParseExact(c.Text.AsSpan(), c.Formats, c.Dtfi, c.TimeSpanStyles, out TimeSpan v), v), IsArgumentError)),
        };
        if (c.Formats.Length == 1)
        {
            alternatives.Add(("TryParseExact(string, string)", Outcome<(bool, TimeSpan)>.Of(() => (TimeSpan.TryParseExact(c.Text, c.Format, c.Dtfi, c.TimeSpanStyles, out TimeSpan v), v), IsArgumentError)));
        }

        Check.ParseAgreement(what + $" formats={Check.Show(c.Format)} styles={c.TimeSpanStyles}", eq,
            Outcome<TimeSpan>.Of(() => TimeSpan.ParseExact(c.Text, c.Formats, c.Dtfi, c.TimeSpanStyles), IsParseError), s_timeSpanFailures,
            exact, alternatives.ToArray());

        TimeSpan value = exact.Ok && exact.Value.Item1 ? exact.Value.Item2 : new TimeSpan((long)c.Seed);
        FormatAll(value, c);
        var inv = DateTimeFormatInfo.InvariantInfo;
        foreach (string f in (string[])["c", "g", "G"])
        {
            string s = value.ToString(f, inv);
            bool ok = TimeSpan.TryParseExact(s, f, inv, out TimeSpan back);
            Check.That(ok && back == value, $"TimeSpan {value.Ticks} formatted with {Check.Show(f)} as {Check.Show(s)} parses back as {(ok ? back.Ticks : "failure")}");
            ok = TimeSpan.TryParse(s, inv, out back);
            Check.That(ok && back == value, $"TimeSpan {value.Ticks} formatted with {Check.Show(f)} as {Check.Show(s)} parses back via TryParse as {(ok ? back.Ticks : "failure")}");
        }
    }

    private static void FormatAll<T>(T value, Case c)
        where T : ISpanFormattable, IUtf8SpanFormattable
    {
        foreach (string format in c.Formats)
        {
            NumberTarget.Formats(value, format, c.Dtfi);
        }

        foreach (string standard in value is TimeSpan ? (string[])["c", "g", "G"] : ["d", "D", "f", "F", "g", "G", "m", "o", "r", "s", "t", "T", "u", "U", "y"])
        {
            NumberTarget.Formats(value, standard, c.Dtfi);
        }
    }

    private static void RoundTrip<T>(T value, string text, IEqualityComparer<T> comparer, T back, string format)
    {
        Check.That(comparer.Equals(value, back), $"{typeof(T).Name} {Check.Show(text)} (format {format}) parses back as {Check.Show(back)}");
    }
}
