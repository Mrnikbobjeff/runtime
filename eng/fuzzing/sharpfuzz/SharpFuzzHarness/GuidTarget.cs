#nullable disable warnings
using System.Globalization;

namespace SharpFuzzHarness;

/// <summary>Fuzzes Guid parsing, formatting and byte conversions.</summary>
/// <remarks>
/// Input layout:
///   byte 0     0x01: also compare against the GUID made from the 16 bytes that follow
///   [16 bytes] (only with 0x01)
///   segment    text to parse
///   segment    format string
/// Checks: Parse / TryParse / span / UTF-8 / IFormatProvider overloads and the constructor agree;
/// Parse accepts exactly what ParseExact accepts for one of N, D, B, P, X, with the same value;
/// every format round-trips through Parse and ParseExact; ToString / TryFormat (UTF-16, UTF-8)
/// agree; byte conversions round-trip; CompareTo and the operators order like ToString("N").
/// </remarks>
public static class GuidTarget
{
    private static readonly string[] s_formats = ["N", "D", "B", "P", "X"];

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        Guid other = (flags & 1) != 0 && input.Remaining >= 16 ? new Guid(input.Bytes(16)) : Guid.Empty;
        byte[] utf8 = input.SegmentBytes().ToArray();
        string text = System.Text.Encoding.UTF8.GetString(utf8);
        string format = input.Segment();
        if (text.Length > 256 || format.Length > 16)
        {
            return;
        }

        var eq = EqualityComparer<Guid>.Default;
        string what = $"Guid {Check.Show(text)}";
        var tryParse = Outcome<(bool, Guid)>.Of(() => (Guid.TryParse(text, out Guid g), g), _ => false);
        var alternatives = new List<(string, Outcome<(bool, Guid)>)>
        {
            ("TryParse(span)", Outcome<(bool, Guid)>.Of(() => (Guid.TryParse(text.AsSpan(), out Guid g), g), _ => false)),
            ("TryParse(string, provider)", Outcome<(bool, Guid)>.Of(() => (Guid.TryParse(text, CultureInfo.InvariantCulture, out Guid g), g), _ => false)),
        };
        if (System.Text.Unicode.Utf8.IsValid(utf8))
        {
            alternatives.Add(("TryParse(UTF-8)", Outcome<(bool, Guid)>.Of(() => (Guid.TryParse(utf8.AsSpan(), out Guid g), g), _ => false)));
        }

        Check.ParseAgreement(what, eq, Outcome<Guid>.Of(() => Guid.Parse(text), e => e is FormatException), [typeof(FormatException)], tryParse, alternatives.ToArray());
        var ctor = Outcome<Guid>.Of(() => new Guid(text), e => e is FormatException);
        Check.That(ctor.Ok == tryParse.Value.Item1 && (!ctor.Ok || ctor.Value == tryParse.Value.Item2), $"new Guid(string) {ctor} disagrees with TryParse {tryParse} for {what}");

        // Parse must accept exactly the union of the ParseExact formats.
        bool anyExact = false;
        foreach (string f in s_formats)
        {
            bool ok = Guid.TryParseExact(text, f, out Guid exact);
            bool okLower = Guid.TryParseExact(text.AsSpan(), f.ToLowerInvariant(), out Guid exactLower);
            Check.That(ok == okLower && exact == exactLower, $"TryParseExact {f} and {f.ToLowerInvariant()} disagree for {what}");
            var parseExact = Outcome<Guid>.Of(() => Guid.ParseExact(text, f), e => e is FormatException);
            Check.That(parseExact.Ok == ok && (!ok || parseExact.Value == exact), $"ParseExact({f}) {parseExact} disagrees with TryParseExact for {what}");
            if (ok)
            {
                anyExact = true;
                Check.That(tryParse.Value.Item1 && tryParse.Value.Item2 == exact, $"ParseExact({f}) accepted {what} as {exact} but TryParse gave {tryParse}");
            }
        }

        Check.That(anyExact == tryParse.Value.Item1, $"TryParse {tryParse} but no ParseExact format accepts {what}");

        var inputFormat = Outcome<Guid>.Of(() => Guid.ParseExact(text, format), e => e is FormatException or ArgumentException);
        _ = inputFormat;

        Guid value = tryParse.Value.Item1 ? tryParse.Value.Item2 : new Guid(BitConverter.GetBytes(Check.Hash(utf8)).Concat(BitConverter.GetBytes(Check.Hash(data))).ToArray());
        CheckValue(value, format);
        if ((flags & 1) != 0)
        {
            CheckValue(other, format);
            CheckOrder(value, other);
        }
    }

    private static void CheckValue(Guid value, string format)
    {
        var inv = CultureInfo.InvariantCulture;
        NumberTarget.Formats(value, format, inv);
        foreach (string f in s_formats.Concat(["n", "d", "b", "p", "x", ""]))
        {
            NumberTarget.Formats(value, f, inv);
            string s = value.ToString(f);
            Check.That(Guid.TryParse(s, out Guid back) && back == value, $"Guid {value} formatted with {Check.Show(f)} as {Check.Show(s)} doesn't parse back");
            Check.That(Guid.TryParseExact(s, f.Length == 0 ? "D" : f, out back) && back == value, $"Guid {value} formatted with {Check.Show(f)} as {Check.Show(s)} doesn't ParseExact back");
        }

        byte[] little = value.ToByteArray();
        byte[] big = value.ToByteArray(bigEndian: true);
        Check.Equal(value, new Guid(little), "new Guid(ToByteArray())");
        Check.Equal(value, new Guid(big, bigEndian: true), "new Guid(ToByteArray(bigEndian), bigEndian)");
        Check.Equal(value.ToString("N"), Convert.ToHexString(big).ToLowerInvariant(), "ToString(N) vs big-endian bytes");
        Span<byte> buffer = stackalloc byte[16];
        Check.That(value.TryWriteBytes(buffer, bigEndian: true, out int written) && written == 16 && buffer.SequenceEqual(big), "TryWriteBytes(bigEndian)");
        Check.That(!value.TryWriteBytes(buffer.Slice(1), bigEndian: false, out written) && written == 0, "TryWriteBytes into 15 bytes succeeded");
        _ = value.Version + value.Variant;
    }

    private static void CheckOrder(Guid a, Guid b)
    {
        int expected = Math.Sign(string.CompareOrdinal(a.ToString("N"), b.ToString("N")));
        Check.Equal(expected, Math.Sign(a.CompareTo(b)), $"Guid.CompareTo({a}, {b})");
        Check.Equal(expected, Math.Sign(a.CompareTo((object)b)), $"Guid.CompareTo(object) ({a}, {b})");
        Check.That((a < b) == (expected < 0) && (a > b) == (expected > 0) && (a <= b) == (expected <= 0) && (a >= b) == (expected >= 0) && (a == b) == (expected == 0),
            $"Guid comparison operators disagree with CompareTo for {a}, {b}");
    }
}
