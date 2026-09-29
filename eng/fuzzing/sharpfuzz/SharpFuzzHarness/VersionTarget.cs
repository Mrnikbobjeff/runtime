#nullable disable warnings
using System.Globalization;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Version parsing, formatting and comparison.</summary>
/// <remarks>
/// Input layout: segment (text to parse) '\0' segment (second version, for comparisons).
/// Checks: Parse / TryParse / span / UTF-8 overloads and the constructor agree with each other
/// and with a reference parser (2-4 '.'-separated components, each an int.Parse(Integer,
/// invariant) value >= 0); ToString(n) / TryFormat(n) (UTF-16, UTF-8) agree and round-trip;
/// CompareTo and the operators agree with component-wise comparison.
/// </remarks>
public static class VersionTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte[] utf8 = input.SegmentBytes().ToArray();
        string text = Encoding.UTF8.GetString(utf8);
        string second = input.Segment();
        if (text.Length > 256 || second.Length > 256)
        {
            return;
        }

        Version? v = CheckParse(text, utf8);
        Version? w = CheckParse(second, Encoding.UTF8.GetBytes(second));
        if (v is not null)
        {
            CheckFormat(v);
        }

        if (v is not null && w is not null)
        {
            int expected = Math.Sign(Components(v).Zip(Components(w), (a, b) => a.CompareTo(b)).FirstOrDefault(x => x != 0));
            Check.Equal(expected, Math.Sign(v.CompareTo(w)), $"Version.CompareTo({v}, {w})");
            Check.That((v < w) == (expected < 0) && (v > w) == (expected > 0) && (v <= w) == (expected <= 0) && (v >= w) == (expected >= 0) && (v == w) == (expected == 0) && v.Equals(w) == (expected == 0),
                $"Version operators disagree with component comparison for {v}, {w}");
        }
    }

    private static int[] Components(Version v) => [v.Major, v.Minor, v.Build, v.Revision];

    private static Version? CheckParse(string text, byte[] utf8)
    {
        var eq = EqualityComparer<Version>.Default;
        string what = $"Version {Check.Show(text)}";
        var tryParse = Outcome<(bool, Version)>.Of(() => (Version.TryParse(text, out Version? v), v!), _ => false);
        var alternatives = new List<(string, Outcome<(bool, Version)>)>
        {
            ("TryParse(span)", Outcome<(bool, Version)>.Of(() => (Version.TryParse(text.AsSpan(), out Version? v), v!), _ => false)),
        };
        if (System.Text.Unicode.Utf8.IsValid(utf8))
        {
            alternatives.Add(("TryParse(UTF-8)", Outcome<(bool, Version)>.Of(() => (Version.TryParse(utf8.AsSpan(), out Version? v), v!), _ => false)));
        }

        Type[] failures = [typeof(ArgumentException), typeof(ArgumentOutOfRangeException), typeof(FormatException), typeof(OverflowException)];
        var parse = Outcome<Version>.Of(() => Version.Parse(text), e => failures.Contains(e.GetType()));
        Check.ParseAgreement(what, eq, parse, failures, tryParse, alternatives.ToArray());
        var ctor = Outcome<Version>.Of(() => new Version(text), e => failures.Contains(e.GetType()));
        Check.That(ctor.SameAs(parse), $"new Version(string) {ctor} != Version.Parse {parse} for {what}");

        Version? reference = Reference(text);
        Check.That(tryParse.Value.Item1 == reference is not null && (reference is null || reference == tryParse.Value.Item2),
            $"Version.TryParse {tryParse} but reference parser gives {reference?.ToString() ?? "failure"} for {what}");
        return tryParse.Value.Item1 ? tryParse.Value.Item2 : null;
    }

    private static Version? Reference(string text)
    {
        string[] parts = text.Split('.');
        if (parts.Length is < 2 or > 4)
        {
            return null;
        }

        int[] values = new int[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out values[i]) || values[i] < 0)
            {
                return null;
            }
        }

        return values.Length switch
        {
            2 => new Version(values[0], values[1]),
            3 => new Version(values[0], values[1], values[2]),
            _ => new Version(values[0], values[1], values[2], values[3]),
        };
    }

    private static void CheckFormat(Version v)
    {
        int defined = v.Revision >= 0 ? 4 : v.Build >= 0 ? 3 : 2;
        NumberTarget.Formats(v, null, CultureInfo.InvariantCulture);
        Check.That(Version.Parse(v.ToString()) == v, $"Version {v} doesn't round-trip");
        for (int n = 0; n <= 5; n++)
        {
            var s = Outcome<string>.Of(() => v.ToString(n), e => e is ArgumentException);
            Check.That(s.Ok == (n <= defined), $"Version {v}.ToString({n}) gave {s}");
            char[] chars = new char[64];
            var t = Outcome<string>.Of(() => v.TryFormat(chars, n, out int written) ? new string(chars, 0, written) : null!, e => e is ArgumentException);
            Check.That(s.SameAs(t), $"Version {v}.ToString({n}) {s} != TryFormat {t}");
            byte[] bytes = new byte[64];
            var u = Outcome<string>.Of(() => v.TryFormat(bytes, n, out int written) ? Encoding.UTF8.GetString(bytes, 0, written) : null!, e => e is ArgumentException);
            Check.That(s.SameAs(u), $"Version {v}.ToString({n}) {s} != TryFormat(UTF-8) {u}");
            if (s.Ok && s.Value!.Length > 0)
            {
                Check.That(!v.TryFormat(new char[s.Value.Length - 1], n, out _), $"Version {v}.TryFormat({n}) into a short buffer succeeded");
                if (n >= 2)
                {
                    Check.That(Version.Parse(s.Value) == new Version(s.Value), $"Version {v}.ToString({n}) = {s.Value} doesn't parse");
                }
            }
        }
    }
}
