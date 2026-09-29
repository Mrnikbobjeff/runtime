#nullable disable warnings
using System.Text;
using System.Text.RegularExpressions;

namespace SharpFuzzHarness;

/// <summary>
/// The regex engines (interpreter, RegexOptions.Compiled, NonBacktracking) over input spans that sit
/// against a guard page (see <see cref="Guarded"/>): anchors, \b and lookarounds peek at the characters
/// around a position, and the vectorized searches read ahead, so a read one character past the input
/// faults. The span APIs (IsMatch, Count, EnumerateMatches, EnumerateSplits) are compared with the
/// string APIs on the same Regex, also on a prefix of the input (where a peek past the end reads the
/// rest of the string rather than faulting, so only the results show it).
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     engine (bits 0-1: interpreter, Compiled, NonBacktracking) and options (bit 2 IgnoreCase,
///              3 Multiline, 4 Singleline, 5 RightToLeft, 6 ExplicitCapture, 7 CultureInvariant)
///   byte 1     bit 0 input at the start of a slot; bits 1-7 the start position / prefix length
///   segment    the pattern (up to 200 chars)
///   rest       the input, UTF-8 (up to 4096 chars)
/// </remarks>
public static class UnsafeRegexTarget
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(500);

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        byte place = input.Byte();
        string pattern = input.Segment();
        string text = Encoding.UTF8.GetString(input.Rest());
        if (pattern.Length > 200 || text.Length > 4096)
        {
            return;
        }

        RegexOptions options = (flags & 3) switch { 1 => RegexOptions.Compiled, 2 or 3 => RegexOptions.NonBacktracking, _ => RegexOptions.None };
        options |= (flags & 0x04) != 0 ? RegexOptions.IgnoreCase : 0;
        options |= (flags & 0x08) != 0 ? RegexOptions.Multiline : 0;
        options |= (flags & 0x10) != 0 ? RegexOptions.Singleline : 0;
        options |= (flags & 0x20) != 0 && (flags & 2) == 0 ? RegexOptions.RightToLeft : 0;
        options |= (flags & 0x40) != 0 ? RegexOptions.ExplicitCapture : 0;
        options |= (flags & 0x80) != 0 ? RegexOptions.CultureInvariant : 0;

        Regex regex;
        try
        {
            regex = new Regex(pattern, options, s_timeout);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or InsufficientExecutionStackException)
        {
            return;
        }

        string what = $"/{Check.Show(pattern)}/ {options} on {Check.Show(text)}";
        bool atStart = (place & 1) != 0;
        int k = Math.Min(text.Length, place >> 1);
        try
        {
            Compare(regex, text, Guarded.Copy<char>(text.AsSpan(), atStart), 0, what);
            // A prefix: the guarded copy ends where the prefix ends.
            string prefix = text[..(text.Length - k)];
            Compare(regex, prefix, Guarded.Copy<char>(prefix.AsSpan(), !atStart), 0, $"prefix of {prefix.Length}: {what}");
            // A start position inside the full input.
            if ((options & RegexOptions.RightToLeft) == 0)
            {
                Compare(regex, text, Guarded.Copy<char>(text.AsSpan(), atStart), k, $"startat {k}: {what}");
            }
        }
        catch (RegexMatchTimeoutException)
        {
        }
    }

    private static void Compare(Regex regex, string text, ReadOnlySpan<char> span, int startat, string what)
    {
        // Without a start position the overloads start at the beginning (or the end, right to left).
        MatchCollection matches = startat == 0 ? regex.Matches(text) : regex.Matches(text, startat);
        var expected = new List<(int, int)>();
        foreach (Match m in matches)
        {
            expected.Add((m.Index, m.Length));
            if (expected.Count > 200)
            {
                return;
            }
        }

        var actual = new List<(int, int)>();
        foreach (ValueMatch m in startat == 0 ? regex.EnumerateMatches(span) : regex.EnumerateMatches(span, startat))
        {
            actual.Add((m.Index, m.Length));
            if (actual.Count > 200)
            {
                break;
            }
        }

        Check.That(actual.SequenceEqual(expected), $"EnumerateMatches(span) [{string.Join(" ", actual.Take(20))}] vs Matches(string) [{string.Join(" ", expected.Take(20))}]: {what}");
        Check.Equal(startat == 0 ? regex.IsMatch(text) : regex.IsMatch(text, startat), startat == 0 ? regex.IsMatch(span) : regex.IsMatch(span, startat), $"IsMatch(span): {what}");
        if (startat == 0)
        {
            Check.Equal(expected.Count, regex.Count(span), $"Count(span): {what}");
            if ((regex.Options & RegexOptions.RightToLeft) == 0 && expected.All(m => m.Item2 > 0))
            {
                // Split without captures in the pattern: the ranges between matches.
                var ranges = new List<string>();
                foreach (Range r in regex.EnumerateSplits(span))
                {
                    ranges.Add(new string(span[r]));
                }

                if (regex.GetGroupNumbers().Length == 1)
                {
                    Check.That(ranges.SequenceEqual(regex.Split(text)), $"EnumerateSplits(span) [{string.Join("|", ranges.Take(20).Select(Check.Show))}] vs Split(string): {what}");
                }
            }
        }
    }
}
