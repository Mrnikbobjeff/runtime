using System.Text;
using System.Text.RegularExpressions;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes System.Text.RegularExpressions: parser, interpreter, RegexCompiler and
/// the NonBacktracking engine, with differential checks between the engines.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     RegexOptions bits (see <see cref="MapOptions"/>)
///   byte 1     engine / API selection bits
///   rest       UTF-8 text: pattern '\0' input ['\0' replacement]
/// </remarks>
public static class RegexTarget
{
    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private const int MaxPatternLength = 256;
    private const int MaxInputLength = 1024;
    private const int MaxMatches = 256;
    private static readonly TimeSpan s_timeout = TimeSpan.FromMilliseconds(250);

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 3)
        {
            return;
        }

        RegexOptions options = MapOptions(data[0]);
        byte selector = data[1];
        string text = Encoding.UTF8.GetString(data.Slice(2));

        string pattern, input, replacement;
        int sep = text.IndexOf('\0');
        if (sep < 0)
        {
            pattern = text;
            input = text;
            replacement = "$0";
        }
        else
        {
            pattern = text.Substring(0, sep);
            input = text.Substring(sep + 1);
            int sep2 = input.IndexOf('\0');
            if (sep2 < 0)
            {
                replacement = "[$&]";
            }
            else
            {
                replacement = input.Substring(sep2 + 1);
                input = input.Substring(0, sep2);
            }
        }

        if (pattern.Length > MaxPatternLength || input.Length > MaxInputLength)
        {
            return;
        }

        // Regex.Escape must always produce a pattern that matches the original text literally.
        if ((selector & 0x80) != 0)
        {
            CheckEscape(input);
            return;
        }

        Regex interpreter;
        try
        {
            interpreter = new Regex(pattern, options, s_timeout);
        }
        catch (ArgumentException)
        {
            // Invalid pattern (RegexParseException) or invalid option combination.
            return;
        }
        catch (InsufficientExecutionStackException)
        {
            // Deeply nested pattern; the engine bails out deliberately instead of overflowing.
            return;
        }
        catch (IndexOutOfRangeException) when (!s_reportKnownIssues && (options & RegexOptions.ECMAScript) != 0 && pattern.EndsWith("[^", StringComparison.Ordinal))
        {
            // Known: ECMAScript pattern ending in "[^" reads past the end of the pattern (FINDINGS.md, REGEX-1).
            return;
        }

        Result? baseline = Execute(interpreter, input, replacement, captures: true);
        if (baseline is null)
        {
            return; // timed out
        }

        if ((selector & 0x01) != 0)
        {
            Regex compiled = new Regex(pattern, options | RegexOptions.Compiled, s_timeout);
            Result? other = Execute(compiled, input, replacement, captures: true);
            if (other is not null)
            {
                Compare("Compiled", pattern, options, input, baseline, other);
            }
        }

        if ((selector & 0x02) != 0 && (options & (RegexOptions.RightToLeft | RegexOptions.ECMAScript)) == 0)
        {
            Regex nonBacktracking;
            try
            {
                nonBacktracking = new Regex(pattern, options | RegexOptions.NonBacktracking, s_timeout);
            }
            catch (NotSupportedException)
            {
                // Backreferences, lookarounds, atomic groups, conditionals, ... aren't supported.
                return;
            }

            // NonBacktracking capture semantics are documented to differ, so only compare overall matches.
            Result? other = Execute(nonBacktracking, input, replacement, captures: false);
            if (other is not null)
            {
                Compare("NonBacktracking", pattern, options, input, baseline with { Groups = null }, other);
            }
        }
    }

    private static RegexOptions MapOptions(byte b)
    {
        RegexOptions options = RegexOptions.None;
        if ((b & 0x01) != 0) options |= RegexOptions.IgnoreCase;
        if ((b & 0x02) != 0) options |= RegexOptions.Multiline;
        if ((b & 0x04) != 0) options |= RegexOptions.ExplicitCapture;
        if ((b & 0x08) != 0) options |= RegexOptions.Singleline;
        if ((b & 0x10) != 0) options |= RegexOptions.IgnorePatternWhitespace;
        if ((b & 0x20) != 0) options |= RegexOptions.RightToLeft;
        if ((b & 0x40) != 0) options |= RegexOptions.CultureInvariant;
        if ((b & 0x80) != 0)
        {
            // ECMAScript may only be combined with IgnoreCase, Multiline and CultureInvariant.
            options = (options & (RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)) | RegexOptions.ECMAScript;
        }
        return options;
    }

    private sealed record Result(
        bool IsMatch,
        int Count,
        List<(int Index, int Length)> Matches,
        List<string>? Groups,
        string? Replaced,
        string[] Split,
        List<(int Index, int Length)> Enumerated);

    private static Result? Execute(Regex regex, string input, string replacement, bool captures)
    {
        try
        {
            bool isMatch = regex.IsMatch(input);
            int count = regex.Count(input);

            var matches = new List<(int, int)>();
            List<string>? groups = captures ? new List<string>() : null;
            Match m = regex.Match(input);
            while (m.Success && matches.Count < MaxMatches)
            {
                matches.Add((m.Index, m.Length));
                if (groups is not null)
                {
                    groups.Add(DescribeGroups(regex, m));
                }
                m = m.NextMatch();
            }

            var enumerated = new List<(int, int)>();
            foreach (ValueMatch vm in regex.EnumerateMatches(input))
            {
                if (enumerated.Count == MaxMatches)
                {
                    break;
                }
                enumerated.Add((vm.Index, vm.Length));
            }

            string? replaced;
            try
            {
                replaced = regex.Replace(input, replacement);
            }
            catch (ArgumentException)
            {
                replaced = null; // invalid replacement pattern
            }

            string[] split = regex.Split(input);

            var result = new Result(isMatch, count, matches, groups, replaced, split, enumerated);
            CheckSelfConsistency(regex, input, result);
            return result;
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }
    }

    private static string DescribeGroups(Regex regex, Match m)
    {
        var sb = new StringBuilder();
        foreach (Group g in m.Groups)
        {
            sb.Append(g.Name).Append('=');
            if (g.Success)
            {
                sb.Append(g.Index).Append(':').Append(g.Length);
            }
            else
            {
                sb.Append('-');
            }
            sb.Append('[');
            foreach (Capture c in g.Captures)
            {
                sb.Append(c.Index).Append(':').Append(c.Length).Append(',');
            }
            sb.Append("] ");
        }
        return sb.ToString();
    }

    /// <summary>Checks that the different APIs on a single Regex instance agree with each other.</summary>
    private static void CheckSelfConsistency(Regex regex, string input, Result r)
    {
        if (r.Matches.Count >= MaxMatches)
        {
            return;
        }

        if (r.IsMatch != (r.Matches.Count > 0))
        {
            Fail(regex, input, $"IsMatch={r.IsMatch} but Match found {r.Matches.Count} matches");
        }

        if (r.Count != r.Matches.Count)
        {
            Fail(regex, input, $"Count={r.Count} but Match/NextMatch found {r.Matches.Count} matches");
        }

        if (!r.Enumerated.SequenceEqual(r.Matches))
        {
            Fail(regex, input, $"EnumerateMatches {Format(r.Enumerated)} != Match/NextMatch {Format(r.Matches)}");
        }

        foreach ((int index, int length) in r.Matches)
        {
            if (index < 0 || length < 0 || index + length > input.Length)
            {
                Fail(regex, input, $"match out of range: {index}:{length}");
            }
        }
    }

    private static void Compare(string engine, string pattern, RegexOptions options, string input, Result expected, Result actual)
    {
        if (expected.Matches.Count >= MaxMatches || actual.Matches.Count >= MaxMatches)
        {
            return;
        }

        string? diff = null;
        if (expected.IsMatch != actual.IsMatch) diff = $"IsMatch {expected.IsMatch} vs {actual.IsMatch}";
        else if (!expected.Matches.SequenceEqual(actual.Matches)) diff = $"matches {Format(expected.Matches)} vs {Format(actual.Matches)}";
        else if (expected.Groups is not null && actual.Groups is not null && !expected.Groups.SequenceEqual(actual.Groups))
            diff = $"groups\n  interpreter: {string.Join(" | ", expected.Groups)}\n  {engine}: {string.Join(" | ", actual.Groups)}";
        else if (expected.Replaced != actual.Replaced) diff = $"Replace {Quote(expected.Replaced)} vs {Quote(actual.Replaced)}";
        else if (!expected.Split.SequenceEqual(actual.Split)) diff = $"Split [{string.Join(",", expected.Split.Select(Quote))}] vs [{string.Join(",", actual.Split.Select(Quote))}]";

        if (diff is not null)
        {
            throw new ConsistencyException(
                $"Interpreter vs {engine} mismatch for pattern {Quote(pattern)} options {options} input {Quote(input)}: {diff}");
        }
    }

    private static void CheckEscape(string text)
    {
        string escaped = Regex.Escape(text);
        var regex = new Regex("^" + escaped + "$", RegexOptions.None, s_timeout);
        Match m = regex.Match(text);
        if (!m.Success || m.Length != text.Length)
        {
            throw new ConsistencyException($"Regex.Escape({Quote(text)}) = {Quote(escaped)} does not match the original text");
        }

        string unescaped = Regex.Unescape(escaped);
        if (unescaped != text)
        {
            throw new ConsistencyException($"Regex.Unescape(Regex.Escape({Quote(text)})) = {Quote(unescaped)}");
        }
    }

    private static void Fail(Regex regex, string input, string message) =>
        throw new ConsistencyException($"pattern {Quote(regex.ToString())} options {regex.Options} input {Quote(input)}: {message}");

    private static string Format(List<(int Index, int Length)> matches) =>
        "[" + string.Join(",", matches.Select(m => $"{m.Index}:{m.Length}")) + "]";

    internal static string Quote(string? s)
    {
        if (s is null)
        {
            return "<null>";
        }

        var sb = new StringBuilder("\"");
        foreach (char c in s)
        {
            if (c is >= ' ' and < (char)0x7F && c != '"' && c != '\\')
            {
                sb.Append(c);
            }
            else
            {
                sb.Append($"\\u{(int)c:X4}");
            }
        }
        return sb.Append('"').ToString();
    }
}
