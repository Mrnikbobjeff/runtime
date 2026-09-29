#nullable disable warnings
using System.Diagnostics;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes System.Diagnostics.DiagnosticSource context propagation: the W3C and legacy propagators
/// that parse incoming traceparent / tracestate / baggage / Correlation-Context / Request-Id headers,
/// ActivityContext.Parse, W3C id parsing and Activity parent ids.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     low 2 bits: 0 W3C extraction, 1 legacy extraction, 2 W3C inject + extract,
///              3 legacy inject + extract; bits 2-6: which headers are present
///   segments   traceparent, tracestate, baggage, Correlation-Context, Request-Id, then (inject modes)
///              the parent id and up to 6 baggage key / value pairs
/// Checks: the W3C propagator accepts exactly the traceparent values the Trace Context grammar
/// allows and ActivityContext.TryParse accepts what it returns; tracestate validation is idempotent;
/// baggage matches a reference W3C baggage decoder; baggage injected by a propagator is extracted
/// back unchanged (up to the documented trimming); W3C ids round-trip through their string, UTF-8
/// and byte forms.
/// </remarks>
public static class DiagTarget
{
    private static readonly string[] s_headers = ["traceparent", "tracestate", "baggage", "Correlation-Context", "Request-Id"];

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < s_headers.Length; i++)
        {
            string value = input.Segment();
            if ((mode >> (2 + i) & 1) != 0)
            {
                headers[s_headers[i]] = value;
            }
        }

        string what = "headers " + string.Join(", ", headers.Select(h => $"{h.Key}: {Check.Show(h.Value)}"));
        Ids(headers.GetValueOrDefault("traceparent") ?? "", headers.GetValueOrDefault("tracestate"));
        switch (mode & 3)
        {
            case 0:
                ExtractW3C(headers, what);
                break;
            case 1:
                ExtractLegacy(headers, what);
                break;
            default:
                InjectExtract(ref input, (mode & 3) == 2, headers.GetValueOrDefault("tracestate"));
                break;
        }
    }

    private static readonly DistributedContextPropagator.PropagatorGetterCallback s_getter = (object carrier, string name, out string value, out IEnumerable<string> values) =>
    {
        ((Dictionary<string, string>)carrier).TryGetValue(name, out value);
        values = null;
    };

    private static readonly DistributedContextPropagator.PropagatorSetterCallback s_setter = (carrier, name, value) =>
    {
        var headers = (Dictionary<string, string>)carrier;
        Check.That(!headers.ContainsKey(name), $"header {name} set twice");
        Check.That(value.AsSpan().IndexOfAny('\r', '\n') < 0, $"header {name} value {Check.Show(value)} contains a line break");
        headers[name] = value;
    };

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static void ExtractW3C(Dictionary<string, string> headers, string what)
    {
        DistributedContextPropagator propagator = DistributedContextPropagator.CreateW3CPropagator();
        propagator.ExtractTraceIdAndState(headers, s_getter, out string traceId, out string traceState);
        string traceParent = headers.GetValueOrDefault("traceparent");
        bool valid = IsValidTraceParent(traceParent);
        Check.That(valid == traceId is not null, $"traceparent accepted as {Check.Show(traceId)}, expected valid={valid} for {what}");
        if (traceId is not null)
        {
            Check.Equal(traceParent.Substring(0, 55), traceId, $"extracted traceparent for {what}");
            Check.That(ActivityContext.TryParse(traceId, traceState, out ActivityContext context), $"ActivityContext.TryParse rejects extracted {Check.Show(traceId)} for {what}");
            Check.Equal(traceId.Substring(3, 32), context.TraceId.ToHexString(), $"TraceId for {what}");
            Check.Equal(traceId.Substring(36, 16), context.SpanId.ToHexString(), $"SpanId for {what}");
            Check.Equal(Convert.ToByte(traceId.Substring(53, 2), 16), (byte)context.TraceFlags, $"TraceFlags for {what}");
            Check.Equal(traceState, context.TraceState, $"TraceState for {what}");
        }

        if (traceState is not null)
        {
            Check.That(traceState.Length <= 512 && traceState.Split(',').All(IsValidTraceStateMember), $"extracted tracestate {Check.Show(traceState)} isn't valid for {what}");
            var again = new Dictionary<string, string>(headers) { ["tracestate"] = traceState };
            propagator.ExtractTraceIdAndState(again, s_getter, out _, out string traceState2);
            Check.Equal(traceState, traceState2, $"tracestate extracted from the extracted tracestate for {what}");
        }

        List<KeyValuePair<string, string>> baggage = propagator.ExtractBaggage(headers, s_getter)?.ToList() ?? [];
        string header = headers.GetValueOrDefault("baggage") ?? headers.GetValueOrDefault("Correlation-Context");
        List<KeyValuePair<string, string>> expected = ReferenceBaggage(header, out bool exact);
        Check.That(baggage.Count == expected.Count, $"{baggage.Count} baggage entries [{Show(baggage)}], expected [{Show(expected)}] for {what}");
        for (int i = 0; i < expected.Count; i++)
        {
            Check.Equal(expected[i].Key, baggage[i].Key, $"baggage key {i} for {what}");
            string e = expected[i].Value, a = baggage[i].Value;
            // For malformed UTF-8, how many U+FFFD replace a bad sequence isn't specified; the rest must match.
            // Known (DIAG-BAGGAGE-1): a 3-byte sequence's continuation bytes aren't checked, so malformed
            // UTF-8 decodes to other characters ("%E2%41%41" -> U+2041, "%ED%20%80" -> lone U+D800).
            bool same = exact ? e == a : !s_reportKnownIssues || e.Replace("�", "") == a.Replace("�", "");
            Check.That(same, $"baggage value {i} {Check.Show(a)}, expected {Check.Show(e)} for {what}");
        }
    }

    private static void ExtractLegacy(Dictionary<string, string> headers, string what)
    {
        DistributedContextPropagator propagator = DistributedContextPropagator.CreatePreW3CPropagator();
        propagator.ExtractTraceIdAndState(headers, s_getter, out string traceId, out string traceState);
        Check.Equal(headers.GetValueOrDefault("traceparent") ?? headers.GetValueOrDefault("Request-Id"), traceId, $"legacy trace id for {what}");
        Check.Equal(headers.GetValueOrDefault("tracestate"), traceState, $"legacy trace state for {what}");
        foreach (KeyValuePair<string, string> pair in propagator.ExtractBaggage(headers, s_getter) ?? [])
        {
            Check.That(pair.Key is not null && pair.Value is not null, $"legacy baggage entry {Check.Show(pair.Key)}={Check.Show(pair.Value)} for {what}");
        }

        // PassThrough and NoOutput only read headers.
        DistributedContextPropagator.CreatePassThroughPropagator().ExtractTraceIdAndState(headers, s_getter, out _, out _);
        _ = DistributedContextPropagator.CreatePassThroughPropagator().ExtractBaggage(headers, s_getter)?.Count();
    }

    private static void InjectExtract(ref FuzzInput input, bool w3c, string traceState)
    {
        string parentId = input.Segment();
        // Known (DIAG-PARENTID-1): SetParentId accepts any string as a hierarchical id, and the legacy
        // propagator writes the resulting Activity.Id to Request-Id as is, line breaks included.
        if (!s_reportKnownIssues)
        {
            parentId = parentId.Replace('\r', '_').Replace('\n', '_');
        }

        var items = new List<KeyValuePair<string, string>>();
        int total = 0;
        while (input.Remaining > 0 && items.Count < 6)
        {
            string key = input.Segment();
            string value = input.Segment();
            if (value == "\u0001")
            {
                value = null;
            }

            total += key.Length + (value?.Length ?? 0);
            if (total > 700)
            {
                break;
            }

            items.Add(new(key, value));
        }

        using var activity = new Activity("fuzz");
        activity.SetIdFormat(w3c ? ActivityIdFormat.W3C : ActivityIdFormat.Hierarchical);
        if (parentId.Length > 0)
        {
            activity.SetParentId(parentId);
        }

        foreach (KeyValuePair<string, string> item in items)
        {
            activity.AddBaggage(item.Key, item.Value);
        }

        activity.TraceStateString = traceState;
        activity.Start();
        string what = $"activity {Check.Show(activity.Id)} (parent {Check.Show(parentId)}, tracestate {Check.Show(traceState)}) baggage [{Show(items)}]";
        _ = (activity.TraceId.ToHexString(), activity.SpanId.ToHexString(), activity.ParentSpanId.ToHexString(), activity.RootId, activity.ParentId, activity.Recorded);

        DistributedContextPropagator propagator = w3c ? DistributedContextPropagator.CreateW3CPropagator() : DistributedContextPropagator.CreatePreW3CPropagator();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        propagator.Inject(activity, headers, s_setter);
        what += " -> " + string.Join(", ", headers.Select(h => $"{h.Key}: {Check.Show(h.Value)}"));

        propagator.ExtractTraceIdAndState(headers, s_getter, out string traceId, out string state);
        // The W3C propagator only injects W3C ids (a hierarchical parent id makes the activity hierarchical).
        bool injected = !w3c || activity.IdFormat == ActivityIdFormat.W3C;
        if (injected)
        {
            Check.Equal(activity.Id, traceId, $"extracted trace id for {what}");
        }

        List<KeyValuePair<string, string>> extracted = propagator.ExtractBaggage(headers, s_getter)?.ToList() ?? [];
        var expected = new List<KeyValuePair<string, string>>();
        foreach (KeyValuePair<string, string> item in injected ? activity.Baggage : [])
        {
            if (w3c)
            {
                string key = item.Key.Trim(' ', '\t');
                if (key.Length > 0 && key.All(c => char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c)))
                {
                    expected.Add(new(key, Utf8RoundTrip((item.Value ?? "").Trim(' ', '\t'))));
                }
            }
            else if (item.Key.Length > 0 && !string.IsNullOrEmpty(item.Value))
            {
                expected.Add(new(Utf8RoundTrip(item.Key).Trim(' ', '\t'), Utf8RoundTrip(item.Value).Trim(' ', '\t')));
            }
        }

        // Extraction reverses the header order back to the order the baggage was added in.
        expected.Reverse();
        Check.That(expected.SequenceEqual(extracted), $"extracted baggage [{Show(extracted)}], expected [{Show(expected)}] for {what}");
        activity.Stop();
    }

    private static string Utf8RoundTrip(string s) => Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(s));

    private static string Show(List<KeyValuePair<string, string>> pairs) => string.Join(", ", pairs.Select(p => $"{Check.Show(p.Key)}={Check.Show(p.Value)}"));

    /// <summary>W3C ids in their string, UTF-8 and byte forms, and ActivityContext.TryParse against the Trace Context grammar.</summary>
    private static void Ids(string text, string traceState)
    {
        foreach (int length in (int[])[32, 16])
        {
            if (text.Length < length)
            {
                continue;
            }

            string s = text.Substring(0, length);
            bool expected = s.All(char.IsAsciiHexDigitLower) && s.Any(c => c != '0');
            string what = $"{(length == 32 ? "ActivityTraceId" : "ActivitySpanId")} {Check.Show(s)}";
            var fromString = Outcome<string>.Of(() => length == 32 ? ActivityTraceId.CreateFromString(s).ToHexString() : ActivitySpanId.CreateFromString(s).ToHexString(), e => e is ArgumentOutOfRangeException);
            var fromUtf8 = Outcome<string>.Of(() => length == 32 ? ActivityTraceId.CreateFromUtf8String(Encoding.UTF8.GetBytes(s)).ToHexString() : ActivitySpanId.CreateFromUtf8String(Encoding.UTF8.GetBytes(s)).ToHexString(), e => e is ArgumentOutOfRangeException);
            // Known (DIAG-UTF8ID-1): CreateFromUtf8String parses each half with Utf8Parser and ignores how
            // much it consumed, so ids that CreateFromString rejects (a non-hex character, upper case, all
            // zeros) become partly-zero ids instead of throwing (or the documented random id).
            if (s_reportKnownIssues || expected)
            {
                Check.That(fromString.SameAs(fromUtf8), $"CreateFromString {fromString} != CreateFromUtf8String {fromUtf8} for {what}");
            }

            if (fromString.Ok)
            {
                Check.That(fromString.Value == s.ToLowerInvariant() && s.All(char.IsAsciiHexDigit), $"parsed as {Check.Show(fromString.Value)}: {what}");
                byte[] bytes = Convert.FromHexString(s);
                string fromBytes = length == 32 ? ActivityTraceId.CreateFromBytes(bytes).ToHexString() : ActivitySpanId.CreateFromBytes(bytes).ToHexString();
                Check.Equal(fromString.Value, fromBytes, $"CreateFromBytes for {what}");
            }
            else
            {
                Check.That(!expected, $"CreateFromString rejects {what}");
            }
        }

        bool valid = IsValidTraceParent(text) && text.Length == 55;
        bool parsed = ActivityContext.TryParse(text, traceState, out ActivityContext context);
        // Known (DIAG-CONTEXT-1): ActivityContext.TryParse doesn't check the '-' separators of traceparent.
        if (s_reportKnownIssues || !(parsed && !valid && IsValidTraceParent(DashesAt(text))))
        {
            Check.That(parsed == valid, $"ActivityContext.TryParse({Check.Show(text)}) = {parsed}, expected {valid}");
        }

        var parse = Outcome<ActivityContext>.Of(() => ActivityContext.Parse(text, traceState), e => e is ArgumentException);
        Check.That(parse.Ok == parsed && (!parsed || parse.Value == context), $"ActivityContext.Parse {parse} vs TryParse {parsed} for {Check.Show(text)}");
    }

    private static string DashesAt(string text)
    {
        if (text.Length != 55)
        {
            return text;
        }

        char[] chars = text.ToCharArray();
        chars[2] = chars[35] = chars[52] = '-';
        return new string(chars);
    }

    /// <summary>traceparent per W3C Trace Context (version 00 exactly 55 characters; later versions may append "-...").</summary>
    private static bool IsValidTraceParent(string s)
    {
        if (s is null || s.Length < 55)
        {
            return false;
        }

        static bool Hex(string s, int start, int length, bool nonZero) =>
            s.AsSpan(start, length).IndexOfAnyExcept("0123456789abcdef") < 0 && (!nonZero || s.AsSpan(start, length).IndexOfAnyExcept('0') >= 0);

        return Hex(s, 0, 2, false) && s.Substring(0, 2) != "ff" &&
            (s.StartsWith("00", StringComparison.Ordinal) ? s.Length == 55 : s.Length == 55 || s[55] == '-') &&
            s[2] == '-' && s[35] == '-' && s[52] == '-' &&
            Hex(s, 3, 32, true) && Hex(s, 36, 16, true) && Hex(s, 53, 2, false);
    }

    private static bool IsValidTraceStateMember(string member)
    {
        int eq = member.IndexOf('=');
        if (eq <= 0 || eq > 256 || member.Length - eq - 1 is 0 or > 256 || member[^1] == ' ')
        {
            return false;
        }

        string key = member.Substring(0, eq), value = member.Substring(eq + 1);
        return (char.IsAsciiLetterLower(key[0]) || char.IsAsciiDigit(key[0])) &&
            key.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || "_-*/@".Contains(c)) &&
            value.All(c => c is >= ' ' and <= '~' and not ',' and not '=');
    }

    /// <summary>
    /// Baggage entries the W3C propagator should extract: comma-separated key=value entries, key a
    /// token, value percent-decoded as UTF-8 (entries with non-ASCII characters or a malformed escape
    /// are dropped), both trimmed of spaces and tabs, reversed.
    /// </summary>
    private static List<KeyValuePair<string, string>> ReferenceBaggage(string header, out bool exact)
    {
        exact = true;
        var list = new List<KeyValuePair<string, string>>();
        if (string.IsNullOrEmpty(header))
        {
            return list;
        }

        foreach (string entry in header.Split(','))
        {
            int eq = entry.IndexOf('=');
            if (eq <= 0 || eq >= entry.Length - 1)
            {
                continue;
            }

            string key = entry.Substring(0, eq).Trim(' ', '\t');
            string value = entry.Substring(eq + 1).Trim(' ', '\t');
            if (key.Length == 0 || !key.All(c => char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c)) || value.Any(c => c > 0x7F))
            {
                continue;
            }

            var bytes = new List<byte>();
            bool ok = true;
            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] != '%')
                {
                    bytes.Add((byte)value[i]);
                }
                else if (i + 2 < value.Length && char.IsAsciiHexDigit(value[i + 1]) && char.IsAsciiHexDigit(value[i + 2]))
                {
                    bytes.Add(Convert.ToByte(value.Substring(i + 1, 2), 16));
                    i += 2;
                }
                else
                {
                    ok = false;
                    break;
                }
            }

            if (!ok)
            {
                continue;
            }

            byte[] utf8 = bytes.ToArray();
            exact &= System.Text.Unicode.Utf8.IsValid(utf8);
            list.Add(new(key, Encoding.UTF8.GetString(utf8)));
        }

        list.Reverse();
        return list;
    }
}
