using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

// Each check returns (reproduced, observed-behaviour). "reproduced" means the runtime still shows the bug.
var checks = new (string Id, string Title, Func<(bool, string)> Check)[]
{
    ("REGEX-1", "new Regex(\"[^\", ECMAScript) throws IndexOutOfRangeException instead of RegexParseException", () =>
    {
        try { _ = new Regex("[^", RegexOptions.ECMAScript); return (true, "no exception at all"); }
        catch (RegexParseException e) { return (false, $"RegexParseException ({e.Error})"); }
        catch (Exception e) { return (true, e.GetType().FullName!); }
    }),

    ("REGEX-2", "NonBacktracking misses the leftmost match of 0?x in \"0axx\"", () =>
    {
        int bt = Regex.Match("0axx", "0?x").Index;
        int nb = Regex.Match("0axx", "0?x", RegexOptions.NonBacktracking).Index;
        string all = string.Join(",", Regex.Matches("0axx", "0?x", RegexOptions.NonBacktracking).Select(m => $"{m.Index}:{m.Length}"));
        return (bt != nb, $"backtracking index {bt}, NonBacktracking index {nb} (all NB matches: {all})");
    }),

    ("REGEX-3", "NonBacktracking ignores the priority of an empty middle alternation branch: (x||.)h on \"hh\"", () =>
    {
        Match bt = Regex.Match("hh", "(x||.)h");
        Match nb = Regex.Match("hh", "(x||.)h", RegexOptions.NonBacktracking);
        return (bt.Length != nb.Length, $"backtracking {bt.Index}:{bt.Length}, NonBacktracking {nb.Index}:{nb.Length}");
    }),

    ("REGEX-4", "NonBacktracking reports a mandatory group as unmatched: x*(\\Bx) on \"xx\"", () =>
    {
        Match nb = Regex.Match("xx", @"x*(\Bx)", RegexOptions.NonBacktracking);
        return (nb.Success && !nb.Groups[1].Success,
            $"match {nb.Index}:{nb.Length}, Groups[1].Success={nb.Groups[1].Success} (backtracking: '{Regex.Match("xx", @"x*(\Bx)").Groups[1].Value}')");
    }),

    ("REGEX-5", "Match timeout not enforced: (){10000000}x with a 100 ms timeout", () =>
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            bool m = new Regex("(){10000000}x", RegexOptions.None, TimeSpan.FromMilliseconds(100)).IsMatch("x");
            return (sw.ElapsedMilliseconds > 200, $"returned {m} after {sw.ElapsedMilliseconds} ms without RegexMatchTimeoutException");
        }
        catch (RegexMatchTimeoutException) { return (false, $"timed out after {sw.ElapsedMilliseconds} ms"); }
    }),

    ("REGEX-6", "Backtracking engines make \\W+ / -+ atomic before \\B and miss matches: -+\\B on \"--a\"", () =>
    {
        bool interp = Regex.IsMatch("--a", @"-+\B");
        bool compiled = Regex.IsMatch("--a", @"-+\B", RegexOptions.Compiled);
        bool nb = Regex.IsMatch("--a", @"-+\B", RegexOptions.NonBacktracking);
        return (!interp || !compiled, $"interpreter {interp}, Compiled {compiled}, NonBacktracking {nb} (expected true: '-' then \\B between '-' and '-')");
    }),

    ("JSON-1", "JsonElement.DeepEquals throws for numbers whose exponent doesn't fit in an int", () =>
    {
        if (DeepEquals is null) return (false, "JsonElement.DeepEquals not available (< .NET 9)");
        try { bool r = CallDeepEquals("0e99999999999", "0e99999999999"); return (false, $"returned {r}"); }
        catch (Exception e) { return (true, $"{e.GetType().Name}: {e.Message}"); }
    }),

    ("JSON-2", "Out-of-range JSON numbers deserialize to double infinity but can't be serialized back (by design, noted)", () =>
    {
        double d = JsonSerializer.Deserialize<double>("1e400");
        try { JsonSerializer.Serialize(d); return (false, $"deserialized {d}, serialized fine"); }
        catch (ArgumentException) { return (true, $"deserialized {d}; Serialize throws ArgumentException"); }
    }),

    ("JSON-3", "JsonElement.DeepEquals(10e2147483647, 1e-2147483648) returns true (int overflow while normalizing)", () =>
    {
        if (DeepEquals is null) return (false, "JsonElement.DeepEquals not available (< .NET 9)");
        bool r = CallDeepEquals("10e2147483647", "1e-2147483648");
        return (r, $"returned {r}");
    }),

    ("BASE64URL-1", "Base64Url.TryDecodeFromChars(\"QUI\", 1-byte buffer) throws FormatException instead of returning false", () =>
    {
        if (Base64UrlTryDecodeFromChars is null) return (false, "Base64Url not available (< .NET 9)");
        byte[] shortBuffer = new byte[1]; // "QUI" decodes to 2 bytes
        try { bool ok = Base64UrlTryDecodeFromChars("QUI", shortBuffer, out int w); return (false, $"returned {ok}, wrote {w}"); }
        catch (FormatException e) { return (true, $"FormatException: {e.Message}"); }
    }),

    ("HEX-1", "Convert.FromHexString(\"zz\", dst, out consumed, out written) reports charsConsumed=1 for an invalid first char", () =>
    {
        if (FromHexStringStatus is null) return (false, "Convert.FromHexString(span, span, out, out) not available (< .NET 9)");
        var status = FromHexStringStatus("zz", new byte[1], out int consumed, out int written);
        var status2 = FromHexStringStatus("0z", new byte[1], out int consumed2, out _);
        return (consumed != 0, $"\"zz\": {status}, charsConsumed={consumed}, bytesWritten={written}; for comparison \"0z\": {status2}, charsConsumed={consumed2}");
    }),

    ("UTF7-1", "UTF-7 Encoder.Convert with a small output buffer duplicates output: \"ab\\u0100\" into 5-byte chunks", () =>
    {
#pragma warning disable SYSLIB0001
        Encoder encoder = new UTF7Encoding().GetEncoder();
#pragma warning restore SYSLIB0001
        char[] chars = "ab\u0100".ToCharArray();
        var output = new List<byte>();
        byte[] buffer = new byte[5];
        int pos = 0;
        for (int i = 0; i < 10; i++)
        {
            encoder.Convert(chars, pos, chars.Length - pos, buffer, 0, buffer.Length, true, out int used, out int produced, out bool completed);
            output.AddRange(buffer.AsSpan(0, produced).ToArray());
            pos += used;
            if (completed) break;
        }

        string result = Encoding.ASCII.GetString(output.ToArray());
        return (result != "ab+AQA-", $"Convert produced \"{result}\", GetBytes produces \"ab+AQA-\"");
    }),

    ("UTF7-2", "UTF-7 Encoder.Convert never reports completed after a surrogate pair followed by a direct char: \"\\uD83D\\uDE00b\"", () =>
    {
#pragma warning disable SYSLIB0001
        Encoder encoder = new UTF7Encoding().GetEncoder();
#pragma warning restore SYSLIB0001
        char[] chars = "\uD83D\uDE00b".ToCharArray();
        byte[] buffer = new byte[64];
        encoder.Convert(chars, 0, chars.Length, buffer, 0, buffer.Length, true, out int used, out int produced, out bool completed);
        encoder.Convert(chars, chars.Length, 0, buffer, 0, buffer.Length, true, out _, out int produced2, out bool completed2);
        return (!completed2, $"first call: charsUsed={used}/{chars.Length}, bytesUsed={produced}, completed={completed}; flushing again: bytesUsed={produced2}, completed={completed2}");
    }),
};

Console.WriteLine(System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
foreach (var (id, title, check) in checks)
{
    var (reproduced, observed) = check();
    Console.WriteLine($"{(reproduced ? "REPRODUCED" : "not seen  ")}  {id,-8} {title}\n            -> {observed}");
}

partial class Program
{
    delegate bool TryDecodeChars(ReadOnlySpan<char> source, Span<byte> destination, out int bytesWritten);
    delegate System.Buffers.OperationStatus HexStatus(ReadOnlySpan<char> source, Span<byte> destination, out int charsConsumed, out int bytesWritten);

    // .NET 9+ APIs, bound dynamically so this also runs on .NET 8.
    static readonly TryDecodeChars? Base64UrlTryDecodeFromChars = typeof(object).Assembly.GetType("System.Buffers.Text.Base64Url")
        ?.GetMethod("TryDecodeFromChars", [typeof(ReadOnlySpan<char>), typeof(Span<byte>), typeof(int).MakeByRefType()])?.CreateDelegate<TryDecodeChars>();

    static readonly HexStatus? FromHexStringStatus = typeof(Convert)
        .GetMethod("FromHexString", [typeof(ReadOnlySpan<char>), typeof(Span<byte>), typeof(int).MakeByRefType(), typeof(int).MakeByRefType()])?.CreateDelegate<HexStatus>();

    // JsonElement.DeepEquals was added in .NET 9; bind to it dynamically so this also runs on .NET 8.
    static readonly MethodInfo? DeepEquals = typeof(JsonElement).GetMethod("DeepEquals", BindingFlags.Public | BindingFlags.Static);

    static bool CallDeepEquals(string left, string right)
    {
        using JsonDocument a = JsonDocument.Parse(left), b = JsonDocument.Parse(right);
        try { return (bool)DeepEquals!.Invoke(null, [a.RootElement, b.RootElement])!; }
        catch (TargetInvocationException e) { throw e.InnerException!; }
    }
}
