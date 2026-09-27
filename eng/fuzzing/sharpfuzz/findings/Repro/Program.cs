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

    ("COMPOSITEFORMAT-1", "CompositeFormat.Parse(\"{4294967297}\") accepts an index string.Format rejects, and formats argument 1", () =>
    {
        string viaString;
        try { viaString = string.Format(null, "{4294967297}", "a", "b"); } catch (FormatException) { viaString = "FormatException"; }
        try
        {
            var cf = System.Text.CompositeFormat.Parse("{4294967297}");
            string viaCf = string.Format(null, cf, "a", "b");
            return (true, $"string.Format: {viaString}; CompositeFormat: MinimumArgumentCount={cf.MinimumArgumentCount}, formats as \"{viaCf}\"");
        }
        catch (FormatException) { return (false, $"string.Format: {viaString}; CompositeFormat.Parse: FormatException"); }
    }),

    ("COMPOSITEFORMAT-2", "For \"{0:}\" string.Format passes format null to IFormattable, CompositeFormat passes \"\"", () =>
    {
        var echo = new EchoFormat();
        string viaString = string.Format(null, "{0:}", echo);
        string viaCf = string.Format(null, System.Text.CompositeFormat.Parse("{0:}"), echo);
        return (viaString != viaCf, $"string.Format gives {viaString}, CompositeFormat gives {viaCf}");
    }),

    ("TIMESPAN-1", "TimeSpan.TryParse(\"0:0:0.0000000123456789\") throws IndexOutOfRangeException", () =>
    {
        try { bool ok = TimeSpan.TryParse("0:0:0.0000000123456789", System.Globalization.CultureInfo.InvariantCulture, out TimeSpan t); return (false, $"returned {ok} ({t})"); }
        catch (IndexOutOfRangeException) { return (true, "IndexOutOfRangeException"); }
    }),

    ("BASE64-STREAM-1", "Base64.DecodeFromUtf8 with isFinalBlock: false returns InvalidData for valid input with whitespace", () =>
    {
        byte[] input = Encoding.ASCII.GetBytes("S\r\nGVsbG8gV29y"); // "Hello Wor"
        byte[] output = new byte[32];
        var first = System.Buffers.Text.Base64.DecodeFromUtf8(input.AsSpan(0, 7), output, out int consumed, out int written, isFinalBlock: false);
        var oneShot = System.Buffers.Text.Base64.DecodeFromUtf8(input, output, out _, out int all, isFinalBlock: true);
        return (first == System.Buffers.OperationStatus.InvalidData,
            $"first 7 bytes with isFinalBlock=false: {first} (consumed {consumed}, written {written}); whole input in one call: {oneShot} ({all} bytes)");
    }),

    ("RESOURCES-1", "A 206-byte .resources file with numResources = 0x10000000 makes ResourceReader allocate ~1 GB", () =>
    {
        var ms = new MemoryStream();
        using (var w = new System.Resources.ResourceWriter(ms)) { w.AddResource("key", "value"); w.Generate(); }
        byte[] file = ms.ToArray();
        var br = new BinaryReader(new MemoryStream(file));
        br.ReadInt32(); br.ReadInt32(); int skip = br.ReadInt32(); br.BaseStream.Seek(skip + 4, SeekOrigin.Current);
        BitConverter.GetBytes(0x10000000).CopyTo(file, (int)br.BaseStream.Position); // numResources
        long before = GC.GetTotalAllocatedBytes(precise: true);
        string result;
        try { using var reader = new System.Resources.ResourceReader(new MemoryStream(file)); result = "no exception"; }
        catch (Exception e) { result = e.GetType().Name; }
        long allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
        return (allocated > 100_000_000, $"{file.Length}-byte file: {result} after allocating {allocated / (1 << 20)} MB");
    }),

    ("NUMBER-NEGZERO-1", "uint.TryParse accepts \"-0\" and \"-0e5\" but rejects \"-0.0\" with NumberStyles.Float", () =>
    {
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        string R(string s) => uint.TryParse(s, System.Globalization.NumberStyles.Float, inv, out uint v) ? v.ToString() : "false";
        bool signed = int.TryParse("-0.0", System.Globalization.NumberStyles.Float, inv, out _);
        return (R("-0.0") == "false" && R("-0") == "0", $"\"-0\": {R("-0")}, \"-0e5\": {R("-0e5")}, \"-0.0\": {R("-0.0")} (int.TryParse(\"-0.0\"): {signed})");
    }),

    ("LINQ-SUM-1", "Enumerable.Sum(int[32]) throws OverflowException although the sum (-2) and every running sum fit", () =>
    {
        var x = new int[32];
        x[0] = int.MinValue; x[1] = int.MaxValue; x[8] = -1;
        var shorter = x[..31];
        string R(int[] a) { try { return a.Sum().ToString(); } catch (OverflowException) { return "OverflowException"; } }
        string full = R(x);
        return (full == "OverflowException", $"int[32]: {full}; same values as int[31]: {R(shorter)} (Vector<int>.Count = {System.Numerics.Vector<int>.Count}, accelerated = {System.Numerics.Vector.IsHardwareAccelerated})");
    }),
};

Console.WriteLine(System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
foreach (var (id, title, check) in checks)
{
    var (reproduced, observed) = check();
    Console.WriteLine($"{(reproduced ? "REPRODUCED" : "not seen  ")}  {id,-8} {title}\n            -> {observed}");
}

sealed class EchoFormat : IFormattable
{
    public string ToString(string? format, IFormatProvider? formatProvider) => format is null ? "<null>" : $"<\"{format}\">";
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
