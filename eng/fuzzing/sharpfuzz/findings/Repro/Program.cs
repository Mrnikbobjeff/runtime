using System.Reflection;
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
};

Console.WriteLine(System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
foreach (var (id, title, check) in checks)
{
    var (reproduced, observed) = check();
    Console.WriteLine($"{(reproduced ? "REPRODUCED" : "not seen  ")}  {id,-8} {title}\n            -> {observed}");
}

partial class Program
{
    // JsonElement.DeepEquals was added in .NET 9; bind to it dynamically so this also runs on .NET 8.
    static readonly MethodInfo? DeepEquals = typeof(JsonElement).GetMethod("DeepEquals", BindingFlags.Public | BindingFlags.Static);

    static bool CallDeepEquals(string left, string right)
    {
        using JsonDocument a = JsonDocument.Parse(left), b = JsonDocument.Parse(right);
        try { return (bool)DeepEquals!.Invoke(null, [a.RootElement, b.RootElement])!; }
        catch (TargetInvocationException e) { throw e.InnerException!; }
    }
}
