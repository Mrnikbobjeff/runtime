#nullable disable warnings
using System.Collections.Specialized;
using System.Net.Mail;
using System.Net.Mime;

namespace SharpFuzzHarness;

/// <summary>Fuzzes the System.Net.Mail / System.Net.Mime header parsers: MailAddress, MailAddressCollection, ContentType, ContentDisposition.</summary>
/// <remarks>
/// Input layout:
///   byte 0     mode % 5: 0 address, 1 address + display name, 2 address list, 3 Content-Type, 4 Content-Disposition
///   segments   the texts
/// Checks: constructors and TryCreate agree and only throw FormatException / ArgumentException;
/// ToString() of a parsed value parses back to the same value; a single address's ToString() adds
/// exactly one address to a MailAddressCollection (a display name can't smuggle in another address).
/// </remarks>
public static class MailTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        string text = input.Segment();
        string second = input.Segment();
        switch (mode % 5)
        {
            case 0:
                Address(text, null);
                break;
            case 1:
                Address(text, second);
                break;
            case 2:
                Collection(text);
                break;
            case 3:
                Mime(text, s => new ContentType(s), c => c.ToString(), c => (c.MediaType, c.Parameters), "ContentType");
                break;
            default:
                Mime(text, s => new ContentDisposition(s), c => c.ToString(), c => (c.DispositionType, c.Parameters), "ContentDisposition");
                if (Outcome<ContentDisposition>.Of(() => new ContentDisposition(text), IsFormatError) is { Ok: true } d)
                {
                    // The date parameters are parsed when read; FormatException is the documented failure.
                    _ = Outcome<object>.Of(() => (d.Value.FileName, d.Value.Inline, d.Value.Size, d.Value.CreationDate, d.Value.ModificationDate, d.Value.ReadDate), IsFormatError);
                }

                break;
        }
    }

    // Known (MAIL-CD-1): ContentDisposition's parser indexes past the end for a trailing parameter
    // without a value ("attachment; x") and throws IndexOutOfRangeException instead of FormatException.
    private static bool IsFormatError(Exception e) => e is FormatException || e.GetType() == typeof(ArgumentException) ||
        !s_reportKnownIssues && e is IndexOutOfRangeException && e.StackTrace?.Contains("ContentDisposition.ParseValue", StringComparison.Ordinal) == true ||
        // Known (MAIL-CD-2): a date parameter with a zone offset beyond +-14 hours throws ArgumentOutOfRangeException.
        !s_reportKnownIssues && e is ArgumentOutOfRangeException && e.StackTrace?.Contains("ValidateOffset", StringComparison.Ordinal) == true;

    private static void Address(string address, string displayName)
    {
        string what = $"MailAddress({Check.Show(address)}, {Check.Show(displayName)})";
        var ctor = Outcome<MailAddress>.Of(() => new MailAddress(address, displayName), IsFormatError);
        bool ok = MailAddress.TryCreate(address, displayName, out MailAddress created);
        Check.That(ctor.Ok == ok && (!ok || Same(ctor.Value, created)), $"ctor {ctor} != TryCreate {ok} for {what}");
        if (ok)
        {
            RoundTrip(created, what);
        }
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    // Known (MAIL-QUOTE-1): ToString() escapes backslashes and quotes in the display name, but parsing a
    // quoted display name keeps its backslashes, so such names gain a layer of escaping on every round trip.
    private static bool Same(MailAddress a, MailAddress b) => a.Address == b.Address && a.User == b.User && a.Host == b.Host &&
        (a.DisplayName == b.DisplayName || !s_reportKnownIssues && a.DisplayName.AsSpan().IndexOfAny((char)92, '"') >= 0);

    private static string Show(MailAddress a) => $"[{Check.Show(a.DisplayName)} <{Check.Show(a.User)}@{Check.Show(a.Host)}>]";

    private static void RoundTrip(MailAddress address, string what)
    {
        _ = (address.GetHashCode(), address.Address);
        string text = address.ToString();
        what = $"{Show(address)} from {what}, ToString {Check.Show(text)}";
        var again = Outcome<MailAddress>.Of(() => new MailAddress(text), IsFormatError);
        Check.That(again.Ok, $"ToString doesn't parse ({again}): {what}");
        Check.That(Same(address, again.Value), $"ToString parses as {Show(again.Value)}: {what}");
        Check.That(address.Equals(again.Value) || !s_reportKnownIssues && address.DisplayName.AsSpan().IndexOfAny((char)92, '"') >= 0, $"Equals after round trip: {what}");

        var list = new MailAddressCollection();
        var added = Outcome<bool>.Of(() => { list.Add(text); return true; }, IsFormatError);
        Check.That(added.Ok && list.Count == 1 && Same(address, list[0]),
            $"MailAddressCollection.Add(ToString) gave {(added.Ok ? string.Join(", ", list.Select(Show)) : added.ToString())}: {what}");
    }

    private static void Collection(string text)
    {
        var list = new MailAddressCollection();
        try
        {
            list.Add(text);
        }
        catch (Exception e) when (IsFormatError(e))
        {
            return;
        }

        string what = $"MailAddressCollection.Add({Check.Show(text)})";
        foreach (MailAddress address in list)
        {
            RoundTrip(address, what);
        }

        string serialized = list.ToString();
        var again = new MailAddressCollection();
        var added = Outcome<bool>.Of(() => { again.Add(serialized); return true; }, IsFormatError);
        Check.That(added.Ok && again.Count == list.Count && list.Zip(again).All(p => Same(p.First, p.Second)),
            $"ToString {Check.Show(serialized)} adds {(added.Ok ? string.Join(", ", again.Select(Show)) : added.ToString())}, expected {string.Join(", ", list.Select(Show))} for {what}");
    }

    private static void Mime<T>(string text, Func<string, T> parse, Func<T, string> format, Func<T, (string Type, StringDictionary Parameters)> parts, string name)
    {
        var parsed = Outcome<T>.Of(() => parse(text), IsFormatError);
        if (!parsed.Ok)
        {
            return;
        }

        string what = $"{name}({Check.Show(text)})";
        (string type, StringDictionary parameters) = parts(parsed.Value);
        string serialized = format(parsed.Value);
        what += $" -> {Check.Show(serialized)}";
        var again = Outcome<T>.Of(() => parse(serialized), IsFormatError);
        Check.That(again.Ok, $"ToString doesn't parse ({again}): {what}");
        (string type2, StringDictionary parameters2) = parts(again.Value);
        Check.Equal(type, type2, $"type after round trip: {what}");
        foreach (string key in parameters.Keys)
        {
            // Known (MAIL-MIME-ENC-1): ToString() writes a parameter value with non-ASCII or control characters
            // as an RFC 2047 encoded-word, which parsing doesn't decode.
            if (!s_reportKnownIssues && parameters[key].Any(c => c is < ' ' or > '~'))
            {
                continue;
            }

            Check.That(parameters2.ContainsKey(key) && parameters2[key] == parameters[key],
                $"parameter {Check.Show(key)}={Check.Show(parameters[key])} after round trip is {Check.Show(parameters2[key])}: {what}");
        }

        Check.Equal(parameters.Count, parameters2.Count, $"parameter count after round trip: {what}");
        // Parameters are a StringDictionary, so ToString's parameter order isn't stable across instances.
    }
}
