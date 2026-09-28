#nullable disable warnings
using System.Collections.Specialized;
using System.Net;
using System.Text;
using System.Web;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Web.HttpUtility and System.Net.WebUtility: HTML, attribute, JavaScript and URL encoding, and query strings.</summary>
/// <remarks>
/// Input layout:
///   byte 0     low 2 bits: 0 text, 1 UTF-16LE text, 2 query string, 3 bytes
///   rest       the text (or bytes)
/// Checks: encoder output can't break out of its context (no raw markup characters in HTML /
/// attribute encoding, no quotes, markup characters, backslashes or line terminators in
/// JavaScriptStringEncode, only URL-safe characters in UrlEncode / UrlPathEncode) and decodes back to
/// the input; HttpUtility and WebUtility decode alike; ParseQueryString(q.ToString()) gives q back.
/// </remarks>
public static class HttpUtilityTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        ReadOnlySpan<byte> rest = input.Rest();
        if (rest.Length > 2048)
        {
            return;
        }

        string text = (mode & 3) == 1 ? Encoding.Unicode.GetString(rest.Slice(0, rest.Length & ~1)) : Encoding.UTF8.GetString(rest);
        switch (mode & 3)
        {
            case 0 or 1:
                Html(text);
                JavaScript(text);
                Url(text);
                break;
            case 2:
                Query(text);
                break;
            default:
                Bytes(rest.ToArray());
                break;
        }
    }

    private static bool HasLoneSurrogate(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(s[i]))
            {
                return true;
            }
        }

        return false;
    }

    private static void Html(string s)
    {
        string what = $"text {Check.Show(s)}";
        bool clean = !HasLoneSurrogate(s);
        foreach ((string name, string encoded, string forbidden) in (ValueTuple<string, string, string>[])
            [("WebUtility.HtmlEncode", WebUtility.HtmlEncode(s), "<>\"'"), ("HttpUtility.HtmlEncode", HttpUtility.HtmlEncode(s), "<>\"'"), ("HttpUtility.HtmlAttributeEncode", HttpUtility.HtmlAttributeEncode(s), "<\"'")])
        {
            int bad = encoded.AsSpan().IndexOfAny(forbidden);
            Check.That(bad < 0, $"{name} output {Check.Show(encoded)} has a raw '{(bad >= 0 ? encoded[bad] : ' ')}' for {what}");
            for (int i = encoded.IndexOf('&'); i >= 0; i = encoded.IndexOf('&', i + 1))
            {
                int semicolon = encoded.IndexOf(';', i);
                Check.That(semicolon > i + 1 && semicolon - i <= 10, $"{name} output {Check.Show(encoded)} has a bare '&' at {i} for {what}");
            }

            if (clean)
            {
                Check.Equal(s, WebUtility.HtmlDecode(encoded), $"HtmlDecode({name}) for {what}");
            }
        }

        Check.Equal(WebUtility.HtmlDecode(s), HttpUtility.HtmlDecode(s), $"WebUtility vs HttpUtility HtmlDecode of {what}");
        var writer = new StringWriter();
        HttpUtility.HtmlEncode(s, writer);
        Check.Equal(HttpUtility.HtmlEncode(s), writer.ToString(), $"HtmlEncode to a TextWriter for {what}");
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static void JavaScript(string s)
    {
        foreach (bool quotes in (bool[])[false, true])
        {
            string encoded = HttpUtility.JavaScriptStringEncode(s, quotes);
            string what = $"JavaScriptStringEncode({Check.Show(s)}, {quotes}) = {Check.Show(encoded)}";
            string body = quotes ? encoded[1..^1] : encoded;
            Check.That(!quotes || encoded.Length >= 2 && encoded[0] == '"' && encoded[^1] == '"', $"not quoted: {what}");
            Check.Equal(s, JsUnescape(body, what), $"unescaping {what}");
        }
    }

    /// <summary>Decodes a JavaScript string literal body; every backslash must start a valid escape.</summary>
    private static string JsUnescape(string body, string what)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < body.Length; i++)
        {
            if (body[i] != (char)92)
            {
                // Outside escapes: no quotes, markup characters, line terminators or control characters.
                Check.That(body[i] >= ' ' && body[i] is not ((char)34 or (char)39 or '<' or '>' or '&' or (char)0x2028 or (char)0x2029),
                    $"raw U+{(int)body[i]:X4} at {i} in the output: {what}");
                sb.Append(body[i]);
                continue;
            }

            Check.That(i + 1 < body.Length, $"trailing backslash: {what}");
            char c = body[++i];
            switch (c)
            {
                case 'b': sb.Append('\b'); break;
                case 'f': sb.Append('\f'); break;
                case 'n': sb.Append('\n'); break;
                case 'r': sb.Append('\r'); break;
                case 't': sb.Append('\t'); break;
                case '"' or '\\' or '/' or '\'': sb.Append(c); break;
                case 'u':
                    Check.That(i + 4 < body.Length && body.AsSpan(i + 1, 4).IndexOfAnyExcept("0123456789abcdefABCDEF") < 0, $"bad \\u escape at {i}: {what}");
                    sb.Append((char)Convert.ToInt32(body.Substring(i + 1, 4), 16));
                    i += 4;
                    break;
                default:
                    Check.That(false, $"unknown escape \\{c} at {i}: {what}");
                    break;
            }
        }

        return sb.ToString();
    }

    private static bool IsUrlSafe(char c) => char.IsAsciiLetterOrDigit(c) || "-_.!*()%+".Contains(c);

    private static void Url(string s)
    {
        string what = $"text {Check.Show(s)}";
        bool clean = !HasLoneSurrogate(s);
        foreach ((string name, string encoded) in (ValueTuple<string, string>[])[("HttpUtility.UrlEncode", HttpUtility.UrlEncode(s)), ("WebUtility.UrlEncode", WebUtility.UrlEncode(s))])
        {
            Check.That(encoded.All(IsUrlSafe), $"{name} output {Check.Show(encoded)} has an unsafe character for {what}");
            if (clean)
            {
                Check.Equal(s, HttpUtility.UrlDecode(encoded), $"HttpUtility.UrlDecode({name}) for {what}");
                Check.Equal(s, WebUtility.UrlDecode(encoded), $"WebUtility.UrlDecode({name}) for {what}");
            }
        }

        // UrlPathEncode only encodes the part before '?'.
        string path = HttpUtility.UrlPathEncode(s);
        int query = path.IndexOf('?');
        // For an absolute URL (or UNC path) only the path is encoded, not the authority.
        string pathPart = Uri.TryCreate(s, UriKind.Absolute, out _) ? "" : query < 0 ? path : path[..query];
        // Known (HTTPUTIL-PATH-1): DEL (U+007F) is left unencoded while other control characters are encoded.
        Check.That(!pathPart.Any(c => c <= ' ' || c > 0x7F || c == 0x7F && s_reportKnownIssues), $"UrlPathEncode output {Check.Show(path)} has an unsafe character in the path for {what}");

        // %uXXXX is an HttpUtility extension; otherwise the two decoders agree.
        if (!s.Contains("%u", StringComparison.OrdinalIgnoreCase) && !s.Contains("%U", StringComparison.Ordinal))
        {
            Check.Equal(WebUtility.UrlDecode(s), HttpUtility.UrlDecode(s), $"WebUtility vs HttpUtility UrlDecode of {what}");
        }
    }

    private static void Bytes(byte[] bytes)
    {
        string what = $"bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 64)))}";
        byte[] encoded = HttpUtility.UrlEncodeToBytes(bytes);
        Check.That(encoded.All(b => IsUrlSafe((char)b)), $"UrlEncodeToBytes output has an unsafe byte for {what}");
        Check.That(HttpUtility.UrlDecodeToBytes(encoded).AsSpan().SequenceEqual(bytes), $"UrlDecodeToBytes(UrlEncodeToBytes) for {what}");
        byte[] web = WebUtility.UrlEncodeToBytes(bytes, 0, bytes.Length);
        Check.That(WebUtility.UrlDecodeToBytes(web, 0, web.Length).AsSpan().SequenceEqual(bytes), $"WebUtility byte round trip for {what}");
        _ = HttpUtility.UrlDecodeToBytes(bytes);
        _ = HttpUtility.UrlDecode(bytes, Encoding.UTF8);
        _ = WebUtility.UrlDecodeToBytes(bytes, 0, bytes.Length);
    }

    private static void Query(string s)
    {
        NameValueCollection q = HttpUtility.ParseQueryString(s);
        string serialized = q.ToString();
        string what = $"ParseQueryString({Check.Show(s)}).ToString() = {Check.Show(serialized)}";
        // Known (HTTPUTIL-QS-1): an empty name ("=x") is written without its '=', so it parses back as a
        // value without a name, merged with any other such values.
        if (!s_reportKnownIssues && q.AllKeys.Contains(""))
        {
            return;
        }

        NameValueCollection again = HttpUtility.ParseQueryString(serialized);
        Check.Equal(q.Count, again.Count, $"key count after round trip: {what}");
        foreach (string key in q.AllKeys)
        {
            string[] a = q.GetValues(key) ?? [], b = again.GetValues(key) ?? [];
            // Lone surrogates don't survive UTF-8.
            if (!HasLoneSurrogate(key ?? "") && !a.Any(HasLoneSurrogate))
            {
                Check.That(a.SequenceEqual(b), $"values of {Check.Show(key)}: [{string.Join(", ", a.Select(Check.Show))}] vs [{string.Join(", ", b.Select(Check.Show))}]: {what}");
            }
        }
    }
}
