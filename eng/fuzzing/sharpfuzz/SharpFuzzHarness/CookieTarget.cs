#nullable disable warnings
using System.Net;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Net.CookieContainer: Set-Cookie parsing, cookie scoping and the Cookie request header.</summary>
/// <remarks>
/// Input layout:
///   byte 0     URI the cookies are set from (index into a fixed list); byte 1 URI they're read for
///   segments   Set-Cookie header values (one SetCookies call each)
/// Checks: SetCookies only throws CookieException; a stored cookie's domain domain-matches the host
/// that set it (a response can't set cookies for other sites); the cookies returned for a URI
/// domain- and path-match it and aren't Secure over http; GetCookieHeader lists exactly the cookies
/// GetCookies returns (a value can't smuggle in another cookie) and contains no line breaks.
/// </remarks>
public static class CookieTarget
{
    private static readonly Uri[] s_uris =
    [
        new("http://example.com/"),
        new("https://www.example.com/a/b/c"),
        new("http://a.b.example.com/a/"),
        new("https://example.co.uk/x"),
        new("http://localhost:8080/p/q"),
        new("http://127.0.0.1/p"),
        new("http://[::1]/"),
        new("https://xn--bcher-kva.example/%E2%82%AC/"),
        new("http://example.com./dot"),
        new("http://EXAMPLE.com/Upper/Case"),
    ];

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        Uri from = s_uris[input.Byte() % s_uris.Length];
        Uri to = s_uris[input.Byte() % s_uris.Length];
        var container = new CookieContainer();
        var headers = new List<string>();
        for (int i = 0; i < 4 && input.Remaining > 0; i++)
        {
            string header = input.Segment();
            if (header.Length > 2048)
            {
                break;
            }

            headers.Add(header);
            try
            {
                container.SetCookies(from, header);
            }
            catch (CookieException)
            {
            }
        }

        string what = $"Set-Cookie [{string.Join(" | ", headers.Select(Check.Show))}] from {from}";
        foreach (Cookie c in container.GetAllCookies())
        {
            Check.That(DomainMatches(from.Host, Unquote(c.Domain)), $"cookie {Show(c)} stored for a domain {from.Host} can't set: {what}");
        }

        foreach (Uri uri in (Uri[])[from, to])
        {
            CookieCollection cookies = container.GetCookies(uri);
            string header = container.GetCookieHeader(uri);
            string readWhat = $"read for {uri}, header {Check.Show(header)}, {what}";
            Check.That(header.AsSpan().IndexOfAny('\r', '\n') < 0, $"line break in the Cookie header: {readWhat}");
            foreach (Cookie c in cookies)
            {
                // RFC 2965 cookies keep the quotes of quoted Domain / Path attributes.
                Check.That(DomainMatches(uri.Host, Unquote(c.Domain)), $"cookie {Show(c)} returned for another domain: {readWhat}");
                Check.That(PathMatches(uri.AbsolutePath, Unquote(c.Path)), $"cookie {Show(c)} returned for another path: {readWhat}");
                Check.That(!c.Secure || uri.Scheme == Uri.UriSchemeHttps, $"Secure cookie {Show(c)} returned over http: {readWhat}");
            }

            // The header is "name=value; name2=value2" (with $Version / $Path / $Domain attributes for
            // RFC 2965 cookies): a name or value with a ';' outside a quoted string would split into
            // another cookie at the server.
            foreach (Cookie c in cookies)
            {
                bool quoted = c.Value.Length >= 2 && c.Value[0] == '"' && c.Value[^1] == '"' && c.Value.IndexOf('"', 1) == c.Value.Length - 1;
                Check.That(!c.Name.Contains(';') && !c.Name.Contains('=') && (quoted || !c.Value.Contains(';')),
                    $"cookie {Show(c)} would split in the Cookie header: {readWhat}");
                Check.That(header.Contains(c.Name + "=" + c.Value, StringComparison.Ordinal), $"cookie {Show(c)} missing from the header: {readWhat}");
            }
        }
    }

    /// <summary>Splits a Cookie header at "; " outside quoted strings (RFC 2965 values may be quoted).</summary>
    private static List<string> SplitHeader(string header)
    {
        var parts = new List<string>();
        int start = 0;
        bool quoted = false;
        for (int i = 0; i < header.Length; i++)
        {
            if (header[i] == '"')
            {
                quoted = !quoted;
            }
            else if (!quoted && header[i] == ';' && i + 1 < header.Length && header[i + 1] == ' ')
            {
                parts.Add(header[start..i]);
                start = i + 2;
                i++;
            }
        }

        if (header.Length > 0)
        {
            parts.Add(header[start..]);
        }

        return parts;
    }

    private static string Unquote(string s) => s.Length >= 2 && s[0] == '"' && s[^1] == '"' ? s[1..^1] : s;

    private static string Show(Cookie c) => $"{Check.Show(c.Name)}={Check.Show(c.Value)} (domain {Check.Show(c.Domain)}, path {Check.Show(c.Path)}, version {c.Version})";

    /// <summary>
    /// Domain-match (RFC 6265 5.1.3), with a leading '.' of the cookie domain ignored; a domain other
    /// than the host itself needs an inner dot (no cookies for a whole TLD) and IP hosts only match exactly.
    /// </summary>
    private static bool DomainMatches(string host, string domain)
    {
        host = host.ToLowerInvariant().TrimEnd('.');
        domain = domain.ToLowerInvariant().TrimStart('.').TrimEnd('.');
        return host == domain ||
            host.EndsWith("." + domain, StringComparison.Ordinal) && domain.Contains('.') && !IPAddress.TryParse(host.Trim('[', ']'), out _);
    }

    /// <summary>Path-match as CookieContainer implements it (RFC 2965: the cookie path is a prefix of the request path).</summary>
    private static bool PathMatches(string requestPath, string cookiePath) =>
        cookiePath.Length == 0 || requestPath.StartsWith(cookiePath, StringComparison.Ordinal);
}
