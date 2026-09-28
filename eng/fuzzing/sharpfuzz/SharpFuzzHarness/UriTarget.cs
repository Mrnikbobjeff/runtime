#nullable disable warnings
namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Private.Uri: parsing, canonicalization, relative resolution and escaping.</summary>
/// <remarks>
/// Input layout:
///   byte 0     low 2 bits: UriKind; 0x04 DangerousDisablePathAndQueryCanonicalization
///   segment    URI text
///   segment    relative URI text (resolved against the first one when it's absolute)
/// Checks: the constructor and TryCreate agree; an absolute URI's AbsoluteUri parses back to an
/// equal URI with the same AbsoluteUri (canonicalization is idempotent); every component getter
/// and GetComponents only throws for relative URIs; relative resolution through the ctor and
/// TryCreate agree; EscapeDataString / UnescapeDataString round-trip and their span overloads
/// agree with the string ones.
/// </remarks>
public static class UriTarget
{
    private const int MaxLength = 1024;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        string text = input.Segment();
        string relative = input.Segment();
        if (text.Length > MaxLength || relative.Length > MaxLength)
        {
            return;
        }

        var kind = (UriKind)(flags % 3);
        string what = $"Uri {Check.Show(text)} ({kind})";
        var ctor = Outcome<Uri>.Of(() => new Uri(text, kind), e => e is UriFormatException);
        bool ok = Uri.TryCreate(text, kind, out Uri tryUri);
        Check.That(ctor.Ok == ok && (!ok || ctor.Value.OriginalString == tryUri.OriginalString && ctor.Value.Equals(tryUri)),
            $"new Uri {ctor} != TryCreate {ok} for {what}");
        _ = Uri.IsWellFormedUriString(text, kind);

        if ((flags & 0x04) != 0)
        {
            var options = new UriCreationOptions { DangerousDisablePathAndQueryCanonicalization = true };
            if (Uri.TryCreate(text, options, out Uri raw) && raw.IsAbsoluteUri)
            {
                // GetComponents() is documented to throw for Path/Query on such instances.
                _ = (raw.ToString(), raw.AbsoluteUri, raw.PathAndQuery, raw.AbsolutePath, raw.Query, raw.Host, raw.Port, raw.Scheme, raw.Fragment, raw.UserInfo, raw.Authority);
                foreach (UriComponents components in (UriComponents[])[UriComponents.SchemeAndServer, UriComponents.UserInfo | UriComponents.Host | UriComponents.Port, UriComponents.NormalizedHost])
                {
                    _ = raw.GetComponents(components, UriFormat.UriEscaped);
                }
            }
        }

        if (ok)
        {
            Components(tryUri, what);
            if (tryUri.IsAbsoluteUri)
            {
                Idempotent(tryUri, what);
                Resolve(tryUri, relative, what);
            }
        }

        Escaping(text);
        Escaping(relative);
    }

    private static void Components(Uri uri, string what)
    {
        _ = uri.ToString();
        _ = uri.OriginalString;
        _ = uri.GetHashCode();
        _ = uri.IsWellFormedOriginalString();
        if (!uri.IsAbsoluteUri)
        {
            return;
        }

        _ = (uri.AbsoluteUri, uri.AbsolutePath, uri.Authority, uri.DnsSafeHost, uri.Fragment, uri.Host, uri.HostNameType,
             uri.IsDefaultPort, uri.IsFile, uri.IsLoopback, uri.IsUnc, uri.LocalPath, uri.PathAndQuery, uri.Port, uri.Query, uri.Scheme,
             uri.Segments, uri.UserEscaped, uri.UserInfo);
        // Known (URI-IDN-1): IdnHost throws UriFormatException for some hosts the constructor accepted
        // ("xn--bcher-kva\u00FC.example"), while Host and DnsSafeHost work.
        _ = Outcome<string>.Of(() => uri.IdnHost, e => !s_reportKnownIssues && e is UriFormatException);
        foreach (UriFormat format in (UriFormat[])[UriFormat.UriEscaped, UriFormat.Unescaped, UriFormat.SafeUnescaped])
        {
            foreach (UriComponents components in (UriComponents[])[UriComponents.AbsoluteUri, UriComponents.HttpRequestUrl, UriComponents.SchemeAndServer,
                UriComponents.PathAndQuery, UriComponents.Path | UriComponents.KeepDelimiter, UriComponents.UserInfo | UriComponents.Host | UriComponents.Port,
                UriComponents.StrongAuthority, UriComponents.NormalizedHost, UriComponents.Fragment, UriComponents.SerializationInfoString])
            {
                _ = uri.GetComponents(components, format);
            }
        }

        _ = uri.GetLeftPart(UriPartial.Authority);
        _ = uri.GetLeftPart(UriPartial.Path);
        _ = uri.GetLeftPart(UriPartial.Query);
    }

    /// <summary>Parsing the canonical form again must give the same URI and the same canonical form.</summary>
    private static void Idempotent(Uri uri, string what)
    {
        string canonical = uri.AbsoluteUri;
        var again = Outcome<Uri>.Of(() => new Uri(canonical, UriKind.Absolute), e => e is UriFormatException);
        // Known (URI-CANON-1): file URIs ("/E:" -> "file:///E:", "/.//x" -> "file:////x", U+FFFD and '%' in
        // implicit paths) and hosts that bidi/format characters reduce to "" or ".com" ("https://\u202E.com/")
        // give an AbsoluteUri that doesn't parse back, or parses back differently.
        bool known = !s_reportKnownIssues && (uri.IsFile || uri.OriginalString.Any(c => char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format));
        if (known && (!again.Ok || again.Value.AbsoluteUri != canonical || !again.Value.Equals(uri)))
        {
            return;
        }

        Check.That(again.Ok, $"AbsoluteUri {Check.Show(canonical)} doesn't parse ({again}) for {what}");

        // Known (URI-CANON-2): a '%' that doesn't start an escape is escaped to "%25" but a following
        // escape is kept, so the next parse decodes it: "tp:%%2E" -> "tp:%25%2E" -> "tp:%25.".
        if (s_reportKnownIssues || !HasStrayPercent(uri.OriginalString))
        {
            Check.That(again.Value.AbsoluteUri == canonical, $"AbsoluteUri {Check.Show(canonical)} parses back as {Check.Show(again.Value.AbsoluteUri)} for {what}");
        }

        // Known (URI-EQUALS-1): a Uri and the Uri parsed from its own AbsoluteUri compare unequal when the
        // original had characters that parsing escapes: '\' in a non-special scheme ("tp:\"), a stray '%'
        // next to non-ASCII ("h1:%\uFFFDx"), or ' ', '^', '|', '"' in the user info. So Equals is only
        // checked for text made of characters RFC 3986 allows unescaped.
        if (s_reportKnownIssues || uri.OriginalString.All(c => char.IsAsciiLetterOrDigit(c) || "-._~:/?#[]@!$&'()*+,;=".Contains(c)))
        {
            Check.That(again.Value.Equals(uri), $"AbsoluteUri {Check.Show(canonical)} parses back as an unequal Uri for {what}");
        }
    }

    private static void Resolve(Uri baseUri, string relative, string what)
    {
        what += $" + {Check.Show(relative)}";
        var ctor = Outcome<Uri>.Of(() => new Uri(baseUri, relative), e => e is UriFormatException);
        bool ok = Uri.TryCreate(baseUri, relative, out Uri resolved);
        Check.That(ctor.Ok == ok && (!ok || ctor.Value.Equals(resolved)), $"new Uri(base, relative) {ctor} != TryCreate {ok} for {what}");
        if (!ok)
        {
            return;
        }

        Components(resolved, what);
        if (resolved.IsAbsoluteUri)
        {
            Idempotent(resolved, what);
            var rel = Outcome<Uri>.Of(() => baseUri.MakeRelativeUri(resolved), e => e is InvalidOperationException);
            if (rel.Ok)
            {
                _ = rel.Value.ToString();
            }
        }
    }

    private static void Escaping(string text)
    {
        string what = $"escaping {Check.Show(text)}";
        string escaped = Uri.EscapeDataString(text);
        Check.Equal(escaped, Uri.EscapeDataString(text.AsSpan()), $"EscapeDataString(span) for {what}");
        if (System.Text.Unicode.Utf8.IsValid(System.Text.Encoding.UTF8.GetBytes(text)) && !HasLoneSurrogate(text))
        {
            Check.Equal(text, Uri.UnescapeDataString(escaped), $"UnescapeDataString(EscapeDataString(s)) for {what}");
        }

        char[] buffer = new char[escaped.Length];
        Check.That(Uri.TryEscapeDataString(text, buffer, out int written) && buffer.AsSpan(0, written).SequenceEqual(escaped),
            $"TryEscapeDataString into an exact buffer != EscapeDataString for {what}");
        if (escaped.Length > 0)
        {
            Check.That(!Uri.TryEscapeDataString(text, new char[escaped.Length - 1], out _), $"TryEscapeDataString into a short buffer succeeded for {what}");
        }

        string unescaped = Uri.UnescapeDataString(text);
        Check.Equal(unescaped, Uri.UnescapeDataString(text.AsSpan()), $"UnescapeDataString(span) for {what}");
        buffer = new char[Math.Max(unescaped.Length, text.Length)];
        Check.That(Uri.TryUnescapeDataString(text, buffer, out written) && buffer.AsSpan(0, written).SequenceEqual(unescaped),
            $"TryUnescapeDataString != UnescapeDataString {Check.Show(unescaped)} for {what}");
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    /// <summary>A file URI given as a bare path ("/tmp/x", "C:\\x", "\\\\server\\x") rather than "file:...".</summary>
    private static bool IsImplicitFile(Uri uri) => uri.IsFile && !uri.OriginalString.TrimStart().StartsWith("file:", StringComparison.OrdinalIgnoreCase);

    private static bool HasStrayPercent(string s)
    {
        for (int i = s.IndexOf('%'); i >= 0; i = s.IndexOf('%', i + 1))
        {
            if (i + 2 >= s.Length || !char.IsAsciiHexDigit(s[i + 1]) || !char.IsAsciiHexDigit(s[i + 2]))
            {
                return true;
            }
        }

        return false;
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
}
