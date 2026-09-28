#nullable disable warnings
using System.Buffers;
using System.Buffers.Text;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;

namespace SharpFuzzHarness;

/// <summary>
/// Memory safety of more vectorized span code that reads and writes through Unsafe / vector loads:
/// SearchValues (IndexOfAnyAsciiSearcher, the probabilistic map, Teddy / Aho-Corasick for strings),
/// Base64 / Base64Url, the System.Text.Encodings.Web encoders, and Utf8JsonReader / Utf8JsonWriter
/// (CopyString, an IBufferWriter that hands out exactly the requested size). Inputs and outputs are
/// exactly sized and sit against a guard page (see <see cref="Guarded"/>); results are compared with
/// the same call over ordinary arrays (which a stray read past the end wouldn't fault on) and, where
/// simple, with a plain loop.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 placement / option bits
///   segment    the search set ('|' separates strings), up to 64 chars
///   rest       the data (bytes, or UTF-16LE text for char operations)
/// </remarks>
public static class UnsafeEncodingTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte place = input.Byte();
        string set = input.Segment();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 8192 || set.Length > 64)
        {
            return;
        }

        char[] chars = Encoding.Unicode.GetString(bytes, 0, bytes.Length & ~1).ToCharArray();
        bool inStart = (place & 1) != 0, outStart = (place & 2) != 0;
        ReadOnlySpan<byte> b = Guarded.Copy<byte>(bytes, inStart);
        ReadOnlySpan<char> c = Guarded.Copy<char>(chars, inStart);
        string what = $"op {op % 6}, place {place:X2}, set {Check.Show(set)}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)))}{(bytes.Length > 48 ? "..." : "")}";
        switch (op % 6)
        {
            case 0: SearchChars(set, chars, c, what); break;
            case 1: SearchBytes(set, bytes, b, what); break;
            case 2: SearchStrings(set, chars, c, (place & 4) != 0, what); break;
            case 3: Base64Codecs(bytes, b, chars, c, place, outStart, what); break;
            case 4: WebEncoders(bytes, b, chars, c, place, outStart, what); break;
            default: Json(bytes, b, place, outStart, what); break;
        }
    }

    private static Span<T> Out<T>(int length, bool atStart) => Guarded.Copy<T>(new T[length], atStart);

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static void SearchChars(string set, char[] chars, ReadOnlySpan<char> c, string what)
    {
        SearchValues<char> values = SearchValues.Create(set);
        int first = Array.FindIndex(chars, set.Contains), last = Array.FindLastIndex(chars, set.Contains);
        int firstExcept = Array.FindIndex(chars, x => !set.Contains(x)), lastExcept = Array.FindLastIndex(chars, x => !set.Contains(x));
        Check.Equal(first, c.IndexOfAny(values), $"IndexOfAny(SearchValues<char>): {what}");
        Check.Equal(last, c.LastIndexOfAny(values), $"LastIndexOfAny(SearchValues<char>): {what}");
        Check.Equal(firstExcept, c.IndexOfAnyExcept(values), $"IndexOfAnyExcept(SearchValues<char>): {what}");
        Check.Equal(lastExcept, c.LastIndexOfAnyExcept(values), $"LastIndexOfAnyExcept(SearchValues<char>): {what}");
        Check.Equal(first >= 0, c.ContainsAny(values), $"ContainsAny(SearchValues<char>): {what}");
        Check.Equal(firstExcept >= 0, c.ContainsAnyExcept(values), $"ContainsAnyExcept(SearchValues<char>): {what}");
        // The span overloads with the set itself (up to 5 values take the non-SearchValues paths).
        Check.Equal(first, c.IndexOfAny(set), $"IndexOfAny(span): {what}");
        Check.Equal(lastExcept, c.LastIndexOfAnyExcept(set), $"LastIndexOfAnyExcept(span): {what}");
    }

    private static void SearchBytes(string set, byte[] bytes, ReadOnlySpan<byte> b, string what)
    {
        byte[] needles = set.Select(ch => (byte)ch).ToArray();
        SearchValues<byte> values = SearchValues.Create(needles);
        int first = Array.FindIndex(bytes, needles.Contains), last = Array.FindLastIndex(bytes, needles.Contains);
        int firstExcept = Array.FindIndex(bytes, x => !needles.Contains(x)), lastExcept = Array.FindLastIndex(bytes, x => !needles.Contains(x));
        Check.Equal(first, b.IndexOfAny(values), $"IndexOfAny(SearchValues<byte>): {what}");
        Check.Equal(last, b.LastIndexOfAny(values), $"LastIndexOfAny(SearchValues<byte>): {what}");
        Check.Equal(firstExcept, b.IndexOfAnyExcept(values), $"IndexOfAnyExcept(SearchValues<byte>): {what}");
        Check.Equal(lastExcept, b.LastIndexOfAnyExcept(values), $"LastIndexOfAnyExcept(SearchValues<byte>): {what}");
        Check.Equal(first >= 0, b.ContainsAny(values), $"ContainsAny(SearchValues<byte>): {what}");
        Check.Equal(first, b.IndexOfAny(needles), $"IndexOfAny(span): {what}");
    }

    private static void SearchStrings(string set, char[] chars, ReadOnlySpan<char> c, bool ignoreCase, string what)
    {
        string[] needles = set.Split('|', StringSplitOptions.RemoveEmptyEntries);
        if (needles.Length == 0)
        {
            return;
        }

        StringComparison comparison = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        SearchValues<string> values = SearchValues.Create(needles, comparison);
        int onArray = chars.AsSpan().IndexOfAny(values);
        Check.Equal(onArray, c.IndexOfAny(values), $"IndexOfAny(SearchValues<string>) guarded vs array: {what}");
        Check.Equal(onArray >= 0, c.ContainsAny(values), $"ContainsAny(SearchValues<string>): {what}");
        if (!ignoreCase)
        {
            // Ordinal: the first position where some needle starts.
            int expected = -1;
            for (int i = 0; i < chars.Length && expected < 0; i++)
            {
                foreach (string n in needles)
                {
                    if (((ReadOnlySpan<char>)chars.AsSpan(i)).StartsWith(n, StringComparison.Ordinal))
                    {
                        expected = i;
                        break;
                    }
                }
            }

            Check.Equal(expected, onArray, $"IndexOfAny(SearchValues<string>, Ordinal) vs a loop: {what}");
        }

        // A single needle through the span IndexOf paths.
        ReadOnlySpan<char> array = chars;
        Check.Equal(array.IndexOf(needles[0], comparison), c.IndexOf(needles[0], comparison), $"IndexOf(string, {comparison}): {what}");
        Check.Equal(array.LastIndexOf(needles[0], comparison), c.LastIndexOf(needles[0], comparison), $"LastIndexOf(string, {comparison}): {what}");
    }

    private static string Show<T>(Outcome<T> o) => o.Ok ? o.Value?.ToString() ?? "null" : o.ErrorType.Name;

    private static void Base64Codecs(byte[] bytes, ReadOnlySpan<byte> b, char[] chars, ReadOnlySpan<char> c, byte place, bool outStart, string what)
    {
        bool final = (place & 4) != 0;
        // Encoding into an exactly sized destination, then one byte short.
        string base64 = Convert.ToBase64String(bytes);
        Span<byte> enc = Out<byte>(base64.Length, outStart);
        Check.That(Base64.EncodeToUtf8(b, enc, out int consumed, out int written) == OperationStatus.Done && consumed == bytes.Length && written == base64.Length && enc.SequenceEqual(Encoding.ASCII.GetBytes(base64)),
            $"Base64.EncodeToUtf8 into {base64.Length} bytes: consumed {consumed}, written {written}: {what}");
        if (base64.Length > 0)
        {
            Span<byte> small = Out<byte>(base64.Length - 1, outStart);
            Check.That(Base64.EncodeToUtf8(b, small, out _, out written) == OperationStatus.DestinationTooSmall && written <= small.Length, $"Base64.EncodeToUtf8 into {base64.Length - 1} bytes: {what}");
        }

        Span<char> encChars = Out<char>(base64.Length, !outStart);
        Check.That(Convert.TryToBase64Chars(b, encChars, out written) && written == base64.Length && encChars.SequenceEqual(base64), $"Convert.TryToBase64Chars: {what}");
        string url = Base64Url.EncodeToString(bytes);
        Span<char> urlChars = Out<char>(url.Length, outStart);
        Check.That(Base64Url.TryEncodeToChars(b, urlChars, out written) && written == url.Length && urlChars.SequenceEqual(url), $"Base64Url.TryEncodeToChars: {what}");
        Span<byte> urlBytes = Out<byte>(url.Length, !outStart);
        Check.That(Base64Url.TryEncodeToUtf8(b, urlBytes, out written) && written == url.Length && urlBytes.SequenceEqual(Encoding.ASCII.GetBytes(url)), $"Base64Url.TryEncodeToUtf8: {what}");

        // Decoding the fuzz data as base64 text: the same result from guarded memory as from an array,
        // then again into an exactly sized destination.
        int max = Base64.GetMaxDecodedFromUtf8Length(bytes.Length);
        byte[] expected = new byte[max];
        OperationStatus status = Base64.DecodeFromUtf8(bytes, expected, out int c1, out int w1, final);
        Span<byte> dec = Out<byte>(max, outStart);
        Check.That(Base64.DecodeFromUtf8(b, dec, out int c2, out int w2, final) == status && c1 == c2 && w1 == w2 && dec[..w2].SequenceEqual(expected.AsSpan(0, w1)),
            $"Base64.DecodeFromUtf8 guarded vs array ({status}, {c1}, {w1}): {what}");
        if (status == OperationStatus.Done && w1 > 0)
        {
            Span<byte> exact = Out<byte>(w1, !outStart);
            OperationStatus again = Base64.DecodeFromUtf8(b, exact, out int c3, out int w3, final);
            Check.That(again == status && c3 == c1 && w3 == w1 && exact.SequenceEqual(expected.AsSpan(0, w1)), $"Base64.DecodeFromUtf8 into exactly {w1} bytes gave {again}, {c3}, {w3}: {what}");
        }

        Span<byte> inPlace = Guarded.Copy<byte>(bytes, outStart);
        OperationStatus inPlaceStatus = Base64.DecodeFromUtf8InPlace(inPlace, out int w4);
        Check.That(inPlaceStatus != OperationStatus.Done || !final || w4 <= bytes.Length && inPlace[..w4].SequenceEqual(expected.AsSpan(0, w4)), $"Base64.DecodeFromUtf8InPlace: {inPlaceStatus} {w4}: {what}");
        Check.Equal(Base64.IsValid(bytes), Base64.IsValid(b), $"Base64.IsValid(utf8): {what}");
        Check.Equal(Base64.IsValid(chars), Base64.IsValid(c), $"Base64.IsValid(chars): {what}");

        byte[] fromChars = new byte[chars.Length];
        bool ok = Convert.TryFromBase64Chars(chars, fromChars, out int w5);
        Span<byte> fromGuarded = Out<byte>(ok ? w5 : chars.Length, outStart);
        Check.That(Convert.TryFromBase64Chars(c, fromGuarded, out int w6) == ok && (!ok || w6 == w5 && fromGuarded.SequenceEqual(fromChars.AsSpan(0, w5))), $"Convert.TryFromBase64Chars: {what}");

        // Base64Url decoding (invalid input throws FormatException from the Try methods, as documented).
        var urlArray = Outcome<string>.Of(() => Base64Url.TryDecodeFromChars(chars, new byte[chars.Length], out int n) ? n.ToString() : "false", e => e is FormatException);
        Memory<char> cm = Guarded.CopyMemory<char>(chars, (place & 1) != 0);
        var urlGuarded = Outcome<string>.Of(() => Base64Url.TryDecodeFromChars(cm.Span, Out<byte>(chars.Length, !outStart), out int n) ? n.ToString() : "false", e => e is FormatException);
        Check.That(urlArray.SameAs(urlGuarded), $"Base64Url.TryDecodeFromChars: {Show(urlArray)} vs guarded {Show(urlGuarded)}: {what}");
        byte[] urlExpected = new byte[Base64Url.GetMaxDecodedLength(bytes.Length)];
        OperationStatus urlStatus = Base64Url.DecodeFromUtf8(bytes, urlExpected, out int c7, out int w7, final);
        // Same-sized guarded destination for every outcome; an exactly sized one when it's Done (otherwise
        // a full destination may be reported before the invalid data).
        Span<byte> urlDec = Out<byte>(urlStatus == OperationStatus.Done ? w7 : urlExpected.Length, outStart);
        OperationStatus urlGuardedStatus = Base64Url.DecodeFromUtf8(b, urlDec, out int c8, out int w8, final);
        // Known (B64URL-EXACT-1): a final block with partial padding ("GQ=", "GQ%") decodes into a larger
        // destination but is InvalidData when the destination is exactly the decoded size.
        if (!s_reportKnownIssues && urlStatus == OperationStatus.Done && urlGuardedStatus == OperationStatus.InvalidData && bytes.AsSpan().IndexOfAny("=%"u8) >= 0)
        {
            return;
        }

        Check.That(urlGuardedStatus == urlStatus && c8 == c7 && w8 == w7 && urlDec[..w8].SequenceEqual(urlExpected.AsSpan(0, w7)),
            $"Base64Url.DecodeFromUtf8 into {urlDec.Length} bytes: {urlGuardedStatus} {c8} {w8} vs {urlStatus} {c7} {w7}: {what}");
    }

    private static TextEncoder Encoder(int kind) => (kind % 7) switch
    {
        0 => JavaScriptEncoder.Default,
        1 => JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        2 => HtmlEncoder.Default,
        3 => UrlEncoder.Default,
        4 => JavaScriptEncoder.Create(UnicodeRanges.BasicLatin, UnicodeRanges.Cyrillic, UnicodeRanges.CjkUnifiedIdeographs),
        5 => HtmlEncoder.Create(UnicodeRanges.All),
        _ => UrlEncoder.Create(UnicodeRanges.Latin1Supplement),
    };

    private static void WebEncoders(byte[] bytes, ReadOnlySpan<byte> b, char[] chars, ReadOnlySpan<char> c, byte place, bool outStart, string what)
    {
        TextEncoder encoder = Encoder(place >> 3);
        what = $"{encoder.GetType().Name} #{(place >> 3) % 7}: {what}";

        // UTF-16: exactly sized destination, then too small.
        string expected = encoder.Encode(new string(chars));
        Span<char> dest = Out<char>(expected.Length, outStart);
        OperationStatus status = encoder.Encode(c, dest, out int consumed, out int written, isFinalBlock: true);
        Check.That(status == OperationStatus.Done && consumed == chars.Length && written == expected.Length && dest.SequenceEqual(expected),
            $"Encode(chars) into {expected.Length}: {status}, consumed {consumed}, written {written}: {what}");
        if (expected.Length > 0)
        {
            Span<char> small = Out<char>(Math.Max(0, expected.Length - 1 - (place & 4)), !outStart);
            status = encoder.Encode(c, small, out consumed, out written, isFinalBlock: true);
            Check.That(status == OperationStatus.DestinationTooSmall && written <= small.Length && small[..written].SequenceEqual(expected.AsSpan(0, written)),
                $"Encode(chars) into {small.Length} < {expected.Length}: {status}, written {written}: {what}");
        }

        unsafe
        {
            fixed (char* p = c)
            {
                Check.Equal(FindFirst(encoder, chars), encoder.FindFirstCharacterToEncode(p, c.Length), $"FindFirstCharacterToEncode: {what}");
            }
        }

        // UTF-8.
        byte[] big = new byte[bytes.Length * 12 + 16];
        OperationStatus s8 = encoder.EncodeUtf8(bytes, big, out int c8, out int w8, isFinalBlock: (place & 4) == 0);
        Span<byte> dest8 = Out<byte>(w8, outStart);
        OperationStatus g8 = encoder.EncodeUtf8(b, dest8, out int gc8, out int gw8, isFinalBlock: (place & 4) == 0);
        Check.That(g8 == s8 && gc8 == c8 && gw8 == w8 && dest8.SequenceEqual(big.AsSpan(0, w8)), $"EncodeUtf8 into exactly {w8}: {g8} {gc8} {gw8} vs {s8} {c8} {w8}: {what}");
        Check.Equal(encoder.FindFirstCharacterToEncodeUtf8(bytes), encoder.FindFirstCharacterToEncodeUtf8(b), $"FindFirstCharacterToEncodeUtf8: {what}");
    }

    private static unsafe int FindFirst(TextEncoder encoder, char[] chars)
    {
        fixed (char* p = chars)
        {
            return encoder.FindFirstCharacterToEncode(p, chars.Length);
        }
    }

    /// <summary>An IBufferWriter that hands out exactly the requested size, in guarded memory, and collects what's advanced.</summary>
    private sealed class GuardedBufferWriter(bool atStart) : IBufferWriter<byte>
    {
        private Memory<byte> _current;
        public readonly List<byte> Written = [];

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            int size = Math.Max(sizeHint, 1);
            _current = size <= Guarded.SlotBytes ? Guarded.CopyMemory<byte>(new byte[size], atStart) : new byte[size];
            return _current;
        }

        public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;

        public void Advance(int count)
        {
            Check.That(count >= 0 && count <= _current.Length, $"Advance({count}) past the {_current.Length} bytes handed out");
            Written.AddRange(_current.Span[..count].ToArray());
            _current = default;
        }
    }

    private static List<string> Tokens(ReadOnlySpan<byte> json, JsonReaderOptions options, bool final, bool copy, bool outStart)
    {
        var tokens = new List<string>();
        var reader = new Utf8JsonReader(json, final, new JsonReaderState(options));
        int copies = 0;
        try
        {
            while (reader.Read() && tokens.Count < 2000)
            {
                string token = reader.TokenType.ToString();
                if (reader.TokenType is JsonTokenType.String or JsonTokenType.PropertyName)
                {
                    string s = reader.GetString();
                    token += "=" + Check.Escape(s, 1 << 16);
                    if (copy && copies++ < 6)
                    {
                        // CopyString into exactly sized (and one short) guarded destinations.
                        int length = Encoding.UTF8.GetByteCount(s);
                        Span<byte> dest = Out<byte>(length, outStart);
                        int n;
                        try
                        {
                            n = reader.CopyString(dest);
                        }
                        catch (ArgumentException) when (!s_reportKnownIssues && reader.ValueIsEscaped)
                        {
                            // Known (JSON-COPY-1): JsonReaderHelper.TryUnescape reports "destination too short" when
                            // the unescaped text after the last escape exactly fills the destination
                            // ("\u0041b" into 2 bytes); one more byte works.
                            Span<byte> larger = Out<byte>(length + 1, outStart);
                            n = reader.CopyString(larger);
                            dest = larger[..length];
                        }

                        Check.That(n == length && dest.SequenceEqual(Encoding.UTF8.GetBytes(s)), $"CopyString(utf8) wrote {n} of {length}");
                        Span<char> destChars = Out<char>(s.Length, !outStart);
                        n = reader.CopyString(destChars);
                        Check.That(n == s.Length && destChars.SequenceEqual(s), $"CopyString(chars) wrote {n} of {s.Length}");
                        if (length > 0)
                        {
                            bool threw = false;
                            try
                            {
                                reader.CopyString(Out<byte>(length - 1, outStart));
                            }
                            catch (ArgumentException)
                            {
                                threw = true;
                            }

                            Check.That(threw, $"CopyString into {length - 1} of {length} bytes succeeded");
                        }

                        Check.That(reader.ValueTextEquals(Guarded.Copy<char>(s.AsSpan(), outStart)), "ValueTextEquals(guarded chars) is false for GetString()");
                    }
                }
                else if (reader.TokenType == JsonTokenType.Number)
                {
                    token += "=" + Encoding.UTF8.GetString(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray());
                    token += reader.TryGetDecimal(out decimal m) ? "/" + m : "";
                }

                tokens.Add(token);
            }
        }
        catch (JsonException e)
        {
            tokens.Add($"error at {reader.BytesConsumed}: {e.GetType().Name}");
        }
        catch (InvalidOperationException e)
        {
            // GetString of a string with invalid UTF-8 / escapes.
            tokens.Add($"error at {reader.BytesConsumed}: {e.GetType().Name}");
        }

        tokens.Add($"consumed {reader.BytesConsumed}");
        return tokens;
    }

    private static void Json(byte[] bytes, ReadOnlySpan<byte> b, byte place, bool outStart, string what)
    {
        var options = new JsonReaderOptions
        {
            CommentHandling = (place & 4) != 0 ? JsonCommentHandling.Skip : JsonCommentHandling.Disallow,
            AllowTrailingCommas = (place & 8) != 0,
            AllowMultipleValues = (place & 16) != 0,
            MaxDepth = 64,
        };
        bool final = (place & 32) == 0;
        List<string> expected = Tokens(bytes, options, final, copy: false, outStart);
        List<string> guarded = Tokens(b, options, final, copy: true, outStart);
        Check.That(guarded.SequenceEqual(expected), $"Utf8JsonReader over guarded memory reads [{string.Join(" ", guarded.Take(40))}], over an array [{string.Join(" ", expected.Take(40))}]: {what}");

        // Write the document back through a writer whose buffers are exactly the size it asks for.
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { CommentHandling = options.CommentHandling, AllowTrailingCommas = options.AllowTrailingCommas, MaxDepth = 64 });
        }
        catch (JsonException)
        {
            return;
        }

        using (doc)
        {
            JavaScriptEncoder encoder = (place >> 6) switch { 0 => null, 1 => JavaScriptEncoder.UnsafeRelaxedJsonEscaping, 2 => JavaScriptEncoder.Create(UnicodeRanges.All), _ => JavaScriptEncoder.Create(UnicodeRanges.BasicLatin) };
            var writerOptions = new JsonWriterOptions { Indented = (place & 64) != 0, Encoder = encoder, SkipValidation = false };
            var array = new ArrayBufferWriter<byte>();
            try
            {
                using var w = new Utf8JsonWriter(array, writerOptions);
                doc.WriteTo(w);
            }
            catch (InvalidOperationException e) when (!s_reportKnownIssues && e.Message.Contains("UTF-16", StringComparison.Ordinal))
            {
                // Known (JSON-SURR-1, informational): JsonDocument.Parse accepts an escaped lone surrogate
                // ("\ud83d"), which WriteTo can't unescape. (The guarded writer below then isn't reached.)
                return;
            }

            var exact = new GuardedBufferWriter(outStart);
            using (var w = new Utf8JsonWriter(exact, writerOptions))
            {
                doc.WriteTo(w);
                // Strings with the fuzz data: escaping (encoder) and base64 paths.
                w.Flush();
            }

            Check.That(exact.Written.SequenceEqual(array.WrittenSpan.ToArray()), $"Utf8JsonWriter into exactly sized buffers wrote {exact.Written.Count} bytes, into an array {array.WrittenCount}: {what}");

            var strings = new GuardedBufferWriter(!outStart);
            using (var w = new Utf8JsonWriter(strings, writerOptions))
            {
                w.WriteStartArray();
                string text = Encoding.UTF8.GetString(bytes);
                w.WriteStringValue(Guarded.Copy<char>(text.AsSpan(), outStart));
                w.WriteBase64StringValue(Guarded.Copy<byte>(bytes, !outStart)); // a fresh copy: the writer's buffers may have reused b's slot
                w.WriteStringValue(JsonEncodedText.Encode(Guarded.Copy<char>(text.AsSpan(), !outStart), encoder));
                w.WriteEndArray();
            }

            using JsonDocument back = JsonDocument.Parse(strings.Written.ToArray());
            string text2 = Encoding.UTF8.GetString(bytes);
            Check.That(back.RootElement[0].GetString() == text2 && back.RootElement[1].GetBytesFromBase64().AsSpan().SequenceEqual(bytes) && back.RootElement[2].GetString() == text2,
                $"Utf8JsonWriter strings / base64 into exactly sized buffers don't read back: {what}");
        }
    }
}
