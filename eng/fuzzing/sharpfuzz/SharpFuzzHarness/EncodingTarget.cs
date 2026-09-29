#nullable disable warnings
using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace SharpFuzzHarness;

/// <summary>Fuzzes the built-in text encodings and the UTF-8/UTF-16/ASCII helpers.</summary>
/// <remarks>
/// Input layout:
///   byte 0     encoding (see <see cref="Create"/>)
///   byte 1     low 2 bits: fallbacks (0 default, 1 exception, 2 replacement strings from the
///              input, 3 custom fallback buffers returning input-chosen, possibly ill-formed,
///              strings)
///   byte 2     chunking seed
///   [segments] replacement strings (modes 2 and 3)
///   rest       payload: decoded as bytes, and reinterpreted as UTF-16LE code units to encode
/// Checks: GetString / GetChars / GetCharCount / span / TryGetChars agree; stateful Decoder and
/// Encoder calls on arbitrary chunks (splitting multi-byte sequences and surrogate pairs), and
/// Convert with tiny output buffers, produce the one-shot result; counts stay within
/// GetMax*Count; decoding matches reference UTF-8/UTF-16/UTF-32 decoders (one replacement per
/// maximal subpart); encoding round-trips to the input with unencodable text replaced; Utf8,
/// Rune and Ascii helpers agree with the references.
/// </remarks>
public static class EncodingTarget
{
    private const int MaxLength = 2048;

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

#pragma warning disable SYSLIB0001 // UTF-7 is obsolete but still ships in CoreLib.
    private static Encoding Create(int index) => (index % 12) switch
    {
        0 => new UTF8Encoding(false, false),
        1 => new UTF8Encoding(true, true),
        2 => new UnicodeEncoding(false, true, false),
        3 => new UnicodeEncoding(true, false, true),
        4 => new UTF32Encoding(false, true, false),
        5 => new UTF32Encoding(true, false, true),
        6 => new ASCIIEncoding(),
        7 => Encoding.Latin1,
        8 => new UTF7Encoding(false),
        9 => new UTF7Encoding(true),
        10 => Encoding.UTF8,
        _ => Encoding.Unicode,
    };
#pragma warning restore SYSLIB0001

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        int index = input.Byte();
        int mode = input.Byte() & 3;
        byte seed = input.Byte();
        Encoding encoding = Create(index);
        var replacements = new List<string>();
        if (mode >= 2)
        {
            for (int i = 1 + input.Byte() % 3; i > 0; i--)
            {
                replacements.Add(mode == 2 ? input.Segment() : MemoryMarshal.Cast<byte, char>(input.SegmentBytes()).ToString());
            }
        }

        byte[] payload = input.Rest().ToArray();
        if (payload.Length > MaxLength || replacements.Any(r => r.Length > 16))
        {
            return;
        }

        switch (mode)
        {
            case 1:
                encoding = (Encoding)encoding.Clone();
                encoding.EncoderFallback = EncoderFallback.ExceptionFallback;
                encoding.DecoderFallback = DecoderFallback.ExceptionFallback;
                break;
            case 2:
                encoding = (Encoding)encoding.Clone();
                try
                {
                    encoding.EncoderFallback = new EncoderReplacementFallback(replacements[0]);
                    encoding.DecoderFallback = new DecoderReplacementFallback(replacements[^1]);
                }
                catch (ArgumentException)
                {
                    return; // Replacement strings must be well-formed.
                }

                break;
            case 3:
                encoding = (Encoding)encoding.Clone();
                encoding.EncoderFallback = new FuzzEncoderFallback([.. replacements]);
                encoding.DecoderFallback = new FuzzDecoderFallback([.. replacements]);
                break;
        }

        string text = MemoryMarshal.Cast<byte, char>(payload.AsSpan(0, payload.Length & ~1)).ToString();
        string? decoded = Decode(encoding, payload, seed, mode == 3);
        Encode(encoding, text, seed, mode >= 2);
        if (decoded is not null && decoded != text)
        {
            Encode(encoding, decoded, seed, mode >= 2);
        }

        if (index % 12 == 0 && mode == 0)
        {
            Utf8Helpers(payload);
            Utf16Helpers(text);
        }
    }

    private static string Describe(Encoding e) => $"{e.GetType().Name}({e.WebName}, {e.EncoderFallback.GetType().Name}/{e.DecoderFallback.GetType().Name})";

    private static string? Decode(Encoding e, byte[] bytes, byte seed, bool custom)
    {
        Func<Exception, bool> allowed = ex => ex is DecoderFallbackException || (custom && ex is ArgumentException);
        string what = $"{Describe(e)} decoding {Check.Show(bytes)} ({bytes.Length} bytes)";
        var str = Outcome<string>.Of(() => e.GetString(bytes), allowed);
        var chars = Outcome<string>.Of(() => new string(e.GetChars(bytes)), allowed);
        var count = Outcome<int>.Of(() => e.GetCharCount(bytes), allowed);
        Check.That(str.SameAs(chars), $"GetString {str} != GetChars {chars} for {what}");
        Check.That(count.Ok == str.Ok && (!str.Ok || count.Value == str.Value!.Length), $"GetCharCount {count} != GetString length {str} for {what}");
        if (str.Ok)
        {
            string s = str.Value!;
            Check.That(s.Length <= e.GetMaxCharCount(bytes.Length), $"GetString length {s.Length} > GetMaxCharCount({bytes.Length}) = {e.GetMaxCharCount(bytes.Length)} for {what}");
            char[] exact = new char[s.Length];
            Check.That(e.GetChars(bytes.AsSpan(), exact) == s.Length && exact.AsSpan().SequenceEqual(s), $"GetChars(span) != GetString for {what}");
            Check.That(e.TryGetChars(bytes, exact, out int written) && written == s.Length, $"TryGetChars into an exact buffer failed for {what}");
            if (s.Length > 0)
            {
                Check.That(!e.TryGetChars(bytes, new char[s.Length - 1], out written), $"TryGetChars into a short buffer succeeded for {what}");
            }

            string? reference = ReferenceDecode(e, bytes);
            if (reference is not null)
            {
                Check.Equal(reference, s, $"GetString vs reference decoder for {what}");
            }

            Check.SequenceEqual<byte>(Encoding.UTF8.GetBytes(s), Encoding.Convert(e, Encoding.UTF8, bytes), $"Encoding.Convert to UTF-8 for {what}");
        }
        else if (!custom && e.DecoderFallback is DecoderExceptionFallback && ReferenceDecode(WithReplacement(e), bytes) is { } lenient)
        {
            Check.That(lenient.Contains('�') || bytes.Length == 0, $"Exception fallback threw {str} but the reference finds no invalid data for {what}");
        }

        // Stateful decoder fed in chunks, counting before converting each chunk.
        var rng = new Random(seed);
        var chunked = Outcome<string>.Of(() =>
        {
            Decoder decoder = e.GetDecoder();
            var sb = new StringBuilder();
            int pos = 0;
            do
            {
                int n = Math.Min(bytes.Length - pos, rng.Next(6));
                bool flush = pos + n == bytes.Length && rng.Next(4) != 0;
                int expectedCount = decoder.GetCharCount(bytes, pos, n, flush);
                char[] buffer = new char[e.GetMaxCharCount(n + 8)];
                int got = decoder.GetChars(bytes, pos, n, buffer, 0, flush);
                Check.Equal(expectedCount, got, $"Decoder.GetCharCount vs GetChars for a {n}-byte chunk at {pos} (flush={flush}) for {what}");
                sb.Append(buffer, 0, got);
                pos += n;
                if (pos == bytes.Length && flush)
                {
                    break;
                }

                if (pos == bytes.Length)
                {
                    char[] tail = new char[e.GetMaxCharCount(8)];
                    sb.Append(tail, 0, decoder.GetChars([], 0, 0, tail, 0, flush: true));
                    break;
                }
            }
            while (true);
            return sb.ToString();
        }, allowed);
        Check.That(chunked.Ok == str.Ok && (!str.Ok || chunked.Value == str.Value), $"Chunked Decoder {chunked} != GetString {str} for {what}");

        // Decoder.Convert into tiny buffers.
        int small = 2 + seed % 5 + (e.DecoderFallback.MaxCharCount > 1 ? e.DecoderFallback.MaxCharCount : 0);
        var converted = Outcome<string>.Of(() =>
        {
            Decoder decoder = e.GetDecoder();
            var sb = new StringBuilder();
            char[] buffer = new char[small];
            int pos = 0;
            for (int iterations = 0; ; iterations++)
            {
                Check.That(iterations <= 2 * bytes.Length + 16, $"Decoder.Convert makes no progress (output buffer {small}) for {what}");
                decoder.Convert(bytes, pos, bytes.Length - pos, buffer, 0, buffer.Length, true, out int used, out int produced, out bool completed);
                sb.Append(buffer, 0, produced);
                pos += used;
                if (completed)
                {
                    Check.Equal(bytes.Length, pos, $"Decoder.Convert completed without consuming all input for {what}");
                    return sb.ToString();
                }
            }
        }, allowed);
        Check.That(converted.Ok == str.Ok && (!str.Ok || converted.Value == str.Value), $"Decoder.Convert with {small}-char buffers {converted} != GetString {str} for {what}");
        return str.Ok ? str.Value : null;
    }

    private static void Encode(Encoding e, string text, byte seed, bool customReplacement)
    {
        Func<Exception, bool> allowed = ex => ex is EncoderFallbackException || (customReplacement && ex is ArgumentException);
        string what = $"{Describe(e)} encoding {Check.Show(text)} ({text.Length} chars)";
        var bytes = Outcome<byte[]>.Of(() => e.GetBytes(text), allowed);
        var count = Outcome<int>.Of(() => e.GetByteCount(text), allowed);
        var eq = new Check.By<byte[]>((a, b) => a.AsSpan().SequenceEqual(b));
        Check.That(count.Ok == bytes.Ok && (!bytes.Ok || count.Value == bytes.Value!.Length), $"GetByteCount {count} != GetBytes length for {what}");
        var fromChars = Outcome<byte[]>.Of(() => e.GetBytes(text.ToCharArray()), allowed);
        Check.That(bytes.SameAs(fromChars, eq), $"GetBytes(string) {bytes} != GetBytes(char[]) {fromChars} for {what}");
        if (bytes.Ok)
        {
            byte[] b = bytes.Value!;
            Check.That(b.Length <= e.GetMaxByteCount(text.Length), $"GetBytes length {b.Length} > GetMaxByteCount({text.Length}) = {e.GetMaxByteCount(text.Length)} for {what}");
            byte[] exact = new byte[b.Length];
            Check.That(e.GetBytes(text.AsSpan(), exact) == b.Length && exact.AsSpan().SequenceEqual(b), $"GetBytes(span) != GetBytes for {what}");
            Check.That(e.TryGetBytes(text, exact, out int written) && written == b.Length, $"TryGetBytes into an exact buffer failed for {what}");
            if (b.Length > 0)
            {
                Check.That(!e.TryGetBytes(text, new byte[b.Length - 1], out written), $"TryGetBytes into a short buffer succeeded for {what}");
            }

            string? expected = Sanitize(e, text);
            if (expected is not null)
            {
                Check.Equal(expected, WithReplacement(e).GetString(b), $"Round trip of {what}");
            }
        }
        else if (e.EncoderFallback is EncoderExceptionFallback && e is not UTF7Encoding)
        {
            Check.That(Sanitize(e, text, "") != text, $"Exception fallback threw {bytes} although everything is encodable for {what}");
        }

        var rng = new Random(seed);
        var chunked = Outcome<byte[]>.Of(() =>
        {
            Encoder encoder = e.GetEncoder();
            var output = new List<byte>();
            char[] chars = text.ToCharArray();
            int pos = 0;
            do
            {
                int n = Math.Min(chars.Length - pos, rng.Next(5));
                bool flush = pos + n == chars.Length && rng.Next(4) != 0;
                int expectedCount = encoder.GetByteCount(chars, pos, n, flush);
                byte[] buffer = new byte[e.GetMaxByteCount(n + 2)];
                int got = encoder.GetBytes(chars, pos, n, buffer, 0, flush);
                Check.Equal(expectedCount, got, $"Encoder.GetByteCount vs GetBytes for a {n}-char chunk at {pos} (flush={flush}) for {what}");
                output.AddRange(buffer.AsSpan(0, got).ToArray());
                pos += n;
                if (pos == chars.Length)
                {
                    if (!flush)
                    {
                        byte[] tail = new byte[e.GetMaxByteCount(2)];
                        output.AddRange(tail.AsSpan(0, encoder.GetBytes([], 0, 0, tail, 0, flush: true)).ToArray());
                    }

                    return output.ToArray();
                }
            }
            while (true);
        }, allowed);
        Check.That(bytes.SameAs(chunked, eq) || (bytes.Ok == chunked.Ok && !bytes.Ok), $"Chunked Encoder {chunked} != GetBytes {bytes} for {what}");

        // Known (UTF7-1, UTF7-2): UTF-7 Encoder.Convert duplicates or drops output when the output
        // buffer is small, and never reports completed after a surrogate pair followed by a
        // directly-encoded char.
        if (e is UTF7Encoding && !s_reportKnownIssues)
        {
            return;
        }

        int small = 4 + seed % 5 + 4 * Math.Max(1, e.EncoderFallback.MaxCharCount);
        var converted = Outcome<byte[]>.Of(() =>
        {
            Encoder encoder = e.GetEncoder();
            var output = new List<byte>();
            char[] chars = text.ToCharArray();
            byte[] buffer = new byte[small];
            int pos = 0;
            for (int iterations = 0; ; iterations++)
            {
                Check.That(iterations <= 2 * chars.Length + 16, $"Encoder.Convert makes no progress (output buffer {small}) for {what}");
                encoder.Convert(chars, pos, chars.Length - pos, buffer, 0, buffer.Length, true, out int used, out int produced, out bool completed);
                output.AddRange(buffer.AsSpan(0, produced).ToArray());
                pos += used;
                if (completed)
                {
                    Check.Equal(chars.Length, pos, $"Encoder.Convert completed without consuming all input for {what}");
                    return output.ToArray();
                }
            }
        }, allowed);
        Check.That(bytes.SameAs(converted, eq) || (bytes.Ok == converted.Ok && !bytes.Ok), $"Encoder.Convert with {small}-byte buffers {converted} != GetBytes {bytes} for {what}");
    }

    private static Encoding WithReplacement(Encoding e)
    {
        var clone = (Encoding)e.Clone();
        clone.EncoderFallback = new EncoderReplacementFallback("�");
        clone.DecoderFallback = new DecoderReplacementFallback("�");
        return clone;
    }

    /// <summary>
    /// What decoding <paramref name="bytes"/> must produce, or null when there's no reference
    /// (UTF-7, custom fallbacks). Invalid data becomes the replacement string: one per maximal
    /// subpart for UTF-8, per lone surrogate / trailing odd byte for UTF-16, per invalid or
    /// incomplete code unit for UTF-32, per byte >= 0x80 for ASCII.
    /// </summary>
    private static string? ReferenceDecode(Encoding e, byte[] bytes)
    {
        if (e.DecoderFallback is not DecoderReplacementFallback { DefaultString: var r })
        {
            return null;
        }

        var sb = new StringBuilder();
        switch (e)
        {
            case UTF8Encoding:
                ReferenceUtf8(bytes, sb, r, out _);
                return sb.ToString();
            case UnicodeEncoding:
            {
                bool bigEndian = e.CodePage == 1201;
                var units = new List<char>();
                for (int i = 0; i + 1 < bytes.Length; i += 2)
                {
                    units.Add((char)(bigEndian ? bytes[i] << 8 | bytes[i + 1] : bytes[i + 1] << 8 | bytes[i]));
                }

                AppendUtf16(units, sb, r);
                if (bytes.Length % 2 != 0)
                {
                    sb.Append(r);
                }

                return sb.ToString();
            }

            case UTF32Encoding:
            {
                bool bigEndian = e.CodePage == 12001;
                int i = 0;
                for (; i + 3 < bytes.Length; i += 4)
                {
                    uint v = bigEndian
                        ? (uint)(bytes[i] << 24 | bytes[i + 1] << 16 | bytes[i + 2] << 8 | bytes[i + 3])
                        : (uint)(bytes[i + 3] << 24 | bytes[i + 2] << 16 | bytes[i + 1] << 8 | bytes[i]);
                    if (Rune.IsValid(v))
                    {
                        sb.Append(new Rune(v).ToString());
                    }
                    else
                    {
                        sb.Append(r);
                    }
                }

                if (i < bytes.Length)
                {
                    sb.Append(r);
                }

                return sb.ToString();
            }

            case ASCIIEncoding:
                foreach (byte b in bytes)
                {
                    sb.Append(b < 0x80 ? ((char)b).ToString() : r);
                }

                return sb.ToString();
            default:
                return e.CodePage == 28591 ? new string(bytes.Select(b => (char)b).ToArray()) : null;
        }
    }

    private static void AppendUtf16(IReadOnlyList<char> units, StringBuilder sb, string replacement)
    {
        for (int i = 0; i < units.Count; i++)
        {
            char c = units[i];
            if (char.IsHighSurrogate(c) && i + 1 < units.Count && char.IsLowSurrogate(units[i + 1]))
            {
                sb.Append(c).Append(units[++i]);
            }
            else if (char.IsSurrogate(c))
            {
                sb.Append(replacement);
            }
            else
            {
                sb.Append(c);
            }
        }
    }

    /// <summary>Decodes UTF-8 with one replacement per maximal subpart (Unicode 15, §3.9 U+FFFD substitution).</summary>
    private static void ReferenceUtf8(ReadOnlySpan<byte> b, StringBuilder sb, string replacement, out int firstError)
    {
        firstError = -1;
        int i = 0;
        while (i < b.Length)
        {
            byte b0 = b[i];
            if (b0 < 0x80)
            {
                sb.Append((char)b0);
                i++;
                continue;
            }

            int need;
            int cp;
            if (b0 is >= 0xC2 and <= 0xDF) { need = 1; cp = b0 & 0x1F; }
            else if (b0 is >= 0xE0 and <= 0xEF) { need = 2; cp = b0 & 0x0F; }
            else if (b0 is >= 0xF0 and <= 0xF4) { need = 3; cp = b0 & 0x07; }
            else
            {
                if (firstError < 0) { firstError = i; }
                sb.Append(replacement);
                i++;
                continue;
            }

            int j = 1;
            for (; j <= need && i + j < b.Length; j++)
            {
                byte bj = b[i + j];
                byte lo = 0x80, hi = 0xBF;
                if (j == 1)
                {
                    if (b0 == 0xE0) { lo = 0xA0; }
                    else if (b0 == 0xED) { hi = 0x9F; }
                    else if (b0 == 0xF0) { lo = 0x90; }
                    else if (b0 == 0xF4) { hi = 0x8F; }
                }

                if (bj < lo || bj > hi)
                {
                    break;
                }

                cp = (cp << 6) | (bj & 0x3F);
            }

            if (j == need + 1)
            {
                sb.Append(new Rune(cp).ToString());
                i += j;
            }
            else
            {
                if (firstError < 0) { firstError = i; }
                sb.Append(replacement);
                i += j;
            }
        }
    }

    /// <summary>
    /// What encoding then decoding <paramref name="text"/> must produce: unencodable chars and
    /// lone surrogates become the encoder's replacement string. An unencodable surrogate pair is
    /// replaced twice, once per char, like Encoding.ASCII.GetBytes("\U0001F600") == "??".
    /// Null when there's no reference (UTF-7, custom fallbacks, unencodable replacement).
    /// </summary>
    private static string? Sanitize(Encoding e, string text) =>
        e is UTF7Encoding || e.EncoderFallback is not EncoderReplacementFallback { DefaultString: var r } ? null : Sanitize(e, text, r);

    private static string? Sanitize(Encoding e, string text, string r)
    {
        Func<int, bool> encodable = e switch
        {
            ASCIIEncoding => c => c < 0x80,
            _ when e.CodePage == 28591 => c => c <= 0xFF,
            _ => c => true,
        };
        if (!r.All(c => encodable(c)))
        {
            return null;
        }

        var sb = new StringBuilder();
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                int scalar = char.ConvertToUtf32(c, text[++i]);
                sb.Append(encodable(scalar) ? char.ConvertFromUtf32(scalar) : r + r);
            }
            else
            {
                sb.Append(!char.IsSurrogate(c) && encodable(c) ? c.ToString() : r);
            }
        }

        return sb.ToString();
    }

    private static void Utf8Helpers(byte[] bytes)
    {
        var sb = new StringBuilder();
        ReferenceUtf8(bytes, sb, "�", out int firstError);
        string expected = sb.ToString();
        string what = $"UTF-8 {Check.Show(bytes)}";

        Check.Equal(firstError < 0, Utf8.IsValid(bytes), $"Utf8.IsValid for {what}");
        char[] chars = new char[bytes.Length + 1];
        OperationStatus status = Utf8.ToUtf16(bytes, chars, out int read, out int written, replaceInvalidSequences: true);
        Check.That(status == OperationStatus.Done && read == bytes.Length && chars.AsSpan(0, written).SequenceEqual(expected), $"Utf8.ToUtf16(replace) {status} ({read}/{written}) != reference for {what}");
        status = Utf8.ToUtf16(bytes, chars, out read, out written, replaceInvalidSequences: false);
        Check.That(firstError < 0 ? status == OperationStatus.Done : status is OperationStatus.InvalidData or OperationStatus.NeedMoreData && read == firstError,
            $"Utf8.ToUtf16(no replace) {status} after {read} bytes, first error at {firstError}, for {what}");
        if (expected.Length > 0)
        {
            status = Utf8.ToUtf16(bytes, new char[expected.Length - 1], out read, out written, replaceInvalidSequences: true);
            Check.That(status == OperationStatus.DestinationTooSmall, $"Utf8.ToUtf16 into a short buffer gave {status} for {what}");
        }

        // Rune-by-rune decoding forwards.
        var runes = new StringBuilder();
        ReadOnlySpan<byte> rest = bytes;
        while (!rest.IsEmpty)
        {
            OperationStatus s = Rune.DecodeFromUtf8(rest, out Rune rune, out int consumed);
            Check.That(consumed > 0 && (s == OperationStatus.Done) == (rune != Rune.ReplacementChar || rest.StartsWith("�"u8)), $"Rune.DecodeFromUtf8 {s} consumed {consumed} at offset {bytes.Length - rest.Length} for {what}");
            runes.Append(rune.ToString());
            rest = rest.Slice(consumed);
        }

        Check.Equal(expected, runes.ToString(), $"Rune.DecodeFromUtf8 loop for {what}");

        // ASCII helpers.
        int firstNonAscii = Array.FindIndex(bytes, b => b >= 0x80);
        Check.Equal(firstNonAscii < 0, Ascii.IsValid(bytes), $"Ascii.IsValid(bytes) for {what}");
        status = Ascii.ToUtf16(bytes, chars, out written);
        int asciiPrefix = firstNonAscii < 0 ? bytes.Length : firstNonAscii;
        Check.That((status == OperationStatus.Done) == (firstNonAscii < 0) && written == asciiPrefix && chars.AsSpan(0, written).SequenceEqual(expected.AsSpan(0, asciiPrefix)),
            $"Ascii.ToUtf16 {status} wrote {written}, ASCII prefix {asciiPrefix}, for {what}");
        byte[] upper = new byte[bytes.Length];
        status = Ascii.ToUpper(bytes, upper, out written);
        Check.That(written == asciiPrefix && upper.AsSpan(0, written).SequenceEqual(Encoding.ASCII.GetBytes(expected.Substring(0, asciiPrefix).ToUpperInvariant())), $"Ascii.ToUpper {status} wrote {written} for {what}");
        Check.Equal(firstNonAscii < 0, Ascii.EqualsIgnoreCase(bytes, Encoding.Latin1.GetString(bytes).ToLowerInvariant()), $"Ascii.EqualsIgnoreCase(bytes, lower) for {what}");
    }

    private static void Utf16Helpers(string text)
    {
        var sb = new StringBuilder();
        AppendUtf16(text.ToCharArray(), sb, "�");
        string expected = sb.ToString();
        string what = $"UTF-16 {Check.Show(text)}";
        byte[] expectedUtf8 = Encoding.UTF8.GetBytes(expected);
        byte[] utf8 = new byte[text.Length * 3];
        OperationStatus status = Utf8.FromUtf16(text, utf8, out int read, out int written, replaceInvalidSequences: true);
        Check.That(status == OperationStatus.Done && read == text.Length && utf8.AsSpan(0, written).SequenceEqual(expectedUtf8), $"Utf8.FromUtf16(replace) {status} != reference for {what}");
        int firstError = -1;
        for (int i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1])) { i++; continue; }
            if (char.IsSurrogate(text[i])) { firstError = i; break; }
        }

        status = Utf8.FromUtf16(text, utf8, out read, out written, replaceInvalidSequences: false);
        Check.That(firstError < 0 ? status == OperationStatus.Done : status is OperationStatus.InvalidData or OperationStatus.NeedMoreData && read == firstError,
            $"Utf8.FromUtf16(no replace) {status} after {read} chars, first error at {firstError}, for {what}");

        var runes = new StringBuilder();
        ReadOnlySpan<char> rest = text;
        while (!rest.IsEmpty)
        {
            Rune.DecodeFromUtf16(rest, out Rune rune, out int consumed);
            Check.That(consumed > 0, $"Rune.DecodeFromUtf16 consumed nothing for {what}");
            runes.Append(rune.ToString());
            rest = rest.Slice(consumed);
        }

        Check.Equal(expected, runes.ToString(), $"Rune.DecodeFromUtf16 loop for {what}");

        int firstNonAscii = text.AsSpan().IndexOfAnyExceptInRange('\0', '\x7F');
        Check.Equal(firstNonAscii < 0, Ascii.IsValid(text), $"Ascii.IsValid(chars) for {what}");
        char[] upper = new char[text.Length];
        status = Ascii.ToUpper(text, upper, out written);
        int prefix = firstNonAscii < 0 ? text.Length : firstNonAscii;
        Check.That((status == OperationStatus.Done) == (firstNonAscii < 0) && written == prefix && upper.AsSpan(0, written).SequenceEqual(text.Substring(0, prefix).ToUpperInvariant()),
            $"Ascii.ToUpper(chars) {status} wrote {written}, prefix {prefix}, for {what}");
        byte[] ascii = new byte[text.Length];
        status = Ascii.FromUtf16(text, ascii, out written);
        Check.That((status == OperationStatus.Done) == (firstNonAscii < 0) && written == prefix, $"Ascii.FromUtf16 {status} wrote {written}, prefix {prefix}, for {what}");
        Check.Equal(firstNonAscii < 0, Ascii.Equals(ascii.AsSpan(0, written), text), $"Ascii.Equals(bytes, chars) for {what}");
    }

    /// <summary>Decoder fallback that returns input-chosen strings, including ill-formed UTF-16.</summary>
    private sealed class FuzzDecoderFallback(string[] replacements) : DecoderFallback
    {
        public override int MaxCharCount => replacements.Max(r => r.Length);

        public override DecoderFallbackBuffer CreateFallbackBuffer() => new Buffer(replacements);

        private sealed class Buffer(string[] replacements) : DecoderFallbackBuffer
        {
            private string _current = "";
            private int _position;

            public override bool Fallback(byte[] bytesUnknown, int index)
            {
                _current = replacements[(int)((uint)(bytesUnknown.Length + bytesUnknown[0]) % (uint)replacements.Length)];
                _position = 0;
                return _current.Length > 0;
            }

            public override char GetNextChar() => _position < _current.Length ? _current[_position++] : '\0';

            public override bool MovePrevious()
            {
                if (_position == 0)
                {
                    return false;
                }

                _position--;
                return true;
            }

            public override int Remaining => _current.Length - _position;

            public override void Reset()
            {
                _current = "";
                _position = 0;
            }
        }
    }

    /// <summary>Encoder fallback that returns input-chosen strings, including ill-formed UTF-16.</summary>
    private sealed class FuzzEncoderFallback(string[] replacements) : EncoderFallback
    {
        public override int MaxCharCount => replacements.Max(r => r.Length);

        public override EncoderFallbackBuffer CreateFallbackBuffer() => new Buffer(replacements);

        private sealed class Buffer(string[] replacements) : EncoderFallbackBuffer
        {
            private string _current = "";
            private int _position;

            public override bool Fallback(char charUnknown, int index) => Set(charUnknown);

            public override bool Fallback(char charUnknownHigh, char charUnknownLow, int index) => Set(charUnknownHigh + charUnknownLow);

            private bool Set(int key)
            {
                _current = replacements[(int)((uint)key % (uint)replacements.Length)];
                _position = 0;
                return _current.Length > 0;
            }

            public override char GetNextChar() => _position < _current.Length ? _current[_position++] : '\0';

            public override bool MovePrevious()
            {
                if (_position == 0)
                {
                    return false;
                }

                _position--;
                return true;
            }

            public override int Remaining => _current.Length - _position;

            public override void Reset()
            {
                _current = "";
                _position = 0;
            }
        }
    }
}
