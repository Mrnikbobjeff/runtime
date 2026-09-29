#nullable disable warnings
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Text.Encoding.CodePages: the legacy SBCS / DBCS / ISO-2022 / GB18030 / ISCII encodings.</summary>
/// <remarks>
/// Input layout:
///   byte 0     code page (index into the provider's encodings)
///   byte 1     chunk pattern for the stateful Decoder / Encoder; 0x80: encode the rest as UTF-16LE text
///              instead of the decoded bytes
///   rest       bytes to decode (and the text to encode)
/// Checks: GetCharCount / GetByteCount match GetChars / GetBytes and stay within GetMaxCharCount /
/// GetMaxByteCount; a Decoder / Encoder fed the input in chunks (GetChars, GetCharCount and Convert
/// with a small output buffer) gives the same result as the one-shot call; text that decodes without
/// fallback encodes without fallback and decodes back to itself.
/// </remarks>
public static class CodePagesTarget
{
    private static readonly int[] s_codePages;
    private static readonly Dictionary<int, (Encoding Replace, Encoding Strict)> s_encodings = new();

    static CodePagesTarget()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        s_codePages = CodePagesEncodingProvider.Instance.GetEncodings().Select(e => e.CodePage).Order().ToArray();
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        int codePage = s_codePages[input.Byte() % s_codePages.Length];
        byte pattern = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 4096)
        {
            return;
        }

        if (!s_encodings.TryGetValue(codePage, out var encodings))
        {
            encodings = (Encoding.GetEncoding(codePage), Encoding.GetEncoding(codePage, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback));
            s_encodings[codePage] = encodings;
        }

        (Encoding enc, Encoding strict) = encodings;
        string what = $"code page {codePage} ({enc.WebName}), bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 64)))}{(bytes.Length > 64 ? "..." : "")}, chunks 0x{pattern:X2}";

        char[] chars = Decode(enc, bytes, pattern, what);
        string text = (pattern & 0x80) != 0 ? Encoding.Unicode.GetString(bytes, 0, bytes.Length & ~1) : new string(chars);
        Encode(enc, text, pattern, $"{what}, text {Check.Show(text)}");

        // Strict round trip: what decodes without fallback must encode without fallback and decode back.
        string decoded;
        try
        {
            decoded = strict.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return;
        }

        Check.Equal(new string(chars), decoded, $"strict GetString vs replacement GetChars for {what}");
        var encoded = Outcome<byte[]>.Of(() => strict.GetBytes(decoded), e => e is EncoderFallbackException);
        Check.That(encoded.Ok, $"strictly decoded text {Check.Show(decoded)} doesn't encode ({encoded}) for {what}");
        string again = strict.GetString(encoded.Value);
        if (!s_lossyRoundTrip.Contains(codePage))
        {
            Check.Equal(decoded, again, $"decode(encode(decoded)) via 0x{Convert.ToHexString(encoded.Value)} for {what}");
        }
    }

    // ISO-2022-JP (50220, 50222) encodes half-width katakana as full-width.
    private static readonly HashSet<int> s_lossyRoundTrip = [50220, 50222];

    /// <summary>The chunk sizes 1-8 taken in turn from the pattern bits (a size may be 0: an empty call).</summary>
    private static IEnumerable<int> Chunks(int total, byte pattern)
    {
        int position = 0, k = 0, last = 1;
        while (position < total)
        {
            int size = Math.Min(total - position, (pattern >> (k++ % 3 * 2) & 3) switch { 0 => 1, 1 => 2, 2 => last == 0 ? 1 : 0, _ => 3 + pattern % 5 });
            yield return size;
            position += size;
            last = size;
        }
    }

    private static char[] Decode(Encoding enc, byte[] bytes, byte pattern, string what)
    {
        char[] chars = enc.GetChars(bytes);
        Check.Equal(chars.Length, enc.GetCharCount(bytes), $"GetCharCount for {what}");
        Check.That(chars.Length <= enc.GetMaxCharCount(bytes.Length), $"{chars.Length} chars > GetMaxCharCount({bytes.Length}) = {enc.GetMaxCharCount(bytes.Length)} for {what}");

        // Decoder.GetChars in chunks, flushing with the last one; GetCharCount must predict each call.
        Decoder decoder = enc.GetDecoder();
        var result = new List<char>();
        int offset = 0;
        List<int> chunks = Chunks(bytes.Length, pattern).ToList();
        for (int i = 0; i <= chunks.Count; i++)
        {
            int size = i < chunks.Count ? chunks[i] : 0;
            bool flush = i == chunks.Count;
            int count = decoder.GetCharCount(bytes, offset, size, flush);
            char[] buffer = new char[count + 4];
            int written = decoder.GetChars(bytes, offset, size, buffer, 0, flush);
            Check.Equal(count, written, $"Decoder.GetCharCount vs GetChars for chunk {i} ({offset}+{size}, flush {flush}) of {what}");
            result.AddRange(buffer.AsSpan(0, written).ToArray());
            offset += size;
        }

        Check.SequenceEqual<char>(chars, result.ToArray(), $"chunked Decoder.GetChars for {what}");

        // Decoder.Convert into a small buffer until everything is consumed and flushed.
        decoder = enc.GetDecoder();
        result.Clear();
        char[] small = new char[Math.Max(enc.GetMaxCharCount(1), 2) + pattern % 4];
        ReadOnlySpan<byte> rest = bytes;
        for (int guard = 0; ; guard++)
        {
            Check.That(guard < 4 * bytes.Length + 64, $"Decoder.Convert makes no progress for {what}");
            decoder.Convert(rest, small, flush: true, out int used, out int produced, out bool completed);
            result.AddRange(small.AsSpan(0, produced).ToArray());
            rest = rest.Slice(used);
            if (completed)
            {
                Check.That(rest.IsEmpty, $"Decoder.Convert completed with {rest.Length} bytes left for {what}");
                break;
            }
        }

        Check.SequenceEqual<char>(chars, result.ToArray(), $"Decoder.Convert into a {small.Length}-char buffer for {what}");
        return chars;
    }

    private static void Encode(Encoding enc, string text, byte pattern, string what)
    {
        byte[] bytes = enc.GetBytes(text);
        Check.Equal(bytes.Length, enc.GetByteCount(text), $"GetByteCount for {what}");
        Check.That(bytes.Length <= enc.GetMaxByteCount(text.Length), $"{bytes.Length} bytes > GetMaxByteCount({text.Length}) = {enc.GetMaxByteCount(text.Length)} for {what}");

        // Encoder.GetBytes in chunks (splitting surrogate pairs too), flushing with the last one.
        Encoder encoder = enc.GetEncoder();
        char[] chars = text.ToCharArray();
        var result = new List<byte>();
        int offset = 0;
        List<int> chunks = Chunks(chars.Length, (byte)(pattern ^ 0x5A)).ToList();
        for (int i = 0; i <= chunks.Count; i++)
        {
            int size = i < chunks.Count ? chunks[i] : 0;
            bool flush = i == chunks.Count;
            int count = encoder.GetByteCount(chars, offset, size, flush);
            byte[] buffer = new byte[count + 8];
            int written = encoder.GetBytes(chars, offset, size, buffer, 0, flush);
            Check.Equal(count, written, $"Encoder.GetByteCount vs GetBytes for chunk {i} ({offset}+{size}, flush {flush}) of {what}");
            result.AddRange(buffer.AsSpan(0, written).ToArray());
            offset += size;
        }

        Check.SequenceEqual<byte>(bytes, result.ToArray(), $"chunked Encoder.GetBytes for {what}");

        // Encoder.Convert into a small buffer (large enough for any one character's bytes).
        // Known (CP-CONVERT-1): when the output fills up at a surrogate pair that needs the fallback,
        // Encoder.Convert writes one replacement where GetBytes writes two (SBCS code pages), or throws
        // ArgumentException (DBCS code pages).
        bool known = !s_reportKnownIssues && text.Any(char.IsSurrogate);
        encoder = enc.GetEncoder();
        result.Clear();
        byte[] small = new byte[Math.Max(enc.GetMaxByteCount(2), 8) + pattern % 4];
        ReadOnlySpan<char> rest = chars;
        for (int guard = 0; ; guard++)
        {
            Check.That(guard < 4 * chars.Length + 64, $"Encoder.Convert makes no progress for {what}");
            int used, produced;
            bool completed;
            try
            {
                encoder.Convert(rest, small, flush: true, out used, out produced, out completed);
            }
            catch (ArgumentException) when (known)
            {
                return;
            }

            result.AddRange(small.AsSpan(0, produced).ToArray());
            rest = rest.Slice(used);
            if (completed)
            {
                Check.That(rest.IsEmpty, $"Encoder.Convert completed with {rest.Length} chars left for {what}");
                break;
            }
        }

        if (!known)
        {
            Check.SequenceEqual<byte>(bytes, result.ToArray(), $"Encoder.Convert into a {small.Length}-byte buffer for {what}");
        }
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;
}
