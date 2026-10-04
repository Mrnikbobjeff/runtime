#nullable disable warnings
using System.Buffers;
using System.Buffers.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Guard-page memory safety for every Base64 / Base64Url decoding entry point (UTF-8 and UTF-16,
/// one-shot, streaming, in-place, Try*, IsValid, Convert.TryFromBase64Chars).
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0  bit 0: Base64Url; bit 1: isFinalBlock; bit 2: source starts after a guard page (else
///           ends at one); bit 3: same for the destination; bit 4: raw payload (else each byte below
///           0xF0 is mapped onto the alphabet and the rest onto whitespace, padding and odd chars, so
///           long valid inputs that reach the vector paths are easy to generate);
///           bits 5-6: destination size mode (exact, slightly short, scaled, max + slack)
///   byte 1  destination size parameter
///   byte 2  chunking / destination seed for the streaming decoder
///   rest    payload
/// Sources and destinations are exactly sized and sit against PROT_NONE pages (SHARPFUZZ_GUARD=1),
/// so an out-of-bounds vector load or store faults. Results must match the same call on plain
/// arrays, stay within bounds, and agree with the reference decoder whenever they report Done.
/// </remarks>
public static class Base64GuardTarget
{
    private const int MaxLength = 4096;
    private const string StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private const string Specials = " \t\r\n==%-_+/\0\u0080ÿĀĽ";

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        byte destSel = input.Byte();
        byte seed = input.Byte();
        ReadOnlySpan<byte> payload = input.Rest();
        if (payload.Length > MaxLength)
        {
            return;
        }

        bool url = (flags & 1) != 0;
        bool final = (flags & 2) != 0;
        bool srcAtStart = (flags & 4) != 0;
        bool dstAtStart = (flags & 8) != 0;
        bool raw = (flags & 0x10) != 0;
        int destMode = (flags >> 5) & 3;

        string alphabet = url ? UrlAlphabet : StdAlphabet;
        char[] text = new char[payload.Length];
        for (int i = 0; i < payload.Length; i++)
        {
            byte b = payload[i];
            text[i] = raw ? (char)b : b < 0xF0 ? alphabet[b & 63] : Specials[b - 0xF0];
        }

        byte[] utf8 = new byte[text.Length];
        char[] utf8AsChars = new char[text.Length];
        for (int i = 0; i < text.Length; i++)
        {
            utf8[i] = (byte)text[i];
            utf8AsChars[i] = (char)utf8[i];
        }

        byte[]? refChars = Base64Target.Reference(text, url);
        byte[]? refUtf8 = Base64Target.Reference(utf8AsChars, url);
        string what = $"{(url ? "Base64Url" : "Base64")} final={final} src@{(srcAtStart ? "start" : "end")} dst@{(dstAtStart ? "start" : "end")} " +
            $"{Check.Show(new string(text.AsSpan(0, Math.Min(text.Length, 120))))} (length {text.Length})";

        int maxDecoded = url ? Base64Url.GetMaxDecodedLength(text.Length) : Base64.GetMaxDecodedLength(text.Length);
        int DestLength(byte[]? reference)
        {
            int refLen = reference?.Length ?? maxDecoded;
            return destMode switch
            {
                0 => refLen,
                1 => Math.Max(0, refLen - 1 - (destSel & 7)),
                2 => (int)(destSel * (long)(maxDecoded + 4) / 255),
                _ => maxDecoded + (destSel & 7),
            };
        }

        Utf8Decode(utf8, refUtf8, url, final, srcAtStart, dstAtStart, DestLength(refUtf8), what);
        CharsDecode(text, refChars, url, final, srcAtStart, dstAtStart, DestLength(refChars), what);
        InPlace(utf8, refUtf8, url, srcAtStart, what);
        Validity(text, utf8, refChars, refUtf8, url, srcAtStart, what);
        Streaming(utf8, refUtf8, url, srcAtStart, dstAtStart, seed, what);
    }

    private delegate OperationStatus Decoder<T>(ReadOnlySpan<T> source, Span<byte> destination, out int consumed, out int written, bool final);

    private static void Compare<T>(Decoder<T> decode, string api, T[] source, byte[]? reference, bool url, bool final, bool srcAtStart, bool dstAtStart, int destLength, string what)
        where T : unmanaged
    {
        ReadOnlySpan<T> src = Guarded.Copy<T>(source, srcAtStart);
        Span<byte> dst = Guarded.Copy<byte>(new byte[destLength], dstAtStart);
        OperationStatus status = decode(src, dst, out int consumed, out int written, final);

        byte[] plainDst = new byte[destLength];
        OperationStatus plain = decode(source, plainDst, out int plainConsumed, out int plainWritten, final);

        string call = $"{api} into {destLength} bytes: {status} (consumed {consumed}, written {written})";
        Check.That(status == plain && consumed == plainConsumed && written == plainWritten && dst[..written].SequenceEqual(plainDst.AsSpan(0, plainWritten)),
            $"{call} but on plain arrays {plain} (consumed {plainConsumed}, written {plainWritten}): {what}");
        Check.That((uint)consumed <= (uint)source.Length && (uint)written <= (uint)destLength, $"{call} out of bounds: {what}");

        if (status == OperationStatus.Done && final)
        {
            Check.That(reference is not null && consumed == source.Length && dst[..written].SequenceEqual(reference),
                $"{call} but reference {Check.Show(reference)}: {what}");
        }

        if (reference is not null && written > 0)
        {
            // Whatever was written must be a prefix of the reference output.
            Check.That(written <= reference.Length && dst[..written].SequenceEqual(reference.AsSpan(0, written)),
                $"{call}: output is not a prefix of the reference {Check.Show(reference)}: {what}");
        }

        if (reference is not null && final && !url && destLength >= reference.Length)
        {
            Check.That(status == OperationStatus.Done, $"{call} for valid input with a large enough destination: {what}");
        }
    }

    private static void Utf8Decode(byte[] utf8, byte[]? reference, bool url, bool final, bool srcAtStart, bool dstAtStart, int destLength, string what)
    {
        if (url)
        {
            Compare<byte>(Base64Url.DecodeFromUtf8, "Base64Url.DecodeFromUtf8", utf8, reference, url, final, srcAtStart, dstAtStart, destLength, what);
        }
        else
        {
            Compare<byte>(Base64.DecodeFromUtf8, "Base64.DecodeFromUtf8", utf8, reference, url, final, srcAtStart, dstAtStart, destLength, what);
        }

        // Try* and the allocating overloads (which decode into a stackalloc'd or pooled buffer).
        ReadOnlySpan<byte> src = Guarded.Copy<byte>(utf8, srcAtStart);
        Span<byte> dst = Guarded.Copy<byte>(new byte[destLength], dstAtStart);
        try
        {
            bool ok = url ? Base64Url.TryDecodeFromUtf8(src, dst, out int written) : Base64.TryDecodeFromUtf8(src, dst, out written);
            Check.That(!ok || (reference is not null && dst[..written].SequenceEqual(reference)), $"TryDecodeFromUtf8 into {destLength} bytes gave {written} bytes, reference {Check.Show(reference)}: {what}");
        }
        catch (FormatException)
        {
        }

        try
        {
            byte[] decoded = url ? Base64Url.DecodeFromUtf8(src) : Base64.DecodeFromUtf8(src);
            Check.That(reference is not null && decoded.AsSpan().SequenceEqual(reference), $"DecodeFromUtf8(source) = {Check.Show(decoded)}, reference {Check.Show(reference)}: {what}");
        }
        catch (FormatException)
        {
        }
    }

    private static void CharsDecode(char[] text, byte[]? reference, bool url, bool final, bool srcAtStart, bool dstAtStart, int destLength, string what)
    {
        Decoder<char> decode = url
            ? (ReadOnlySpan<char> s, Span<byte> d, out int c, out int w, bool f) => Base64Url.DecodeFromChars(s, d, out c, out w, f)
            : (ReadOnlySpan<char> s, Span<byte> d, out int c, out int w, bool f) => Base64.DecodeFromChars(s, d, out c, out w, f);
        Compare(decode, url ? "Base64Url.DecodeFromChars" : "Base64.DecodeFromChars", text, reference, url, final, srcAtStart, dstAtStart, destLength, what);

        ReadOnlySpan<char> src = Guarded.Copy<char>(text, srcAtStart);
        Span<byte> dst = Guarded.Copy<byte>(new byte[destLength], dstAtStart);
        if (!url)
        {
            bool ok = Convert.TryFromBase64Chars(src, dst, out int written);
            Check.That(!ok || (reference is not null && dst[..written].SequenceEqual(reference)), $"Convert.TryFromBase64Chars into {destLength} bytes gave {written} bytes, reference {Check.Show(reference)}: {what}");
        }

        try
        {
            bool ok = url ? Base64Url.TryDecodeFromChars(src, dst, out int written) : Base64.TryDecodeFromChars(src, dst, out written);
            Check.That(!ok || (reference is not null && dst[..written].SequenceEqual(reference)), $"TryDecodeFromChars into {destLength} bytes gave {written} bytes, reference {Check.Show(reference)}: {what}");
        }
        catch (FormatException)
        {
        }

        try
        {
            byte[] decoded = url ? Base64Url.DecodeFromChars(src) : Base64.DecodeFromChars(src);
            Check.That(reference is not null && decoded.AsSpan().SequenceEqual(reference), $"DecodeFromChars(source) = {Check.Show(decoded)}, reference {Check.Show(reference)}: {what}");
        }
        catch (FormatException)
        {
        }
    }

    private static void InPlace(byte[] utf8, byte[]? reference, bool url, bool atStart, string what)
    {
        Span<byte> buffer = Guarded.Copy<byte>(utf8, atStart);
        if (url)
        {
            int written;
            try
            {
                written = Base64Url.DecodeFromUtf8InPlace(buffer);
            }
            catch (FormatException)
            {
                Check.That(reference is null, $"Base64Url.DecodeFromUtf8InPlace threw FormatException, reference {Check.Show(reference)}: {what}");
                return;
            }

            Check.That(reference is not null && buffer[..written].SequenceEqual(reference), $"Base64Url.DecodeFromUtf8InPlace wrote {Check.Show(buffer[..written].ToArray())}, reference {Check.Show(reference)}: {what}");
        }
        else
        {
            OperationStatus status = Base64.DecodeFromUtf8InPlace(buffer, out int written);
            Check.That((uint)written <= (uint)utf8.Length, $"Base64.DecodeFromUtf8InPlace written {written}: {what}");
            Check.That((status == OperationStatus.Done) == reference is not null && (reference is null || buffer[..written].SequenceEqual(reference)),
                $"Base64.DecodeFromUtf8InPlace {status} wrote {Check.Show(buffer[..written].ToArray())}, reference {Check.Show(reference)}: {what}");
        }
    }

    private static void Validity(char[] text, byte[] utf8, byte[]? refChars, byte[]? refUtf8, bool url, bool atStart, string what)
    {
        ReadOnlySpan<char> c = Guarded.Copy<char>(text, atStart);
        ReadOnlySpan<byte> b = Guarded.Copy<byte>(utf8, !atStart);
        bool okChars = url ? Base64Url.IsValid(c, out int lenChars) : Base64.IsValid(c, out lenChars);
        bool okUtf8 = url ? Base64Url.IsValid(b, out int lenUtf8) : Base64.IsValid(b, out lenUtf8);
        Check.That(okChars == refChars is not null && (!okChars || lenChars == refChars.Length), $"IsValid(chars) {okChars} ({lenChars}), reference {Check.Show(refChars)}: {what}");
        Check.That(okUtf8 == refUtf8 is not null && (!okUtf8 || lenUtf8 == refUtf8.Length), $"IsValid(UTF-8) {okUtf8} ({lenUtf8}), reference {Check.Show(refUtf8)}: {what}");
    }

    /// <summary>
    /// Feeds the input to DecodeFromUtf8 in chunks (isFinalBlock: false until the last one), each chunk
    /// copied to guarded memory and decoded into a guarded destination of a random size.
    /// </summary>
    private static void Streaming(byte[] utf8, byte[]? reference, bool url, bool srcAtStart, bool dstAtStart, byte seed, string what)
    {
        var rng = new Random(seed);
        var output = new List<byte>();
        int start = 0, available = 0;
        OperationStatus last = OperationStatus.Done;
        for (int step = 0; step < 4 * utf8.Length + 64; step++)
        {
            available = Math.Min(utf8.Length, available + 1 + rng.Next(80));
            bool final = available == utf8.Length;
            ReadOnlySpan<byte> src = Guarded.Copy<byte>(utf8.AsSpan(start, available - start), srcAtStart);
            int max = Base64Url.GetMaxDecodedLength(src.Length) + 2;
            Span<byte> dst = Guarded.Copy<byte>(new byte[rng.Next(2) == 0 ? max : rng.Next(max + 1)], dstAtStart);
            last = url
                ? Base64Url.DecodeFromUtf8(src, dst, out int consumed, out int written, final)
                : Base64.DecodeFromUtf8(src, dst, out consumed, out written, final);
            Check.That((uint)consumed <= (uint)src.Length && (uint)written <= (uint)dst.Length, $"streaming step {step}: {last} consumed {consumed} of {src.Length}, written {written} of {dst.Length}: {what}");
            output.AddRange(dst[..written].ToArray());
            start += consumed;
            if (last == OperationStatus.InvalidData || (final && last == OperationStatus.Done))
            {
                break;
            }
        }

        if (last == OperationStatus.Done)
        {
            Check.That(reference is not null && output.ToArray().AsSpan().SequenceEqual(reference),
                $"streaming decode ended Done with {Check.Show(output.ToArray())}, reference {Check.Show(reference)}: {what}");
        }
    }
}
