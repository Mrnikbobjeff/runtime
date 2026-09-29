#nullable disable warnings
using System.Buffers;
using System.Buffers.Text;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes Base64, Base64Url and hex decoding/encoding (Convert, Base64, Base64Url).</summary>
/// <remarks>
/// Input layout:
///   byte 0     low 2 bits: mode (0 Base64 decode, 1 Base64Url decode, 2 hex decode, 3 encode);
///              0x04: widen the payload to chars as UTF-16LE pairs instead of Latin-1
///   byte 1     chunking seed for the streaming APIs
///   rest       payload
/// Decoding: every API (Convert string/span/char[], Base64 UTF-8/in-place/IsValid, Base64Url
/// chars/UTF-8/Try*/IsValid, Convert.FromHexString overloads) must agree with each other and with
/// a reference decoder, streaming (isFinalBlock=false) decoding must match one-shot decoding,
/// and short destinations must report DestinationTooSmall/false. Encoding: all encoders agree
/// and round-trip.
/// </remarks>
public static class Base64Target
{
    private const int MaxLength = 4096;

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        byte chunkSeed = input.Byte();
        byte[] payload = input.Rest().ToArray();
        if (payload.Length > MaxLength)
        {
            return;
        }

        string chars = (mode & 4) != 0
            ? new string(System.Runtime.InteropServices.MemoryMarshal.Cast<byte, char>(payload.AsSpan(0, payload.Length & ~1)))
            : Encoding.Latin1.GetString(payload);
        // In Latin-1 mode chars[i] == payload[i], so the UTF-8 APIs see the same symbols.
        byte[]? utf8 = (mode & 4) == 0 ? payload : null;
        switch (mode & 3)
        {
            case 0: DecodeBase64(chars, utf8, chunkSeed); break;
            case 1: DecodeBase64Url(chars, utf8, chunkSeed); break;
            case 2: DecodeHex(chars, utf8); break;
            default: Encode(payload, chunkSeed); break;
        }
    }

    private static readonly byte[] s_decodeMap = BuildMap("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    private static readonly byte[] s_decodeMapUrl = BuildMap("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

    private static byte[] BuildMap(string alphabet)
    {
        byte[] map = new byte[0x10000];
        map.AsSpan().Fill(0xFF);
        for (int i = 0; i < alphabet.Length; i++)
        {
            map[alphabet[i]] = (byte)i;
        }

        return map;
    }

    private static bool IsBase64Space(char c) => c is ' ' or '\t' or '\r' or '\n';

    /// <summary>
    /// Reference Base64 decoder: whitespace (space, tab, CR, LF) is ignored anywhere; the rest must
    /// be a multiple of 4 (unless <paramref name="url"/>, where the final block may be 2 or 3 chars
    /// long) with at most two '=' at the very end, and the unused low bits of the last symbol are 0.
    /// Returns null for invalid input.
    /// </summary>
    private static byte[]? Reference(ReadOnlySpan<char> text, bool url)
    {
        var symbols = new List<char>(text.Length);
        foreach (char c in text)
        {
            if (!IsBase64Space(c))
            {
                symbols.Add(c);
            }
        }

        // Base64Url also accepts '%' (the URL-encoded form of '=') as padding.
        int padding = 0;
        while (padding < symbols.Count && symbols[symbols.Count - 1 - padding] is '=' or '%' && (url || symbols[symbols.Count - 1 - padding] == '='))
        {
            padding++;
        }

        int length = symbols.Count - padding;
        if (padding > 2)
        {
            return null;
        }

        if (url)
        {
            // Padding is optional and may be partial ("QQ=", like "QQ" or "QQ=="), but it can't follow
            // a complete block or extend past the end of the final one ("QQQ==" is invalid).
            if (length % 4 == 1 || (padding > 0 && (length % 4 == 0 || length % 4 + padding > 4)))
            {
                return null;
            }
        }
        else if (symbols.Count % 4 != 0 || (padding > 0 && length % 4 == 0))
        {
            return null;
        }

        byte[] map = url ? s_decodeMapUrl : s_decodeMap;
        var output = new List<byte>(length * 3 / 4);
        int acc = 0, bits = 0;
        for (int i = 0; i < length; i++)
        {
            byte v = map[symbols[i]];
            if (v == 0xFF)
            {
                return null;
            }

            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)(acc >> bits));
                acc &= (1 << bits) - 1;
            }
        }

        return acc == 0 ? output.ToArray() : null;
    }

    private static string Describe(ReadOnlySpan<char> text) => Check.Show(new string(text.Slice(0, Math.Min(text.Length, 80))));

    private static void DecodeBase64(string chars, byte[]? utf8Payload, byte chunkSeed)
    {
        byte[]? reference = Reference(chars, url: false);
        string what = $"Base64 {Describe(chars)} (length {chars.Length})";

        var convert = Outcome<byte[]>.Of(() => Convert.FromBase64String(chars), e => e is FormatException);
        Check.That(convert.Ok == reference is not null && (!convert.Ok || convert.Value.AsSpan().SequenceEqual(reference)),
            $"Convert.FromBase64String {convert} but reference {Check.Show(reference)} for {what}");
        var charArray = Outcome<byte[]>.Of(() => Convert.FromBase64CharArray(chars.ToCharArray(), 0, chars.Length), e => e is FormatException);
        Check.That(convert.SameAs(charArray, new Check.By<byte[]>((a, b) => a.AsSpan().SequenceEqual(b))), $"FromBase64CharArray {charArray} != FromBase64String {convert} for {what}");

        byte[] buffer = new byte[chars.Length];
        bool tryOk = Convert.TryFromBase64String(chars, buffer, out int written);
        Check.That(tryOk == reference is not null && (!tryOk || buffer.AsSpan(0, written).SequenceEqual(reference)), $"TryFromBase64String {tryOk} for {what}");
        tryOk = Convert.TryFromBase64Chars(chars, buffer, out written);
        Check.That(tryOk == reference is not null && (!tryOk || buffer.AsSpan(0, written).SequenceEqual(reference)), $"TryFromBase64Chars {tryOk} for {what}");
        if (reference is { Length: > 0 })
        {
            Check.That(!Convert.TryFromBase64String(chars, new byte[reference.Length - 1], out written) && written == 0, $"TryFromBase64String into a short buffer succeeded for {what}");
        }

        Check.That(Base64.IsValid(chars.AsSpan(), out int decodedLength) == reference is not null && (reference is null || decodedLength == reference.Length),
            $"Base64.IsValid(chars) disagrees with reference {Check.Show(reference)} (decodedLength {decodedLength}) for {what}");
        Check.Equal(reference is not null, Base64.IsValid(chars.AsSpan()), $"Base64.IsValid(chars) without length for {what}");

        // The UTF-8 APIs see the same text when every char is ASCII.
        if (utf8Payload is null)
        {
            return;
        }

        Check.That(Base64.IsValid(utf8Payload, out decodedLength) == reference is not null && (reference is null || decodedLength == reference.Length),
            $"Base64.IsValid(UTF-8) disagrees with reference (decodedLength {decodedLength}) for {what}");

        OperationStatus status = Base64.DecodeFromUtf8(utf8Payload, buffer, out int consumed, out written, isFinalBlock: true);
        Check.That((status == OperationStatus.Done) == reference is not null, $"Base64.DecodeFromUtf8 {status} (consumed {consumed}, written {written}) but reference {Check.Show(reference)} for {what}");
        if (reference is not null)
        {
            Check.That(consumed == utf8Payload.Length && buffer.AsSpan(0, written).SequenceEqual(reference), $"Base64.DecodeFromUtf8 output (consumed {consumed}, written {written}) != reference for {what}");
            if (reference.Length > 0)
            {
                byte[] shortBuffer = new byte[reference.Length - 1];
                status = Base64.DecodeFromUtf8(utf8Payload, shortBuffer, out consumed, out written, isFinalBlock: true);
                Check.That(status == OperationStatus.DestinationTooSmall && written <= shortBuffer.Length && shortBuffer.AsSpan(0, written).SequenceEqual(reference.AsSpan(0, written)),
                    $"Base64.DecodeFromUtf8 into {shortBuffer.Length} bytes gave {status} (consumed {consumed}, written {written}) for {what}");
            }
        }

        byte[] inPlace = (byte[])utf8Payload.Clone();
        status = Base64.DecodeFromUtf8InPlace(inPlace, out written);
        Check.That((status == OperationStatus.Done) == reference is not null && (reference is null || inPlace.AsSpan(0, written).SequenceEqual(reference)),
            $"Base64.DecodeFromUtf8InPlace {status} (written {written}) but reference {Check.Show(reference)} for {what}");

        if (reference is not null)
        {
            byte[] streamed = Stream(utf8Payload, chunkSeed, (src, dst, final) => (Base64.DecodeFromUtf8(src, dst, out int c, out int w, final), c, w), out OperationStatus last);
            Check.That((last == OperationStatus.Done && streamed.AsSpan().SequenceEqual(reference)) || IsKnownStreamingIssue(last, chars),
                $"Streaming Base64.DecodeFromUtf8 ended with {last}, output {Check.Show(streamed)} != reference for {what}");
        }
    }

    // Known (BASE64-STREAM-1): with isFinalBlock: false, DecodeFromUtf8 returns InvalidData for valid
    // input containing whitespace when a chunk ends inside a whitespace-interrupted block.
    private static bool IsKnownStreamingIssue(OperationStatus last, string chars) =>
        !s_reportKnownIssues && last == OperationStatus.InvalidData && chars.Any(IsBase64Space);

    /// <summary>
    /// Feeds <paramref name="source"/> to a streaming decoder in chunks (isFinalBlock=false until the
    /// last chunk), carrying unconsumed input over like a caller reading from a stream would.
    /// </summary>
    private static byte[] Stream(byte[] source, byte seed, Func<byte[], byte[], bool, (OperationStatus, int, int)> step, out OperationStatus last)
    {
        var output = new List<byte>();
        byte[] dst = new byte[2 * source.Length + 16];
        int start = 0, available = 0;
        var rng = new Random(seed);
        last = OperationStatus.Done;
        while (true)
        {
            available = Math.Min(source.Length, available + 1 + rng.Next(8));
            bool final = available == source.Length;
            (last, int consumed, int written) = step(source[start..available], dst, final);
            output.AddRange(dst.AsSpan(0, written).ToArray());
            start += consumed;
            if (last == OperationStatus.InvalidData || (final && last != OperationStatus.NeedMoreData) || (final && consumed == 0))
            {
                return output.ToArray();
            }
        }
    }

    private static void DecodeBase64Url(string chars, byte[]? utf8Payload, byte chunkSeed)
    {
        byte[]? reference = Reference(chars, url: true);
        string what = $"Base64Url {Describe(chars)} (length {chars.Length})";
        var eq = new Check.By<byte[]>((a, b) => a.AsSpan().SequenceEqual(b));

        var fromChars = Outcome<byte[]>.Of(() => Base64Url.DecodeFromChars(chars), e => e is FormatException);
        Check.That(fromChars.Ok == reference is not null && (!fromChars.Ok || fromChars.Value.AsSpan().SequenceEqual(reference)),
            $"Base64Url.DecodeFromChars {fromChars} but reference {Check.Show(reference)} for {what}");
        byte[] buffer = new byte[chars.Length + 3];
        // TryDecode* throw FormatException for invalid input (documented); false means "destination too small".
        var tryChars = Outcome<(bool, int)>.Of(() => (Base64Url.TryDecodeFromChars(chars, buffer, out int w), w), e => e is FormatException);
        Check.That(tryChars.Ok == fromChars.Ok && (!tryChars.Ok || (tryChars.Value.Item1 && buffer.AsSpan(0, tryChars.Value.Item2).SequenceEqual(fromChars.Value))),
            $"Base64Url.TryDecodeFromChars {tryChars} != DecodeFromChars {fromChars} for {what}");
        OperationStatus status = Base64Url.DecodeFromChars(chars, buffer, out int consumed, out int written, isFinalBlock: true);
        Check.That((status == OperationStatus.Done) == fromChars.Ok && (!fromChars.Ok || (consumed == chars.Length && buffer.AsSpan(0, written).SequenceEqual(fromChars.Value))),
            $"Base64Url.DecodeFromChars(OperationStatus) {status} (consumed {consumed}, written {written}) != {fromChars} for {what}");
        Check.That(Base64Url.IsValid(chars.AsSpan(), out int decodedLength) == fromChars.Ok && (!fromChars.Ok || decodedLength == fromChars.Value.Length),
            $"Base64Url.IsValid(chars) (decodedLength {decodedLength}) != DecodeFromChars {fromChars} for {what}");
        // Known (BASE64URL-1): unpadded input whose length isn't a multiple of 4 reports InvalidData
        // instead of DestinationTooSmall for short destinations, so TryDecode* throws FormatException.
        bool unpaddedTail = chars.Count(c => !IsBase64Space(c)) % 4 != 0;
        if (fromChars.Ok && fromChars.Value.Length > 0 && (s_reportKnownIssues || !unpaddedTail))
        {
            byte[] shortBuffer = new byte[fromChars.Value.Length - 1];
            var tryShort = Outcome<bool>.Of(() => Base64Url.TryDecodeFromChars(chars, shortBuffer, out _), e => e is FormatException);
            Check.That(tryShort.Ok && !tryShort.Value, $"Base64Url.TryDecodeFromChars into a short buffer gave {tryShort} for {what}");
            status = Base64Url.DecodeFromChars(chars, shortBuffer, out consumed, out written, isFinalBlock: true);
            Check.That(status == OperationStatus.DestinationTooSmall && fromChars.Value.AsSpan().StartsWith(shortBuffer.AsSpan(0, written)),
                $"Base64Url.DecodeFromChars into a short buffer gave {status} (consumed {consumed}, written {written}) for {what}");
            if (utf8Payload is not null)
            {
                var tryShort8 = Outcome<bool>.Of(() => Base64Url.TryDecodeFromUtf8(utf8Payload, shortBuffer, out _), e => e is FormatException);
                Check.That(tryShort8.Ok && !tryShort8.Value, $"Base64Url.TryDecodeFromUtf8 into a short buffer gave {tryShort8} for {what}");
            }
        }

        if (utf8Payload is null)
        {
            return;
        }

        var fromUtf8 = Outcome<byte[]>.Of(() => Base64Url.DecodeFromUtf8(utf8Payload), e => e is FormatException);
        Check.That(fromUtf8.SameAs(fromChars, eq), $"Base64Url.DecodeFromUtf8 {fromUtf8} != DecodeFromChars {fromChars} for {what}");
        var tryUtf8 = Outcome<(bool, int)>.Of(() => (Base64Url.TryDecodeFromUtf8(utf8Payload, buffer, out int w), w), e => e is FormatException);
        Check.That(tryUtf8.Ok == fromChars.Ok && (!tryUtf8.Ok || (tryUtf8.Value.Item1 && buffer.AsSpan(0, tryUtf8.Value.Item2).SequenceEqual(fromChars.Value))),
            $"Base64Url.TryDecodeFromUtf8 {tryUtf8} != DecodeFromChars {fromChars} for {what}");
        Check.That(Base64Url.IsValid(utf8Payload.AsSpan(), out decodedLength) == fromChars.Ok && (!fromChars.Ok || decodedLength == fromChars.Value.Length),
            $"Base64Url.IsValid(UTF-8) (decodedLength {decodedLength}) != DecodeFromChars {fromChars} for {what}");
        byte[] inPlace = (byte[])utf8Payload.Clone();
        var inPlaceResult = Outcome<int>.Of(() => Base64Url.DecodeFromUtf8InPlace(inPlace), e => e is FormatException);
        Check.That(inPlaceResult.Ok == fromChars.Ok && (!fromChars.Ok || inPlace.AsSpan(0, inPlaceResult.Value).SequenceEqual(fromChars.Value)),
            $"Base64Url.DecodeFromUtf8InPlace {inPlaceResult} != DecodeFromChars {fromChars} for {what}");
        if (fromChars.Ok)
        {
            byte[] streamed = Stream(utf8Payload, chunkSeed, (src, dst, final) => (Base64Url.DecodeFromUtf8(src, dst, out int c, out int w, final), c, w), out OperationStatus last);
            Check.That((last == OperationStatus.Done && streamed.AsSpan().SequenceEqual(fromChars.Value)) || IsKnownStreamingIssue(last, chars),
                $"Streaming Base64Url.DecodeFromUtf8 ended with {last}, output {Check.Show(streamed)} != {fromChars} for {what}");
        }
    }

    private static void DecodeHex(string chars, byte[]? utf8Payload)
    {
        byte[]? reference = null;
        if (chars.Length % 2 == 0 && chars.All(char.IsAsciiHexDigit))
        {
            reference = new byte[chars.Length / 2];
            for (int i = 0; i < reference.Length; i++)
            {
                reference[i] = (byte)(HexValue(chars[2 * i]) << 4 | HexValue(chars[2 * i + 1]));
            }
        }

        string what = $"hex {Describe(chars)} (length {chars.Length})";
        var eq = new Check.By<byte[]>((a, b) => a.AsSpan().SequenceEqual(b));
        var fromString = Outcome<byte[]>.Of(() => Convert.FromHexString(chars), e => e is FormatException);
        Check.That(fromString.Ok == reference is not null && (!fromString.Ok || fromString.Value.AsSpan().SequenceEqual(reference)),
            $"Convert.FromHexString {fromString} but reference {Check.Show(reference)} for {what}");
        var fromSpan = Outcome<byte[]>.Of(() => Convert.FromHexString(chars.AsSpan()), e => e is FormatException);
        Check.That(fromString.SameAs(fromSpan, eq), $"FromHexString(span) {fromSpan} != FromHexString(string) {fromString} for {what}");

        // OperationStatus overloads: decode as much as possible.
        byte[] buffer = new byte[chars.Length / 2 + 1];
        OperationStatus status = Convert.FromHexString(chars, buffer, out int consumed, out int written);
        int validPrefix = 0;
        while (validPrefix < chars.Length && char.IsAsciiHexDigit(chars[validPrefix]))
        {
            validPrefix++;
        }

        // The odd trailing char of an odd-length input isn't examined: that's NeedMoreData.
        bool oddTailOnly = chars.Length % 2 == 1 && validPrefix >= chars.Length - 1;
        OperationStatus expected = reference is not null ? OperationStatus.Done : oddTailOnly ? OperationStatus.NeedMoreData : OperationStatus.InvalidData;
        int expectedConsumed = expected == OperationStatus.InvalidData ? validPrefix : 2 * (validPrefix / 2);
        if (!s_reportKnownIssues && expected == OperationStatus.InvalidData && validPrefix % 2 == 0 && validPrefix + 1 < chars.Length && !char.IsAsciiHexDigit(chars[validPrefix + 1]))
        {
            expectedConsumed++; // Known (HEX-1): a pair with two invalid chars still counts the first as consumed.
        }

        Check.That(status == expected && consumed == expectedConsumed && written == validPrefix / 2,
            $"Convert.FromHexString(OperationStatus) {status} (consumed {consumed}, written {written}), expected {expected} (consumed {expectedConsumed}, written {validPrefix / 2}), for {what}");
        OperationStatus spanStatus = Convert.FromHexString(chars.AsSpan(), buffer, out int consumed2, out int written2);
        Check.That(spanStatus == status && consumed2 == consumed && written2 == written, $"FromHexString(span, OperationStatus) {spanStatus} != string overload {status} for {what}");
        if (reference is { Length: > 0 })
        {
            status = Convert.FromHexString(chars, new byte[reference.Length - 1], out consumed, out written);
            Check.That(status == OperationStatus.DestinationTooSmall && written == reference.Length - 1 && consumed == 2 * written,
                $"FromHexString into a short buffer gave {status} (consumed {consumed}, written {written}) for {what}");
        }

        if (utf8Payload is null)
        {
            return;
        }

        var fromUtf8 = Outcome<byte[]>.Of(() => Convert.FromHexString(utf8Payload.AsSpan()), e => e is FormatException);
        Check.That(fromString.SameAs(fromUtf8, eq), $"FromHexString(UTF-8) {fromUtf8} != FromHexString(string) {fromString} for {what}");
        status = Convert.FromHexString(utf8Payload.AsSpan(), buffer, out consumed2, out written2);
        Check.That(status == expected && consumed2 == expectedConsumed && written2 == validPrefix / 2, $"FromHexString(UTF-8, OperationStatus) {status} (consumed {consumed2}, written {written2}) != expected {expected} (consumed {expectedConsumed}) for {what}");
    }

    private static int HexValue(char c) => c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;

    private static void Encode(byte[] bytes, byte chunkSeed)
    {
        string what = $"bytes {Check.Show(bytes)} (length {bytes.Length})";
        string b64 = Convert.ToBase64String(bytes);
        Check.That(Convert.FromBase64String(b64).AsSpan().SequenceEqual(bytes), $"ToBase64String doesn't round-trip for {what}");
        string lines = Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks);
        Check.Equal(b64, lines.Replace("\r\n", ""), $"ToBase64String(InsertLineBreaks) minus line breaks for {what}");
        Check.That(lines.Split("\r\n").All(l => l.Length <= 76), $"ToBase64String(InsertLineBreaks) has a line over 76 chars for {what}");
        Check.That(Convert.FromBase64String(lines).AsSpan().SequenceEqual(bytes), $"InsertLineBreaks output doesn't round-trip for {what}");

        char[] chars = new char[b64.Length];
        Check.That(Convert.TryToBase64Chars(bytes, chars, out int written) && written == b64.Length && chars.AsSpan().SequenceEqual(b64), $"TryToBase64Chars != ToBase64String for {what}");
        Check.That(b64.Length == 0 || !Convert.TryToBase64Chars(bytes, chars.AsSpan(1), out _), $"TryToBase64Chars into a short buffer succeeded for {what}");
        char[] lineChars = new char[lines.Length];
        Check.That(Convert.TryToBase64Chars(bytes, lineChars, out written, Base64FormattingOptions.InsertLineBreaks) && lineChars.AsSpan(0, written).SequenceEqual(lines), $"TryToBase64Chars(InsertLineBreaks) != ToBase64String for {what}");

        byte[] utf8 = new byte[Base64.GetMaxEncodedToUtf8Length(bytes.Length)];
        OperationStatus status = Base64.EncodeToUtf8(bytes, utf8, out int consumed, out written);
        Check.That(status == OperationStatus.Done && consumed == bytes.Length && Encoding.ASCII.GetString(utf8, 0, written) == b64, $"Base64.EncodeToUtf8 {status} != ToBase64String for {what}");
        byte[] inPlace = new byte[utf8.Length];
        bytes.CopyTo(inPlace, 0);
        status = Base64.EncodeToUtf8InPlace(inPlace, bytes.Length, out written);
        Check.That(status == OperationStatus.Done && Encoding.ASCII.GetString(inPlace, 0, written) == b64, $"Base64.EncodeToUtf8InPlace {status} != ToBase64String for {what}");
        byte[] streamed = Stream(bytes, chunkSeed, (src, dst, final) => (Base64.EncodeToUtf8(src, dst, out int c, out int w, final), c, w), out OperationStatus last);
        Check.That(last == OperationStatus.Done && Encoding.ASCII.GetString(streamed) == b64, $"Streaming Base64.EncodeToUtf8 ended with {last}, output {Check.Show(Encoding.ASCII.GetString(streamed))} != ToBase64String for {what}");
        streamed = Stream(bytes, chunkSeed, (src, dst, final) => (Base64Url.EncodeToUtf8(src, dst, out int c, out int w, final), c, w), out last);
        Check.That(last == OperationStatus.Done && Encoding.ASCII.GetString(streamed) == Base64Url.EncodeToString(bytes), $"Streaming Base64Url.EncodeToUtf8 ended with {last} for {what}");

        string url = Base64Url.EncodeToString(bytes);
        Check.Equal(b64.TrimEnd('=').Replace('+', '-').Replace('/', '_'), url, $"Base64Url.EncodeToString for {what}");
        Check.Equal(url, new string(Base64Url.EncodeToChars(bytes)), $"Base64Url.EncodeToChars for {what}");
        Check.Equal(url, Encoding.ASCII.GetString(Base64Url.EncodeToUtf8(bytes)), $"Base64Url.EncodeToUtf8 for {what}");
        Check.Equal(url.Length, Base64Url.GetEncodedLength(bytes.Length), $"Base64Url.GetEncodedLength for {what}");
        Check.That(Base64Url.DecodeFromChars(url).AsSpan().SequenceEqual(bytes), $"Base64Url doesn't round-trip for {what}");
        byte[] urlInPlace = new byte[Math.Max(url.Length, bytes.Length)];
        bytes.CopyTo(urlInPlace, 0);
        Check.That(Base64Url.TryEncodeToUtf8InPlace(urlInPlace, bytes.Length, out written) && Encoding.ASCII.GetString(urlInPlace, 0, written) == url, $"Base64Url.TryEncodeToUtf8InPlace for {what}");

        string hex = Convert.ToHexString(bytes);
        Check.Equal(hex.ToLowerInvariant(), Convert.ToHexStringLower(bytes), $"ToHexStringLower for {what}");
        Check.That(Convert.FromHexString(hex).AsSpan().SequenceEqual(bytes) && Convert.FromHexString(hex.ToLowerInvariant()).AsSpan().SequenceEqual(bytes), $"hex doesn't round-trip for {what}");
        char[] hexChars = new char[hex.Length];
        Check.That(Convert.TryToHexString(bytes, hexChars, out written) && hexChars.AsSpan(0, written).SequenceEqual(hex), $"TryToHexString != ToHexString for {what}");
        byte[] hexUtf8 = new byte[hex.Length];
        Check.That(Convert.TryToHexStringLower(bytes, hexUtf8, out written) && Encoding.ASCII.GetString(hexUtf8, 0, written) == hex.ToLowerInvariant(), $"TryToHexStringLower(UTF-8) != ToHexStringLower for {what}");
        Check.That(hex.Length == 0 || !Convert.TryToHexString(bytes, hexChars.AsSpan(1), out _), $"TryToHexString into a short buffer succeeded for {what}");
    }
}
